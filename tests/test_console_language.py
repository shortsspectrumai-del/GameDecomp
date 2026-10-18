"""Validate real console conversion against the frontend's observed language ID."""
import hashlib
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from gamedecomp.backends.console import analyze
from gamedecomp.models import Analysis
from tests.test_console_formats import nso_fixture, nro_fixture
from tests.test_retro_formats import psx_fixture, gba_fixture, dol_fixture
from tests.test_nes_format import nrom_image
from tests.test_megadrive_format import megadrive_fixture


class ConsoleLanguageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / 'module'

    def run_frontend(self, fixture, profile, language):
        self.source.write_bytes(fixture())
        def frontend(path, **kwargs):
            # Only the expensive external analyzer is replaced; loaders and hashes are real.
            return Analysis(hashlib.sha256(path.read_bytes()).hexdigest(),
                            'BinaryLoader' if profile == 'nes-nrom-6502' else 'Executable and Linking Format (ELF)',
                            language, 'ghidra')
        with patch('gamedecomp.backends.ghidra.analyze', side_effect=frontend):
            return analyze(self.source, profile=profile)

    def test_supported_languages_preserve_observed_format_and_processor_id(self):
        for fixture, profile, language, architecture in (
            (nso_fixture, 'switch-aarch64', 'AARCH64:LE:64:v8A', 'aarch64'),
            (nro_fixture, 'switch-aarch64', 'AARCH64:LE:64:v8A', 'aarch64'),
            (psx_fixture, 'psx-mipsel', 'MIPS:LE:32:default', 'mipsel'),
            (gba_fixture, 'gba-arm', 'ARM:LE:32:v8', 'arm'),
            (gba_fixture, 'gba-arm', 'ARM:LE:32:v7', 'arm'),
            (gba_fixture, 'gba-arm', 'ARM:LE:32:v4t', 'arm'),
            (dol_fixture, 'dol-ppc', 'PowerPC:BE:32:default', 'powerpc'),
            (nrom_image, 'nes-nrom-6502', '6502:LE:16:default', '6502'),
            (megadrive_fixture, 'megadrive-m68k', '68000:BE:32:default', 'm68k'),
        ):
            with self.subTest(profile=profile, language=language):
                result = self.run_frontend(fixture, profile, language)
                self.assertEqual(result.architecture, architecture)
                metadata = result.metadata['console_import']
                self.assertEqual(metadata['frontend_architecture'], language)
                self.assertIn(metadata['frontend_format'], ('BinaryLoader', 'Executable and Linking Format (ELF)'))
                self.assertEqual(metadata['frontend_language_status'], 'PROFILE_COMPATIBLE')
                self.assertEqual(result.binary_hash, hashlib.sha256(self.source.read_bytes()).hexdigest())

    def test_normalized_profiles_request_the_console_instruction_set_explicitly(self):
        for fixture, profile, language in (
            (nso_fixture, 'switch-aarch64', 'AARCH64:LE:64:v8A'),
            (nro_fixture, 'switch-aarch64', 'AARCH64:LE:64:v8A'),
            (psx_fixture, 'psx-mipsel', 'MIPS:LE:32:default'),
            (gba_fixture, 'gba-arm', 'ARM:LE:32:v4t'),
            (dol_fixture, 'dol-ppc', 'PowerPC:BE:32:default'),
            (megadrive_fixture, 'megadrive-m68k', '68000:BE:32:default'),
        ):
            self.source.write_bytes(fixture())
            def frontend(path, **kwargs):
                self.assertEqual(kwargs.get('processor_id'), language)
                return Analysis(hashlib.sha256(path.read_bytes()).hexdigest(), 'ELF', language, 'ghidra')
            with self.subTest(profile=profile), patch('gamedecomp.backends.ghidra.analyze', side_effect=frontend):
                analyze(self.source, profile=profile)

    def test_normalized_processor_override_is_allowlisted_and_keeps_elf_loader(self):
        import json
        from gamedecomp.backends.ghidra import analyze as ghidra_analyze
        executable = self.root / 'support' / 'analyzeHeadless'
        executable.parent.mkdir(); executable.touch()
        self.source.write_bytes(b'fixture')
        def frontend(command, *_):
            self.assertEqual(command[command.index('-processor') + 1], 'MIPS:LE:32:default')
            self.assertNotIn('BinaryLoader', command)
            export = Path(command[command.index('-postScript') + 2])
            export.write_text(json.dumps(Analysis('unused', 'ELF', 'MIPS:LE:32:default', 'ghidra').to_dict()))
            return 0, b'Completed', False, False
        with patch('gamedecomp.backends.ghidra._capture_compiler', side_effect=frontend):
            ghidra_analyze(self.source, ghidra_home=self.root, processor_id='MIPS:LE:32:default')
        for invalid in ('x86:LE:64:default', 'MIPS:LE:32:R6', '../../processor', True):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                ghidra_analyze(self.source, ghidra_home=self.root, processor_id=invalid)
        with self.assertRaises(ValueError):
            ghidra_analyze(self.source, ghidra_home=self.root,
                          processor_id='MIPS:LE:32:default', raw_processor='6502:LE:16:default',
                          raw_base=0x8000, entry_point=0x8000)

    def test_mismatching_cpu_endianness_and_width_are_refused(self):
        for language in ('x86:LE:64:default', 'AARCH64:BE:64:v8A', 'AARCH64:LE:32:v8A',
                         'aarch64', '', None, 'AARCH64:LE:64:v8A:extra'):
            with self.subTest(language=language), self.assertRaisesRegex(ValueError, 'language|profile'):
                self.run_frontend(nso_fixture, 'switch-aarch64', language)

    def test_processor_variants_with_different_instruction_semantics_are_refused(self):
        for fixture, profile, language in (
            (nso_fixture, 'switch-aarch64', 'AARCH64:LE:64:AppleSilicon'),
            (psx_fixture, 'psx-mipsel', 'MIPS:LE:32:micro'),
            (psx_fixture, 'psx-mipsel', 'MIPS:LE:32:R6'),
            (gba_fixture, 'gba-arm', 'ARM:LE:32:v8T'),
            (gba_fixture, 'gba-arm', 'ARM:LE:32:Cortex'),
            (dol_fixture, 'dol-ppc', 'PowerPC:BE:32:e500'),
            (nrom_image, 'nes-nrom-6502', '6502:LE:16:65c02'),
            (megadrive_fixture, 'megadrive-m68k', '68000:BE:32:Coldfire'),
        ):
            with self.subTest(profile=profile, language=language), self.assertRaisesRegex(ValueError, 'language|profile'):
                self.run_frontend(fixture, profile, language)
