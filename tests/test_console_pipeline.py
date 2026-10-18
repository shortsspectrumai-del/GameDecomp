import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from gamedecomp.pipeline import AnalysisConfig, _backend_name, run_analysis


class ConsoleProfileTests(unittest.TestCase):
    def test_profiles_are_explicit_and_validated(self):
        self.assertEqual(AnalysisConfig(console_profile='switch-aarch64').console_profile, 'switch-aarch64')
        for value in ('../../loader', 'ps5-auto', True):
            with self.assertRaises(ValueError):
                AnalysisConfig(console_profile=value)

    def test_console_automatic_backend_requires_ghidra(self):
        self.assertEqual(_backend_name({'format': 'NSO'}, AnalysisConfig()), 'ghidra')

    def test_missing_wrong_profile_or_backend_reject_before_frontend(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); source = root / 'module.nso'; source.write_bytes(b'NSO0')
            info = {'path': str(source), 'sha256': hashlib.sha256(b'NSO0').hexdigest(),
                    'format': 'NSO', 'architecture': 'aarch64', 'bits': 64, 'endianness': 'little',
                    'required_profile': 'switch-aarch64'}
            for options in ({}, {'console_profile': 'gba-arm'},
                            {'console_profile': 'switch-aarch64', 'backend': 'native'}):
                with self.subTest(options=options), patch('gamedecomp.pipeline.inspect_binary', return_value=info), \
                     patch('gamedecomp.pipeline._analyze') as frontend:
                    with self.assertRaises(ValueError):
                        run_analysis(source, root/'output', AnalysisConfig(cache_path=root/'cache.sqlite', **options))
                    frontend.assert_not_called()

    def test_container_guidance_uses_signatures(self):
        from gamedecomp.console_support import unsupported_input_message
        self.assertIn('SELF', unsupported_input_message(b'\x54\x14\xf5\xee'))
        self.assertIn('PFS0', unsupported_input_message(b'PFS0'))
        self.assertIn('Unsupported input', unsupported_input_message(b'not a ROM'))

    def test_ghidra_exit_zero_cannot_hide_failed_console_entry(self):
        from gamedecomp.backends.ghidra import analyze
        from gamedecomp.models import Analysis
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            executable = root / 'support' / 'analyzeHeadless'
            executable.parent.mkdir(); executable.touch()
            source = root / 'module.elf'; source.write_bytes(b'fixture')
            for output, expected in ((b'REPORT SCRIPT ERROR: unmapped entry', 'initialization failed'),
                                     (b'Completed', 'entry function missing')):
                def fake_frontend(command, *_):
                    export = Path(command[command.index('-postScript') + 2])
                    export.write_text(json.dumps(Analysis('unused', 'ELF', 'aarch64', 'ghidra').to_dict()))
                    return 0, output, False, False
                with self.subTest(output=output), patch('gamedecomp.backends.ghidra._capture_compiler', side_effect=fake_frontend):
                    with self.assertRaisesRegex(RuntimeError, expected):
                        analyze(source, ghidra_home=root, entry_point=0)
