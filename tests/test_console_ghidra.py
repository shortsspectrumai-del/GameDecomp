"""Real optional Ghidra imports of synthetic console CPU functions; no execution."""
import hashlib
import os
from pathlib import Path
import tempfile
import unittest

from gamedecomp.pipeline import AnalysisConfig, run_analysis
from tests.test_console_formats import nso_fixture, nro_fixture
from tests.test_retro_formats import psx_fixture, gba_fixture, dol_fixture
from tests.test_nes_format import nrom_image
from tests.test_megadrive_format import megadrive_fixture


def console_fixtures():
    """Small synthetic CPU functions, never commercial game images."""
    nso = nso_fixture()
    nro = nro_fixture(); nro[:4] = bytes.fromhex('20000014')
    nro[0x80:0x88] = bytes.fromhex('40058052c0035fd6')
    psx = psx_fixture(); psx[0x800:0x80c] = bytes.fromhex('2a0002240800e00300000000')
    gba = gba_fixture(); gba[0xc0:0xc8] = bytes.fromhex('2a00a0e31eff2fe1')
    dol = dol_fixture(); dol[0x100:0x108] = bytes.fromhex('3860002a4e800020')
    nes = bytearray(nrom_image(reset=0x8000)); nes[16:19] = bytes.fromhex('a92a60')
    return [('NSO', nso, 'switch-aarch64'), ('NRO', nro, 'switch-aarch64'),
            ('PSX_EXE', psx, 'psx-mipsel'), ('GBA', gba, 'gba-arm'),
            ('DOL', dol, 'dol-ppc'), ('NES', nes, 'nes-nrom-6502'),
            ('MEGADRIVE', megadrive_fixture(), 'megadrive-m68k')]


@unittest.skipUnless(os.environ.get('GAMEDECOMP_TEST_GHIDRA_HOME'), 'Real Ghidra console imports require explicit test installation')
class ConsoleGhidraTests(unittest.TestCase):
    def test_console_cpu_functions_are_imported_with_original_provenance(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name, data, profile in console_fixtures():
                with self.subTest(format=name):
                    source = root / name; source.write_bytes(data)
                    report = run_analysis(source, root / (name+'-analysis'), AnalysisConfig(
                        console_profile=profile, ghidra_home=Path(os.environ['GAMEDECOMP_TEST_GHIDRA_HOME']),
                        phase_timeout=90, timeout=120, max_functions=100,
                        cache_path=root / (name+'.sqlite')))
                    self.assertEqual(report['input']['sha256'], hashlib.sha256(data).hexdigest())
                    self.assertEqual(report['input']['format'], name)
                    self.assertGreater(len(report['functions']), 0)
                    self.assertTrue(any(f['instructions'] for f in report['functions']))
                    self.assertTrue(any(f.get('source') for f in report['functions']))
                    for function in report['functions']:
                        self.assertEqual(function['compilation']['status'], 'UNKNOWN')
                        self.assertEqual(function['metadata']['console_target']['profile'], profile)
                    provenance = report['metadata']['console_import']
                    self.assertFalse(provenance['executable_run'])
                    self.assertEqual(provenance['source_sha256'], report['input']['sha256'])
