import hashlib
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

from gamedecomp.models import Analysis, Function
from gamedecomp.pipeline import AnalysisConfig, run_analysis


class CompatibilityPipelineTests(unittest.TestCase):
    def run_fixture(self, root, *, check=True, bits=64):
        binary = root / 'input.elf'
        header = bytearray(64)
        header[:6] = b'\x7fELF\x02\x01'
        header[18:20] = (62).to_bytes(2, 'little')
        if bits == 32:
            header[4] = 1
            header[18:20] = (3).to_bytes(2, 'little')
        binary.write_bytes(header)
        source = 'unsigned long packed(unsigned char *p) { unsigned char auVar1[16]; auVar1=*(unsigned char (*)[16])p; return auVar1._0_8_; }'
        metadata = {'language': 'c', 'compile_preamble': '', 'compile_preamble_status': 'AVAILABLE'}
        analysis = Analysis(hashlib.sha256(header).hexdigest(), 'ELF', 'x86_64', 'ghidra',
                            [Function('packed', 'packed', 4096, source=source, metadata=metadata)])
        with patch('gamedecomp.pipeline._analyze', return_value=analysis):
            report = run_analysis(binary, root/'output', AnalysisConfig(backend='ghidra',
                cache_path=root/'cache.sqlite', recover_types=False, check_compile=check))
        return report, source

    @unittest.skipUnless(shutil.which('gcc'), 'gcc required')
    def test_compatibility_compiles_separately_and_is_exported(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report, source = self.run_fixture(root)
            record = report['functions'][0]
            self.assertEqual(record['source'], source)
            self.assertEqual(record['compilation']['status'], 'COMPILE_FAILED')
            self.assertEqual(record['compatibility']['compilation']['status'], 'COMPILED')
            self.assertEqual(record['compatibility']['semantic_status'], 'UNKNOWN')
            self.assertEqual(report['summary']['compiled'], 0)
            self.assertEqual(report['summary']['compatibility_compiled'], 1)
            self.assertTrue((root/'output/functions/00000_1000.compat.unit.c').is_file())
            self.assertTrue((root/'output/project/manifest.json').is_file())
            self.assertEqual(report['project']['summary']['exported_units'], 0)

    def test_disabled_compilation_never_calls_compiler(self):
        with tempfile.TemporaryDirectory() as directory, patch('gamedecomp.pipeline.compile_source') as compiler:
            report, _ = self.run_fixture(Path(directory), check=False)
            compiler.assert_not_called()
            self.assertIsNone(report['functions'][0]['compatibility'])

    @unittest.skipUnless(shutil.which('gcc'), 'gcc required')
    def test_unsupported_target_is_unknown(self):
        with tempfile.TemporaryDirectory() as directory:
            report, _ = self.run_fixture(Path(directory), bits=32)
            self.assertEqual(report['functions'][0]['compatibility']['status'], 'UNKNOWN')
            self.assertEqual(report['summary']['compatibility_compiled'], 0)
