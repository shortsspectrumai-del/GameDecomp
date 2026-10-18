"""Differential checks execute only shared libraries authored by these tests."""
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import unittest

try:
    from gamedecomp.verify import run_demo, verify_report
except ImportError:
    run_demo = verify_report = None


@unittest.skipUnless(shutil.which('gcc') and shutil.which('objdump'), 'GCC/binutils required')
class VerificationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='verification fixtures ')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.binary = self.root / 'original.so'
        source = self.root / 'original.c'
        source.write_text('#include <stdint.h>\n'
                          'uint32_t fixture_add(uint32_t a, uint32_t b) { return a + b; }\n')
        subprocess.run(['gcc', '-shared', '-fPIC', '-O2', str(source), '-o', str(self.binary)],
                       check=True, capture_output=True)
        self.report = self.root / 'report.json'
        self.data = {
            'backend': 'native', 'input': {'sha256': hashlib.sha256(self.binary.read_bytes()).hexdigest()},
            'metadata': {'abi': 'sysv-amd64'},
            'functions': [{
                'id': 'native:1100', 'name': 'fixture_add',
                'source': '#include <stdint.h>\nuint32_t recovered_add(uint32_t p0, uint32_t p1) { return p0 + p1; }',
                'metadata': {'export_name': 'recovered_add', 'original_symbol': 'fixture_add',
                             'parameter_bits': [32, 32], 'return_bits': 32, 'language': 'c'},
                'semantic_status': 'UNKNOWN', 'selected_source': 'conservative_baseline',
            }],
        }
        self.save()

    def save(self):
        self.report.write_text(json.dumps(self.data), encoding='utf-8')

    def replace_original(self, source_text):
        source = self.root / 'replacement.c'
        source.write_text(source_text, encoding='utf-8')
        subprocess.run(['gcc', '-shared', '-fPIC', '-O2', str(source), '-o', str(self.binary)],
                       check=True, capture_output=True)
        self.data['input']['sha256'] = hashlib.sha256(self.binary.read_bytes()).hexdigest()
        self.save()

    def verify(self, **kwargs):
        self.assertTrue(callable(verify_report), 'verify_report must be implemented')
        return verify_report(self.binary, self.report, **kwargs)

    def test_trust_is_required_before_reading_or_loading_any_input(self):
        self.assertTrue(callable(verify_report), 'verify_report must be implemented')
        with self.assertRaises(PermissionError):
            verify_report(self.root / 'absent.so', self.root / 'absent.json')
        with self.assertRaises(PermissionError):
            self.verify(trusted=1)

    def test_matching_returns_are_tested_with_explicit_scope_and_denominators(self):
        result = self.verify(trusted=True, cases=32)
        self.assertEqual(result['summary']['total'], 1)
        self.assertEqual(result['summary']['tested'], 1)
        self.assertEqual(result['summary']['mismatches'], 0)
        self.assertEqual(result['summary']['proved'], 0)
        function = result['functions'][0]
        self.assertEqual(function['semantic_status'], 'TESTED')
        self.assertEqual(function['cases_checked'], 32)
        self.assertEqual(function['scope'], 'return-values under inferred scalar ABI')

    def test_source_mismatch_returns_a_reproducible_counterexample(self):
        self.data['functions'][0]['source'] = self.data['functions'][0]['source'].replace('p0 + p1', 'p0 - p1')
        self.save()
        result = self.verify(trusted=True, cases=32)
        function = result['functions'][0]
        self.assertEqual(function['semantic_status'], 'DISPROVED')
        self.assertEqual(result['summary']['mismatches'], 1)
        counterexample = function['counterexample']
        self.assertNotEqual(counterexample['original'], counterexample['recovered'])
        again = self.verify(trusted=True, cases=32)
        self.assertEqual(again['functions'][0]['counterexample'], counterexample)

    def test_wrong_hash_is_refused(self):
        self.data['input']['sha256'] = '0' * 64
        self.save()
        with self.assertRaisesRegex(ValueError, '(?i)hash|sha256'):
            self.verify(trusted=True)

    def test_compilation_failure_stays_unknown_and_is_counted(self):
        self.data['functions'][0]['source'] = self.data['functions'][0]['source'].replace('p0 + p1', 'missing_name + p1')
        self.save()
        result = self.verify(trusted=True)
        self.assertEqual(result['functions'][0]['semantic_status'], 'UNKNOWN')
        self.assertEqual(result['summary']['eligible'], 1)
        self.assertEqual(result['summary']['tested'], 0)
        self.assertEqual(result['summary']['unknown'], 1)

    def test_native_crash_is_unknown_and_parent_remains_alive(self):
        self.replace_original('#include <stdint.h>\n#include <stdlib.h>\n'
                              'uint32_t fixture_add(uint32_t a, uint32_t b) { abort(); }\n')
        result = self.verify(trusted=True, cases=16)
        self.assertEqual(result['functions'][0]['semantic_status'], 'UNKNOWN')
        self.assertEqual(result['summary']['cases_checked'], 0)
        self.assertEqual(result['summary']['mismatches'], 0)
        self.assertIn('exit', result['functions'][0]['diagnostics'][0])

    def test_native_hang_is_killed_within_the_total_deadline(self):
        self.replace_original('#include <stdint.h>\n'
                              'uint32_t fixture_add(uint32_t a, uint32_t b) { for (;;) {} }\n')
        started = time.monotonic()
        result = self.verify(trusted=True, timeout=0.5)
        self.assertLess(time.monotonic() - started, 2)
        self.assertEqual(result['functions'][0]['semantic_status'], 'UNKNOWN')
        self.assertIn('timeout', result['functions'][0]['diagnostics'][0].lower())

    def test_native_stdout_flood_is_bounded_and_unknown(self):
        self.replace_original('#include <stdint.h>\n#include <unistd.h>\n'
                              'uint32_t fixture_add(uint32_t a, uint32_t b) {\n'
                              ' char data[8192] = {0}; for (int i=0; i<100; ++i) write(1, data, sizeof(data));\n'
                              ' return a+b; }\n')
        result = self.verify(trusted=True, timeout=2)
        self.assertEqual(result['functions'][0]['semantic_status'], 'UNKNOWN')
        self.assertIn('limite', result['functions'][0]['diagnostics'][0])

    def test_timeout_stops_an_ordinary_native_descendant(self):
        pid_file = self.root / 'descendant.pid'
        quoted_path = json.dumps(str(pid_file))
        self.replace_original('#include <stdint.h>\n#include <stdio.h>\n#include <unistd.h>\n'
                              '__attribute__((constructor)) static void initialize(void) {\n'
                              ' int child = fork(); if (child == 0) { sleep(30); _exit(0); }\n'
                              f' FILE *file = fopen({quoted_path}, "w");\n'
                              ' if (file) { fprintf(file, "%d", child); fclose(file); } }\n'
                              'uint32_t fixture_add(uint32_t a, uint32_t b) { return a+b; }\n')
        result = self.verify(trusted=True, timeout=0.5)
        self.assertEqual(result['functions'][0]['semantic_status'], 'UNKNOWN')
        self.assertTrue(pid_file.is_file(), 'trusted constructor must have spawned its descendant')
        descendant = int(pid_file.read_text())
        self.assertGreater(descendant, 0)
        state = Path(f'/proc/{descendant}/stat')
        # A dead orphan may briefly remain as a zombie until the host init reaps it.
        for _ in range(20):
            if not state.exists() or state.read_text().split(') ', 1)[1].startswith('Z '):
                break
            time.sleep(0.01)
        else:
            self.fail('Native descendant is still running after verification timeout')

    def test_unsupported_abi_is_skipped_instead_of_testing_a_wrong_prototype(self):
        self.data['functions'][0]['metadata']['parameter_bits'] = [8, 32]
        self.save()
        result = self.verify(trusted=True)
        self.assertEqual(result['summary']['eligible'], 0)
        self.assertEqual(result['summary']['skipped'], 1)
        self.assertEqual(result['functions'][0]['semantic_status'], 'UNKNOWN')

    def test_executable_filename_is_never_loaded_as_a_shared_library(self):
        path = self.root / 'program'
        self.binary.rename(path)
        self.binary = path
        result = self.verify(trusted=True)
        self.assertEqual(result['summary']['tested'], 0)
        self.assertEqual(result['summary']['skipped'], 1)

    def test_wrong_hash_is_rejected_before_an_elf_constructor_can_run(self):
        marker = self.root / 'constructor-ran'
        quoted_path = json.dumps(str(marker))
        self.replace_original('#include <stdint.h>\n#include <stdio.h>\n'
                              '__attribute__((constructor)) static void initialize(void) {\n'
                              f' FILE *file = fopen({quoted_path}, "w"); if (file) fclose(file); }}\n'
                              'uint32_t fixture_add(uint32_t a, uint32_t b) { return a+b; }\n')
        self.data['input']['sha256'] = '0' * 64
        self.save()
        with self.assertRaises(ValueError):
            self.verify(trusted=True)
        self.assertFalse(marker.exists())

    def test_demo_recovers_four_leaves_and_keeps_branch_unknown(self):
        self.assertTrue(callable(run_demo), 'run_demo must be implemented')
        output = self.root / 'demo'
        result = run_demo(output, workers=2, cases=48)
        verification = json.loads((output / 'verification.json').read_text())
        functions = {f['name']: f for f in verification['functions']}
        self.assertEqual(set(functions), {'game_add32', 'game_mix32', 'game_mul64', 'game_scale64', 'game_branch'})
        for name in ('game_add32', 'game_mix32', 'game_mul64', 'game_scale64'):
            self.assertEqual(functions[name]['semantic_status'], 'TESTED', functions[name])
        self.assertEqual(functions['game_branch']['semantic_status'], 'UNKNOWN')
        self.assertEqual(result['recovered'], 4)
        self.assertEqual(result['tested'], 4)
        self.assertEqual(result['mismatches'], 0)
        self.assertEqual(verification['summary']['total'], 5)
        self.assertEqual(verification['summary']['skipped'], 1)
        self.assertTrue((output / 'analysis' / 'recovered.c').is_file())
        with self.assertRaises(FileExistsError):
            run_demo(output)


if __name__ == '__main__':
    unittest.main()
