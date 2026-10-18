import tempfile
import unittest
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch


class OptionalBackendTests(unittest.TestCase):
    def fake_ghidra(self, directory, payload=None, *, flood=False):
        home = Path(directory) / 'ghidra'
        (home / 'support').mkdir(parents=True)
        executable = home / 'support' / 'analyzeHeadless'
        if flood:
            body = "import sys\nsys.stdout.write('x' * 300000)\nsys.stdout.flush()\n"
        else:
            body = ("import json, pathlib, sys\n"
                    "destination = sys.argv[sys.argv.index('-postScript') + 2]\n"
                    f"pathlib.Path(destination).write_text({json.dumps(json.dumps(payload))})\n")
        executable.write_text(f'#!{sys.executable}\n' + body)
        executable.chmod(0o700)
        binary = Path(directory) / 'input'
        binary.write_bytes(b'fixture')
        return home, binary

    def test_ghidra_timeout_configuration_is_positive_finite_number(self):
        from gamedecomp.backends.ghidra import analyze
        for timeout in (True, False, 0, -1, float('inf'), float('nan')):
            with self.subTest(timeout=timeout), self.assertRaises(ValueError):
                analyze(Path('/missing'), ghidra_home=Path('/missing'), timeout=timeout)

    def test_ghidra_headless_diagnostic_output_is_bounded(self):
        from gamedecomp.backends.ghidra import analyze
        with tempfile.TemporaryDirectory() as directory:
            home, binary = self.fake_ghidra(directory, flood=True)
            with self.assertRaisesRegex(RuntimeError, 'output|diagnostic'):
                analyze(binary, ghidra_home=home, timeout=3)

    def test_ghidra_preserves_source_and_separate_observed_preamble(self):
        from gamedecomp.backends.ghidra import analyze
        original = 'uint observed(uint x) { return x + 1; }'
        preamble = 'typedef unsigned int uint;\n'
        payload = {'binary_hash': '', 'format': 'ELF', 'architecture': 'x86:LE:64:default',
                   'backend': 'ghidra', 'functions': [{'id': 'native:10', 'name': 'observed',
                       'address': 16, 'source': original,
                       'metadata': {'language': 'c', 'compile_preamble': preamble,
                                    'compile_preamble_status': 'AVAILABLE'}}]}
        with tempfile.TemporaryDirectory() as directory:
            home, binary = self.fake_ghidra(directory, payload)
            result = analyze(binary, ghidra_home=home, timeout=3)
            self.assertEqual(result.functions[0].source, original)
            self.assertEqual(result.functions[0].metadata['compile_preamble'], preamble)
            self.assertEqual(len(result.binary_hash), 64)
        payload['functions'][0]['metadata']['compile_preamble'] = 'x' * (262144 + 1)
        with tempfile.TemporaryDirectory() as directory:
            home, binary = self.fake_ghidra(directory, payload)
            with self.assertRaisesRegex(ValueError, 'preamble'):
                analyze(binary, ghidra_home=home, timeout=3)

    def test_ghidra_missing_compilation_context_is_explicitly_unavailable(self):
        from gamedecomp.backends.ghidra import analyze
        payload = {'binary_hash': '', 'format': 'ELF', 'architecture': 'x86:LE:64:default',
                   'backend': 'ghidra', 'functions': [{'id': 'native:10', 'name': 'observed',
                       'address': 16, 'source': 'int observed(void) { return 1; }'}]}
        with tempfile.TemporaryDirectory() as directory:
            home, binary = self.fake_ghidra(directory, payload)
            function = analyze(binary, ghidra_home=home, timeout=3).functions[0]
            self.assertEqual(function.metadata['compile_preamble_status'], 'UNAVAILABLE')
            self.assertEqual(function.metadata['compile_preamble'], '')

    @unittest.skipUnless(os.environ.get('GAMEDECOMP_TEST_GHIDRA_HOME') and shutil.which('gcc'),
                         'requires explicitly configured real Ghidra and gcc')
    def test_real_ghidra_exports_observed_types_calls_and_globals_for_isolated_compile(self):
        from gamedecomp.backends.ghidra import analyze
        from gamedecomp.validation import compile_source
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'fixture.c'
            source.write_text('#include <stdbool.h>\n'
                              '#undef bool\ntypedef unsigned char bool;\n'
                              'typedef unsigned int Counter;\n'
                              'volatile Counter observed_total = 2;\n'
                              'Counter observed_add(Counter value) { return value + observed_total; }\n'
                              'Counter observed_call(Counter value) { return observed_add(value) + 3; }\n'
                              '_Bool observed_bool(Counter value) { return value > observed_total; }\n'
                              'bool observed_byte_bool(bool value) { return value; }\n'
                              'int observed_scoped(int value) { static volatile int tally = 1; '
                              'tally += value; return tally; }\n'
                              'extern int puts(const char *);\n'
                              'int observed_literal(void) { return puts("Renderer::debug"); }\n'
                              'int main(void) { return observed_call(4); }\n')
            binary = root / 'fixture'
            subprocess.run(['gcc', '-g', '-O0', '-fno-pie', '-no-pie', str(source), '-o', str(binary)],
                           check=True, capture_output=True, timeout=30)
            result = analyze(binary, ghidra_home=Path(os.environ['GAMEDECOMP_TEST_GHIDRA_HOME']), timeout=120)
            self.assertTrue(result.metadata['frontend_version'])
            self.assertEqual(result.metadata['semantic_status'], 'UNKNOWN')
            scoped = next(f for f in result.functions if f.name == 'observed_scoped')
            self.assertEqual(scoped.metadata['compile_preamble_status'], 'UNAVAILABLE')
            for name in ('observed_add', 'observed_call', 'observed_bool', 'observed_byte_bool', 'observed_literal'):
                function = next(f for f in result.functions if f.name == name)
                self.assertEqual(function.metadata['compile_preamble_status'], 'AVAILABLE')
                preamble = function.metadata['compile_preamble']
                self.assertLessEqual(len(preamble.encode('utf-8')), 262144)
                compiled = compile_source(preamble + '\n' + function.source)
                self.assertEqual(compiled['status'], 'COMPILED', compiled['diagnostics'])
                if name == 'observed_byte_bool':
                    checked = compile_source(preamble + '\n' + function.source +
                                             '\n_Static_assert((bool)2 == 2, "observed bool values preserved");\n')
                    self.assertEqual(checked['status'], 'COMPILED', checked['diagnostics'])

    @unittest.skipUnless(os.environ.get('GAMEDECOMP_TEST_GHIDRA_HOME') and
                         shutil.which('gcc') and shutil.which('strip') and shutil.which('nm'),
                         'requires explicitly configured real Ghidra and native build tools')
    def test_real_stripped_ghidra_exports_types_used_only_by_recovered_casts(self):
        from gamedecomp.backends.ghidra import analyze
        from gamedecomp.validation import compile_source
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'fixture.c'
            source.write_text('long observed_lookup(unsigned char *bytes, unsigned char index) '
                              '{ return bytes[index]; }\n'
                              '_Bool observed_predicate(int value) { return value > 0; }\n'
                              'int observed_caller(int value) { return observed_predicate(value) + 2; }\n'
                              'int main(void) { unsigned char bytes[4] = {1,2,3,4}; '
                              'return observed_lookup(bytes, 2) + observed_caller(3); }\n')
            binary = root / 'fixture'
            subprocess.run(['gcc', '-g', '-O0', '-fno-pie', '-no-pie', str(source), '-o', str(binary)],
                           check=True, capture_output=True, timeout=30)
            symbols = subprocess.check_output(['nm', '--format=posix', '--defined-only', str(binary)],
                                              text=True, timeout=30)
            addresses = {line.split()[0]: int(line.split()[2], 16) for line in symbols.splitlines()
                         if line.split()[0] in ('observed_lookup', 'observed_predicate', 'observed_caller')}
            subprocess.run(['strip', '--strip-all', str(binary)], check=True, capture_output=True, timeout=30)
            result = analyze(binary, ghidra_home=Path(os.environ['GAMEDECOMP_TEST_GHIDRA_HOME']), timeout=120)
            for name, address in addresses.items():
                with self.subTest(function=name):
                    function = next(f for f in result.functions if f.address == address)
                    self.assertEqual(function.metadata['compile_preamble_status'], 'AVAILABLE')
                    compiled = compile_source(function.metadata['compile_preamble'] + '\n' + function.source)
                    self.assertEqual(compiled['status'], 'COMPILED', compiled['diagnostics'])

    def test_ghidra_missing_has_actionable_error(self):
        from gamedecomp.backends.ghidra import analyze
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(RuntimeError, 'Ghidra'):
                analyze(Path(directory) / 'input', ghidra_home=Path(directory))

    def test_ilspy_missing_has_actionable_error(self):
        from gamedecomp.backends.ilspy import analyze
        with patch('gamedecomp.backends.ilspy.shutil.which', return_value=None):
            with self.assertRaisesRegex(RuntimeError, 'ilspycmd'):
                analyze(Path('/missing'))

    def test_ilspy_timeout_is_normalized_and_bounded(self):
        from gamedecomp.backends.ilspy import analyze
        with tempfile.TemporaryDirectory() as directory:
            executable = Path(directory) / 'ilspycmd'
            executable.write_text('#!/bin/sh\nsleep 30\n')
            executable.chmod(0o700)
            with patch('gamedecomp.backends.ilspy.shutil.which', return_value=str(executable)):
                with self.assertRaises(TimeoutError):
                    analyze(Path('/missing'), timeout=0.05)
