"""Compilation is a syntax/toolchain check, never execution or equivalence."""
import os
import shutil
import tempfile
import time
import unittest
from pathlib import Path


class ValidationTests(unittest.TestCase):
    def test_missing_compiler_has_unknown_status(self):
        from gamedecomp.validation import compile_source
        result = compile_source('int f(void) { return 1; }', compiler='gamedecomp-no-such-compiler')
        self.assertEqual(result['status'], 'UNKNOWN')
        self.assertTrue(result['diagnostics'])
        self.assertEqual(result['toolchain']['language'], 'c')
        self.assertFalse(result['toolchain']['sandboxed'])

    @unittest.skipUnless(shutil.which('gcc'), 'GCC unavailable')
    def test_real_gcc_compiles_known_types_and_only_writes_object(self):
        from gamedecomp.validation import compile_source
        with tempfile.TemporaryDirectory(prefix='gamedecomp-test-') as directory:
            marker = Path(directory) / 'executed'
            source = '#include <stdio.h>\nuint32_t f(uint32_t x) { return x + 1; }\n'
            source += f'int main(void) {{ FILE *f = fopen("{marker}", "w"); if (f) fclose(f); return 0; }}'
            result = compile_source(source, compiler='gcc')
            self.assertEqual(result['status'], 'COMPILED', result['diagnostics'])
            self.assertEqual(result['returncode'], 0)
            self.assertFalse(marker.exists(), 'compilation must never execute source')

    @unittest.skipUnless(shutil.which('gcc'), 'GCC unavailable')
    def test_syntax_error_is_compile_failed_with_diagnostics(self):
        from gamedecomp.validation import compile_source
        result = compile_source('int f(void) { return ; this is invalid; }', compiler='gcc')
        self.assertEqual(result['status'], 'COMPILE_FAILED')
        self.assertNotEqual(result['returncode'], 0)
        self.assertTrue(any('error' in line for line in result['diagnostics']))

    @unittest.skipUnless(shutil.which('gcc'), 'GCC unavailable')
    def test_implicit_function_declarations_are_compile_errors(self):
        from gamedecomp.validation import compile_source
        result = compile_source('int f(void) { return undeclared_call(); }', compiler='gcc')
        self.assertEqual(result['status'], 'COMPILE_FAILED')

    def test_invalid_timeout_and_input_are_rejected(self):
        from gamedecomp.validation import compile_source
        for timeout in (0, -1, float('inf'), float('nan')):
            with self.subTest(timeout=timeout), self.assertRaises(ValueError):
                compile_source('int f;', timeout=timeout)
        with self.assertRaises(TypeError):
            compile_source(123)
        with self.assertRaises(ValueError):
            compile_source('x' * 1_100_000)

    def test_timeout_during_compiler_is_unknown(self):
        from gamedecomp.validation import compile_source
        with tempfile.TemporaryDirectory(prefix='gamedecomp-tool-') as directory:
            compiler = Path(directory) / 'slow-compiler'
            compiler.write_text('#!/usr/bin/env python3\nimport time\ntime.sleep(2)\n')
            compiler.chmod(0o755)
            result = compile_source('int f;', compiler=str(compiler), timeout=0.03)
        self.assertEqual(result['status'], 'UNKNOWN')
        self.assertTrue(result['timed_out'])
        self.assertTrue(any('timeout' in line.lower() for line in result['diagnostics']))

    def test_relative_compiler_path_is_resolved_before_temporary_cwd(self):
        from gamedecomp.validation import compile_source
        with tempfile.TemporaryDirectory(prefix='gamedecomp-tool-', dir='.') as directory:
            compiler = Path(directory) / 'fake-compiler'
            compiler.write_text('#!/usr/bin/env python3\nimport pathlib, sys\npathlib.Path(sys.argv[sys.argv.index("-o") + 1]).write_bytes(b"object")\n')
            compiler.chmod(0o755)
            result = compile_source('int f;', compiler=os.path.relpath(compiler))
        self.assertEqual(result['status'], 'COMPILED', result['diagnostics'])

    def test_timeout_also_stops_compiler_child_process(self):
        from gamedecomp.validation import compile_source
        with tempfile.TemporaryDirectory(prefix='gamedecomp-tool-') as directory:
            compiler = Path(directory) / 'forking-compiler'
            marker = Path(directory) / 'child-survived'
            child = f'import time; from pathlib import Path; time.sleep(0.3); Path({str(marker)!r}).write_text("survived")'
            compiler.write_text('#!/usr/bin/env python3\nimport subprocess, sys, time\n'
                                + f'subprocess.Popen([sys.executable, "-c", {child!r}])\n'
                                + 'time.sleep(2)\n')
            compiler.chmod(0o755)
            result = compile_source('int f;', compiler=str(compiler), timeout=0.08)
            time.sleep(0.4)
            self.assertFalse(marker.exists(), 'timed-out compiler children must be terminated')
        self.assertEqual(result['status'], 'UNKNOWN')
        self.assertTrue(result['timed_out'])

    def test_excessive_compiler_output_is_bounded(self):
        from gamedecomp.validation import compile_source
        with tempfile.TemporaryDirectory(prefix='gamedecomp-tool-') as directory:
            compiler = Path(directory) / 'noisy-compiler'
            compiler.write_text('#!/usr/bin/env python3\nimport os\nfor _ in range(1000):\n os.write(1, b"diagnostic\\n" * 1000)\n')
            compiler.chmod(0o755)
            result = compile_source('int f;', compiler=str(compiler), timeout=2)
        self.assertEqual(result['status'], 'UNKNOWN')
        self.assertLess(sum(map(len, result['diagnostics'])), 300_000)
        self.assertTrue(any('limit' in line.lower() for line in result['diagnostics']))

    def test_success_exit_without_object_is_not_compiled(self):
        from gamedecomp.validation import compile_source
        with tempfile.TemporaryDirectory(prefix='gamedecomp-tool-') as directory:
            compiler = Path(directory) / 'empty-compiler'
            compiler.write_text('#!/usr/bin/env python3\n')
            compiler.chmod(0o755)
            result = compile_source('int f;', compiler=str(compiler))
        self.assertEqual(result['status'], 'UNKNOWN')

    @unittest.skipUnless(shutil.which('g++') or shutil.which('clang++'), 'C++ compiler unavailable')
    def test_explicit_cpp_language_compiles_templates(self):
        from gamedecomp.validation import compile_source
        result = compile_source('template<class T> T f(T a) { return a + 1; }', language='c++')
        self.assertEqual(result['status'], 'COMPILED', result['diagnostics'])
        self.assertEqual(result['toolchain']['language'], 'c++')

    def test_strict_compilation_rejects_missing_returns_and_uninitialized_reads(self):
        from gamedecomp.validation import compile_source
        toolchains = [(name, language) for name, language in
                      [('gcc', 'c'), ('clang', 'c'), ('g++', 'c++'), ('clang++', 'c++')]
                      if shutil.which(name)]
        if not toolchains:
            self.skipTest('GCC/Clang unavailable')
        sources = [
            ('initialized', 'int f(int p) { int x = 2; if (p) x = p; return x; }', 'COMPILED'),
            ('unused', 'static int helper(int unused) { return 1; }\nint f(int unused) { return 2; }', 'COMPILED'),
            ('missing_return', 'int f(int p) { if (p) return p; }', 'COMPILE_FAILED'),
            ('uninitialized', 'int f(int p) { int x; return x; }', 'COMPILE_FAILED'),
        ]
        for compiler, language in toolchains:
            for label, source, expected in sources:
                with self.subTest(compiler=compiler, language=language, source=label):
                    result = compile_source(source, compiler=compiler, language=language, strict=True)
                    self.assertEqual(result['status'], expected, result['diagnostics'])
                    self.assertIs(result['toolchain']['strict'], True)

    def test_clang_strict_compilation_rejects_conditionally_uninitialized_reads(self):
        from gamedecomp.validation import compile_source
        toolchains = [(name, language) for name, language in
                      [('clang', 'c'), ('clang++', 'c++')] if shutil.which(name)]
        if not toolchains:
            self.skipTest('Clang unavailable')
        # GCC may optimize away this undefined path before its warning pass.
        # This stronger Clang diagnostic is not a portable equivalence proof.
        for compiler, language in toolchains:
            with self.subTest(compiler=compiler, language=language):
                result = compile_source('int f(int p) { int x; if (p) x = 1; return x; }',
                                        compiler=compiler, language=language, strict=True)
                self.assertEqual(result['status'], 'COMPILE_FAILED', result['diagnostics'])

    @unittest.skipUnless(shutil.which('gcc'), 'GCC unavailable')
    def test_default_compilation_keeps_baseline_warning_policy(self):
        from gamedecomp.validation import compile_source
        source = 'int f(int p) { int x; return x; }'
        default = compile_source(source, compiler='gcc')
        explicit = compile_source(source, compiler='gcc', strict=False)
        self.assertEqual(default['status'], 'COMPILED', default['diagnostics'])
        self.assertEqual(explicit['status'], 'COMPILED', explicit['diagnostics'])
        self.assertEqual(default['toolchain']['flags'], explicit['toolchain']['flags'])
        self.assertNotIn('-O1', default['toolchain']['flags'])
        self.assertIs(default['toolchain']['strict'], False)

    def test_strict_compilation_requires_a_boolean(self):
        from gamedecomp.validation import compile_source
        for invalid in (None, 0, 1, '', 'true', [], {}):
            with self.subTest(strict=invalid), self.assertRaises(TypeError):
                compile_source('int f(void) { return 1; }', strict=invalid)


if __name__ == '__main__':
    unittest.main()
