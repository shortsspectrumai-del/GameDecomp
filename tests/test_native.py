"""Native recovery tests compile and execute only fixtures authored here."""
import ctypes
import hashlib
import os
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile
import unittest
from unittest import mock

try:
    from gamedecomp.backends.native import analyze
    from gamedecomp.backends.native import _inspect, _parse_disassembly, _Recovery
except ImportError:
    analyze = None


C_FIXTURE = r"""
#include <stdint.h>
uint32_t add32(uint32_t a, uint32_t b) { return a + b; }
uint64_t mul64(uint64_t a, uint64_t b) { return a * b; }
uint64_t bits64(uint64_t a, uint64_t b) {
    return ((a ^ b) << 3) + ((a & b) >> 5);
}
uint32_t unary32(uint32_t a) { return ~(0u - a); }
uint32_t constant32(void) { return 0xfedcba98u; }
"""

ASSEMBLY_FIXTURE = r"""
.text
.macro function name
.globl \name
.type \name,@function
\name:
.endm
.macro finish name
.size \name,.-\name
.endm
function mixed_widths
    mov %edi,%eax
    add %rsi,%rax
    ret
finish mixed_widths
function zero_extend
    mov $0xfffffff0,%eax
    add %rdi,%rax
    ret
finish zero_extend
function immediate_mul
    imul $-7,%rdi,%rax
    ret
finish immediate_mul
function danger.symbol
    lea 13(%rdi,%rdi,4),%rax
    ret
finish danger.symbol
function rotate_bswap_signext
    mov %edi,%eax
    inc %eax
    rol $7,%eax
    bswap %eax
    cltq
    movsxd %esi,%rcx
    ror $13,%rcx
    bswap %rcx
    add %rcx,%rax
    ret
finish rotate_bswap_signext
function swap_inc_dec
    mov %rdi,%rax
    mov %rsi,%rcx
    xchg %rcx,%rax
    dec %rax
    inc %rcx
    sub %rcx,%rax
    ret
finish swap_inc_dec
function reads_memory
    mov (%rdi),%eax
    ret
finish reads_memory
function reads_uninitialized
    add %r10,%rax
    ret
finish reads_uninitialized
function partial_register
    mov %dil,%al
    ret
finish partial_register
function consumes_flags
    mov %edi,%eax
    adc %esi,%eax
    ret
finish consumes_flags
function signed_shift
    mov %rdi,%rax
    sar $3,%rax
    ret
finish signed_shift
function variable_shift
    mov %rdi,%rax
    mov %esi,%ecx
    shl %cl,%rax
    ret
finish variable_shift
function oversized_shift
    mov %rdi,%rax
    shl $64,%rax
    ret
finish oversized_shift
function division
    mov %rdi,%rax
    xor %edx,%edx
    div %rsi
    ret
finish division
function callee_saved_clobber
    mov %rdi,%rbx
    mov %rbx,%rax
    ret
finish callee_saved_clobber
function calls_other
    call mixed_widths
    ret
finish calls_other
function conditional_branch
    test %edi,%edi
    jz 1f
    mov $1,%eax
    ret
1:  xor %eax,%eax
    ret
finish conditional_branch
.section .note.GNU-stack,"",@progbits
"""


@unittest.skipUnless(shutil.which('gcc') and shutil.which('objdump'), 'GCC/binutils required')
class NativeBackendTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='native fixtures ')
        cls.root = Path(cls.temp.name)
        (cls.root / 'fixture.c').write_text(C_FIXTURE)
        (cls.root / 'fixture.S').write_text(ASSEMBLY_FIXTURE)
        cls.binary = cls.root / 'fixture with spaces.so'
        subprocess.run(['gcc', '-O2', '-fPIC', '-shared', '-Wl,-Bsymbolic',
                        str(cls.root / 'fixture.c'), str(cls.root / 'fixture.S'),
                        '-o', str(cls.binary)], check=True, capture_output=True)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def backend(self, path=None, timeout=60):
        self.assertTrue(callable(analyze), 'native analyze must be implemented')
        return analyze(path or self.binary, timeout=timeout)

    def functions(self):
        return {f.name: f for f in self.backend().functions}

    def test_real_disassembly_hash_and_machine_type_evidence(self):
        artifact = self.backend()
        self.assertEqual(artifact.binary_hash, hashlib.sha256(self.binary.read_bytes()).hexdigest())
        self.assertEqual(artifact.format, 'ELF')
        self.assertEqual(artifact.architecture, 'x86_64')
        self.assertEqual(artifact.metadata.get('abi'), 'sysv-amd64')
        add = next(f for f in artifact.functions if f.name == 'add32')
        self.assertTrue(add.instructions)
        self.assertEqual(add.metadata['parameter_bits'], [32, 32])
        self.assertEqual(add.metadata['return_bits'], 32)
        self.assertEqual(add.metadata['type_evidence']['confidence'], 'low')
        self.assertIn('machine', add.metadata['type_evidence']['basis'].lower())

    def test_supported_functions_compile_and_match_trusted_fixture(self):
        functions = self.functions()
        cases = {
            'add32': [(0, 0), (1, 2), (0xffffffff, 1), (0x80000000, 0x80000001)],
            'mul64': [(0, 9), (13, 17), (0xffffffffffffffff, 3), (1 << 63, 2)],
            'bits64': [(0, 0), (7, 9), (0xffffffffffffffff, 0x8888888888888888)],
            'unary32': [(0,), (1,), (0xffffffff,), (0x80000000,)],
            'constant32': [()],
            'mixed_widths': [(0xffffffff, 1 << 40), (0, 0xffffffffffffffff)],
            'zero_extend': [(0,), (1 << 40,), (0xffffffffffffffff,)],
            'immediate_mul': [(0,), (1,), (0xffffffffffffffff,), (1 << 63,)],
            'danger.symbol': [(0,), (17,), (0xffffffffffffffff,)],
            'rotate_bswap_signext': [(0, 0), (0x12345678, 0x9abcdef0), (0xffffffff, 0x80000000)],
            'swap_inc_dec': [(0, 0), (100, 42), (0xffffffffffffffff, 1)],
        }
        for name in cases:
            self.assertIsNotNone(functions[name].source, f'{name}: {functions[name].diagnostics}')
        recovered_c = self.root / 'recovered.c'
        recovered_c.write_text('\n\n'.join(functions[name].source for name in cases))
        recovered_so = self.root / 'recovered.so'
        subprocess.run(['gcc', '-std=c11', '-Wall', '-Wextra', '-Werror', '-O2',
                        '-fPIC', '-shared', str(recovered_c), '-o', str(recovered_so)],
                       check=True, capture_output=True)
        original = ctypes.CDLL(str(self.binary))
        recovered = ctypes.CDLL(str(recovered_so))
        for name, inputs in cases.items():
            with self.subTest(function=name):
                f = functions[name]
                ctype = {32: ctypes.c_uint32, 64: ctypes.c_uint64}
                expected = getattr(original, name)
                actual = getattr(recovered, f.metadata['export_name'])
                expected.argtypes = actual.argtypes = [ctype[b] for b in f.metadata['parameter_bits']]
                expected.restype = actual.restype = ctype[f.metadata['return_bits']]
                for args in inputs:
                    self.assertEqual(actual(*args), expected(*args), (name, args))

    def test_unsupported_semantics_keep_instructions_and_diagnostics(self):
        functions = self.functions()
        for name in ['reads_memory', 'reads_uninitialized', 'partial_register',
                     'consumes_flags', 'signed_shift', 'variable_shift',
                     'oversized_shift', 'division', 'callee_saved_clobber',
                     'calls_other', 'conditional_branch']:
            with self.subTest(function=name):
                self.assertIsNone(functions[name].source)
                self.assertTrue(functions[name].instructions)
                self.assertTrue(functions[name].diagnostics)

    def test_call_targets_use_the_function_id(self):
        functions = self.functions()
        self.assertIn(functions['mixed_widths'].id, functions['calls_other'].calls)

    def test_symbol_names_are_safely_exported(self):
        function = self.functions()['danger.symbol']
        self.assertRegex(function.metadata['export_name'], r'^[A-Za-z][A-Za-z0-9_]*$')
        self.assertEqual(function.metadata['original_symbol'], 'danger.symbol')
        self.assertNotIn('danger.symbol(', function.source)

    def test_metadata_preserves_mixed_register_widths(self):
        functions = self.functions()
        self.assertEqual(functions['mixed_widths'].metadata['parameter_bits'], [32, 64])
        self.assertEqual(functions['mixed_widths'].metadata['return_bits'], 64)
        self.assertEqual(functions['zero_extend'].metadata['parameter_bits'], [64])
        self.assertEqual(functions['zero_extend'].metadata['return_bits'], 64)

    def test_non_sysv_format_has_no_recovered_source(self):
        # Change e_machine only: GNU objdump may refuse it; either way no C is claimed.
        data = bytearray(self.binary.read_bytes())
        data[18:20] = (183).to_bytes(2, 'little')
        arm = self.root / 'unsupported-arm.so'
        arm.write_bytes(data)
        artifact = self.backend(arm)
        self.assertEqual(artifact.architecture, 'aarch64')
        self.assertTrue(artifact.diagnostics)
        self.assertTrue(all(f.source is None for f in artifact.functions))

    def test_missing_objdump_and_tool_timeout_are_explicit(self):
        with mock.patch.dict(os.environ, {'PATH': ''}):
            artifact = self.backend()
        self.assertTrue(artifact.diagnostics)
        self.assertEqual(artifact.functions, [])
        # A real sleeping executable tests process cleanup and timeout diagnostics.
        tools_dir = self.root / 'slowtools'
        tools_dir.mkdir(exist_ok=True)
        objdump = tools_dir / 'objdump'
        objdump.write_text('#!/usr/bin/python3\nimport time\ntime.sleep(2)\n')
        objdump.chmod(0o755)
        with mock.patch.dict(os.environ, {'PATH': str(tools_dir)}):
            artifact = self.backend(timeout=0.05)
        self.assertTrue(any('timeout' in d.lower() for d in artifact.diagnostics))
        self.assertEqual(artifact.functions, [])

    def test_invalid_timeout_is_rejected(self):
        for value in [0, -1, float('nan'), float('inf'), True]:
            with self.subTest(timeout=value), self.assertRaises(ValueError):
                self.backend(timeout=value)

    def test_tool_output_budget_preserves_evidence_but_disables_source(self):
        with mock.patch('gamedecomp.backends.native._MAX_TOOL_OUTPUT', 2048):
            artifact = self.backend()
        self.assertTrue(artifact.functions)
        self.assertTrue(any('truncat' in d.lower() for d in artifact.diagnostics))
        self.assertTrue(all(f.source is None for f in artifact.functions))

    def test_partial_disassembly_is_retained_on_tool_timeout(self):
        tools_dir = self.root / 'partialtools'
        tools_dir.mkdir(exist_ok=True)
        objdump = tools_dir / 'objdump'
        objdump.write_text(
            '#!/usr/bin/python3\nimport time\n'
            'print("0000000000000000 <partial>:\\n 0:\\tmov eax,0x2a\\n 5:\\tret", flush=True)\n'
            'time.sleep(2)\n')
        objdump.chmod(0o755)
        with mock.patch.dict(os.environ, {'PATH': str(tools_dir)}):
            artifact = self.backend(timeout=0.1)
        self.assertTrue(any('timeout' in d.lower() for d in artifact.diagnostics))
        self.assertEqual(len(artifact.functions), 1)
        self.assertEqual(len(artifact.functions[0].instructions), 2)
        self.assertIsNone(artifact.functions[0].source)

    def test_relocatable_object_is_disassembled_without_claiming_applied_relocations(self):
        obj = self.root / 'fixture.o'
        subprocess.run(['gcc', '-O2', '-c', str(self.root / 'fixture.c'), '-o', str(obj)],
                       check=True, capture_output=True)
        artifact = self.backend(obj)
        self.assertTrue(artifact.functions)
        self.assertTrue(any('relocation' in d.lower() for d in artifact.diagnostics))
        self.assertTrue(all(f.source is None for f in artifact.functions))

    def test_text_relocation_prevents_constant_instruction_recovery(self):
        source = self.root / 'textrel.S'
        source.write_text('.text\n.globl reloc_leaf\n.type reloc_leaf,@function\n'
                          'reloc_leaf:\n movabs $external_symbol,%rax\n ret\n'
                          '.size reloc_leaf,.-reloc_leaf\n'
                          '.section .note.GNU-stack,"",@progbits\n')
        binary = self.root / 'textrel.so'
        subprocess.run(['gcc', '-shared', str(source), '-o', str(binary)],
                       check=True, capture_output=True)
        artifact = self.backend(binary)
        function = next(f for f in artifact.functions if f.name == 'reloc_leaf')
        self.assertTrue(function.instructions)
        self.assertIsNone(function.source)
        self.assertTrue(any('text relocation' in d.lower() for d in artifact.diagnostics))

    def test_malicious_elf_file_offsets_produce_diagnostics(self):
        data = bytearray(self.binary.read_bytes())
        data[32:40] = ((1 << 64) - 1).to_bytes(8, 'little')
        malformed = self.root / 'invalid offsets.so'
        malformed.write_bytes(data)
        artifact = self.backend(malformed)
        self.assertTrue(artifact.diagnostics)
        self.assertTrue(all(f.source is None for f in artifact.functions))

    def test_writable_executable_segment_relocation_without_textrel_is_rejected(self):
        source = self.root / 'writable_code.S'
        source.write_text('.section .wxcode,"awx",@progbits\n'
                          '.globl reloc_writable\n.type reloc_writable,@function\n'
                          'reloc_writable:\n movabs $external_symbol,%rax\n ret\n'
                          '.size reloc_writable,.-reloc_writable\n'
                          '.data\n.globl external_symbol\nexternal_symbol:\n .quad 0\n'
                          '.section .note.GNU-stack,"",@progbits\n')
        binary = self.root / 'writable_code.so'
        subprocess.run(['gcc', '-shared', '-nostdlib', str(source), '-o', str(binary)],
                       check=True, capture_output=True)
        # Writable code gets a loader relocation without necessarily DT_TEXTREL.
        # The on-disk zero immediate is not the runtime address of the symbol.
        if shutil.which('readelf'):
            dynamic = subprocess.run(['readelf', '-d', str(binary)], check=True,
                                     capture_output=True, text=True).stdout
            self.assertNotIn('(TEXTREL)', dynamic)
        artifact = self.backend(binary)
        function = next(f for f in artifact.functions if f.name == 'reloc_writable')
        self.assertTrue(function.instructions)
        self.assertIsNone(function.source)
        self.assertTrue(any('writable' in d.lower() and 'executable' in d.lower()
                            for d in artifact.diagnostics))

    def dynamic_elf(self, entries, *, segments=1):
        header = bytearray(self.binary.read_bytes()[:64])
        header[32:40] = (64).to_bytes(8, 'little')
        header[54:56] = (56).to_bytes(2, 'little')
        header[56:58] = segments.to_bytes(2, 'little')
        offset = 64 + 56 * segments
        table = b''.join(struct.pack('<QQ', tag, value) for tag, value in entries)
        program = struct.pack('<IIQQQQQQ', 2, 4, offset, 0, 0, len(table), len(table), 8)
        path = self.root / 'dynamic-table-only.elf'
        path.write_bytes(header + program * segments + table)
        return path

    def test_duplicate_dynamic_segments_are_rejected_before_repeated_table_scanning(self):
        # Repeated pointers must not multiply parser work by the header count.
        path = self.dynamic_elf([(0, 0)], segments=64)
        _, _, _, diagnostics, supported = _inspect(path)
        self.assertFalse(supported)
        self.assertTrue(any('multiple' in d.lower() and 'dynamic' in d.lower() for d in diagnostics))

    def test_dynamic_table_requires_a_null_terminator(self):
        path = self.dynamic_elf([(21, 0)] * 256)
        _, _, _, diagnostics, supported = _inspect(path)
        self.assertFalse(supported)
        self.assertTrue(any('terminat' in d.lower() for d in diagnostics))

    def test_timeout_budget_includes_hashing(self):
        tick = iter([0.0, 2.0])
        def clock():
            return next(tick, 2.0)
        output = '0000000000000000 <constant>:\n 0:\tmov eax,0x2a\n 5:\tret\n'
        with mock.patch('time.monotonic', side_effect=clock), \
                mock.patch('gamedecomp.backends.native._objdump', return_value=(output, [], True)):
            artifact = self.backend(timeout=1)
        self.assertFalse(artifact.metadata.get('hash_complete', True))
        self.assertEqual(artifact.binary_hash, '')
        self.assertTrue(any('timeout' in d.lower() for d in artifact.diagnostics))
        self.assertTrue(all(f.source is None for f in artifact.functions))

    def test_inspection_accepts_an_optional_expired_deadline(self):
        _, _, _, diagnostics, supported = _inspect(self.binary, deadline=0.0)
        self.assertFalse(supported)
        self.assertTrue(any('timeout' in d.lower() for d in diagnostics))

    def test_recovery_stops_when_its_shared_deadline_expires(self):
        output = ('0000000000000000 <many_ops>:\n 0:\txor eax,eax\n' +
                  ''.join(f' {index + 1:x}:\tadd eax,0x1\n' for index in range(1000)) +
                  ' 1000:\tret\n')
        function = _parse_disassembly(output)[0]
        tick = iter([0.0, 0.0, 2.0])
        with mock.patch('time.monotonic', side_effect=lambda: next(tick, 2.0)):
            _Recovery(function, deadline=1.0).recover()
        self.assertIsNone(function.source)
        self.assertTrue(any('timeout' in d.lower() for d in function.diagnostics))


if __name__ == '__main__':
    unittest.main()
