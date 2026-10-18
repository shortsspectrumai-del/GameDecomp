import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path


def wasm_fixture(op=0x6a):
    return (b'\0asm\x01\0\0\0'
            b'\x01\x07\x01\x60\x02\x7f\x7f\x01\x7f'
            b'\x03\x02\x01\x00'
            b'\x07\x07\x01\x03add\x00\x00'
            b'\x0a\x09\x01\x07\x00\x20\x00\x20\x01' + bytes([op]) + b'\x0b')


class WasmTests(unittest.TestCase):
    def analyze(self, data):
        from gamedecomp.backends.wasm import analyze
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'example.wasm'
            path.write_bytes(data)
            return analyze(path)

    def test_add_has_source_and_parameter_evidence(self):
        result = self.analyze(wasm_fixture())
        self.assertEqual(len(result.functions), 1)
        function = result.functions[0]
        self.assertIsNotNone(function.source)
        self.assertEqual(function.metadata['parameter_bits'], [32, 32])
        self.assertEqual(function.metadata['return_bits'], 32)
        self.assertIn('uint32_t', function.source)

    def test_unsupported_opcode_keeps_evidence(self):
        function = self.analyze(wasm_fixture(0x6d)).functions[0]
        self.assertIsNone(function.source)
        self.assertTrue(function.diagnostics)
        self.assertTrue(function.instructions)

    def test_truncation_rejected(self):
        with self.assertRaises(ValueError):
            self.analyze(wasm_fixture()[:-1])

    def test_bad_stack_not_invented(self):
        data = wasm_fixture().replace(b'\x20\x00\x20\x01', b'\x01\x01\x01\x01')
        function = self.analyze(data).functions[0]
        self.assertIsNone(function.source)

    def test_deadline_checked_inside_single_function(self):
        from gamedecomp.backends.wasm import analyze
        def leb(value):
            data = bytearray()
            while value >= 128:
                data.append((value & 127) | 128)
                value >>= 7
            data.append(value)
            return bytes(data)
        body = b'\0' + b'\x01' * 1000 + b'\x41\0\x0b'
        code = b'\x01' + leb(len(body)) + body
        data = b'\0asm\x01\0\0\0\x01\x05\x01\x60\0\x01\x7f\x03\x02\x01\0' + b'\x0a' + leb(len(code)) + code
        counter = iter(index * 0.001 for index in range(100000))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'large.wasm'
            path.write_bytes(data)
            with patch('gamedecomp.backends.wasm.time.monotonic', side_effect=lambda: next(counter)):
                with self.assertRaises(TimeoutError):
                    analyze(path, timeout=0.01)

    def test_expanded_wasm_opcodes_compile_and_match_semantics(self):
        import ctypes
        import shutil
        import subprocess
        # Build a WASM module with 3 functions:
        # 0: select_lt_s(a: i32, b: i32) -> i32: (a <s b) ? a : b  (min_s via i32.lt_s + select)
        #    body: local.get 0, local.get 1, local.get 0, local.get 1, i32.lt_s (0x48), select (0x1b), end (0x0b)
        # 1: bitops32(a: i32, s: i32) -> i32: (rotl(a, s) ^ rotr(a, s)) + shr_s(a, s) + clz(a) + ctz(a) + popcnt(a)
        # 2: conv32(a: i32) -> i32: wrap_i64(extend_i32_s(extend8_s(a)) + extend_i32_u(extend16_s(a)))
        b0 = b'\x00\x20\x00\x20\x01\x20\x00\x20\x01\x48\x1b\x0b'
        b1 = (b'\x00'
              b'\x20\x00\x20\x01\x77'  # rotl(p0, p1)
              b'\x20\x00\x20\x01\x78'  # rotr(p0, p1)
              b'\x73'                  # ^
              b'\x20\x00\x20\x01\x75'  # shr_s(p0, p1)
              b'\x6a'                  # +
              b'\x20\x00\x67\x6a'      # + clz(p0)
              b'\x20\x00\x68\x6a'      # + ctz(p0)
              b'\x20\x00\x69\x6a'      # + popcnt(p0)
              b'\x0b')
        b2 = (b'\x00'
              b'\x20\x00\xc0\xac'      # i64.extend_i32_s(i32.extend8_s(p0))
              b'\x20\x00\xc1\xad'      # i64.extend_i32_u(i32.extend16_s(p0))
              b'\x7c'                  # i64.add
              b'\xa7'                  # i32.wrap_i64
              b'\x0b')
        type_sec = b'\x01\x0c\x02\x60\x02\x7f\x7f\x01\x7f\x60\x01\x7f\x01\x7f'
        func_sec = b'\x03\x04\x03\x00\x00\x01'
        exp_payload = (b'\x03'
                       b'\x03min\x00\x00'
                       b'\x04bits\x00\x01'
                       b'\x04conv\x00\x02')
        exp_sec = b'\x07' + bytes([len(exp_payload)]) + exp_payload
        code_payload = (b'\x03'
                        + bytes([len(b0)]) + b0
                        + bytes([len(b1)]) + b1
                        + bytes([len(b2)]) + b2)
        code_sec = b'\x0a' + bytes([len(code_payload)]) + code_payload
        wasm_bytes = b'\0asm\x01\0\0\0' + type_sec + func_sec + exp_sec + code_sec
        result = self.analyze(wasm_bytes)
        self.assertEqual(len(result.functions), 3)
        for fn in result.functions:
            self.assertIsNotNone(fn.source, fn.diagnostics)
        if not shutil.which('gcc'):
            return
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            c_file = root / 'wasm_recovered.c'
            c_file.write_text('#include <stdint.h>\n' + '\n\n'.join(fn.source for fn in result.functions))
            so_file = root / 'wasm_recovered.so'
            subprocess.run(['gcc', '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', '-fPIC', '-shared',
                            str(c_file), '-o', str(so_file)], check=True, capture_output=True)
            lib = ctypes.CDLL(str(so_file))
            f_min = getattr(lib, result.functions[0].metadata['export_name'])
            f_min.argtypes = [ctypes.c_uint32, ctypes.c_uint32]
            f_min.restype = ctypes.c_uint32
            self.assertEqual(f_min(0xffffffff, 5), 0xffffffff)  # -1 < 5 in signed i32
            self.assertEqual(f_min(10, 3), 3)
            f_bits = getattr(lib, result.functions[1].metadata['export_name'])
            f_bits.argtypes = [ctypes.c_uint32, ctypes.c_uint32]
            f_bits.restype = ctypes.c_uint32
            self.assertEqual(f_bits(0, 0), 64)  # clz(0)=32 + ctz(0)=32 + popcnt(0)=0
            self.assertEqual(f_bits(0x80000000, 4),
                             ((0x00000008 ^ 0x08000000) + 0xf8000000 + 0 + 31 + 1) & 0xffffffff)
            f_conv = getattr(lib, result.functions[2].metadata['export_name'])
            f_conv.argtypes = [ctypes.c_uint32]
            f_conv.restype = ctypes.c_uint32
            # p0 = 0x80ff: extend8_s(0xff) = -1, extend16_s(0x80ff) = -32513 (0xffff80ff unsigned 32-bit)
            self.assertEqual(f_conv(0x80ff), (0xffffffffffffffff + 0xffff80ff) & 0xffffffff)

