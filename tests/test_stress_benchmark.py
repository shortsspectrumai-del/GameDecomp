from pathlib import Path
import struct
import tempfile
import unittest

from benchmarks.real_game import mapped_symbol_addresses
from benchmarks.stress_game import run_stress


class StressBenchmarkTests(unittest.TestCase):
    def test_pie_symbols_are_mapped_only_in_evaluation(self):
        header = bytearray(120)
        header[:6] = b'\x7fELF\x02\x01'
        struct.pack_into('<Q', header, 32, 64)
        struct.pack_into('<HH', header, 54, 56, 1)
        struct.pack_into('<I', header, 64, 1)
        struct.pack_into('<Q', header, 80, 0)
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory)/'pie'
            binary.write_bytes(header)
            symbols = 'main T 1000 20\n'
            report = {'metadata': {'image_base': 0x100000}}
            mapped, adjustment = mapped_symbol_addresses(binary, report, symbols, {'main'})
            self.assertEqual(adjustment, 0x100000)
            self.assertEqual(mapped, {'main': 0x101000})
            self.assertEqual(report, {'metadata': {'image_base': 0x100000}})
            self.assertEqual(mapped_symbol_addresses(binary, {}, symbols, {'main'}), ({'main': 0x1000}, 0))

    def test_invalid_image_mapping_is_not_guessed(self):
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory)/'invalid'
            binary.write_bytes(b'bad')
            with self.assertRaises(ValueError):
                mapped_symbol_addresses(binary, {'metadata': {'image_base': 1}}, '', set())

    def test_hash_mismatch_blocks_stress_build_before_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root/'2048.c').write_text('not the trusted game')
            with self.assertRaises(ValueError):
                run_stress(root, root/'output', root/'ghidra')
            self.assertFalse((root/'output').exists())
