"""Synthetic iNES fixtures test bounded NROM import without external ROMs."""
import tempfile
import unittest
from pathlib import Path

from gamedecomp.nes_format import detect_nes, inspect_nes_module, prepare_nes_module


def nrom_image(prg_banks=1, chr_banks=1, trainer=False, reset=0xC000):
    header = bytearray(b'NES\x1a' + bytes(12))
    header[4:6] = bytes((prg_banks, chr_banks))
    header[6] = 4 if trainer else 0
    prg = bytearray(b'\xea' * (prg_banks * 16384))
    if len(prg) >= 4:
        prg[-4:-2] = reset.to_bytes(2, 'little')
    return bytes(header) + (b'T' * 512 if trainer else b'') + bytes(prg) + b'C' * (chr_banks * 8192)


class NesFormatTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)

    def write_image(self, image):
        path = self.root / 'synthetic.nes'
        path.write_bytes(image)
        return path

    def test_detection_requires_full_magic(self):
        self.assertTrue(detect_nes(b'NES\x1a'))
        for head in (b'', b'NES', b'NES0', b'\x7fELF'):
            self.assertFalse(detect_nes(head))

    def test_nrom128_maps_mirrored_prg_and_reset_vector(self):
        source = self.write_image(nrom_image())
        info = inspect_nes_module(source)
        self.assertEqual((info['profile'], info['architecture'], info['bits']),
                         ('nes-nrom-6502', '6502', 16))
        output = self.root / 'prg.bin'
        prepared = prepare_nes_module(source, output)
        raw = output.read_bytes()
        self.assertEqual(len(raw), 32768)
        self.assertEqual(raw[:16384], raw[16384:])
        self.assertEqual(prepared['load_address'], 0x8000)
        self.assertEqual(prepared['entry_point'], 0xC000)
        self.assertEqual(prepared['processor_id'], '6502:LE:16:default')
        self.assertTrue(prepared['prg_mirrored'])
        self.assertEqual(prepared['chr_omitted_bytes'], 8192)

    def test_nrom256_keeps_bank_order_and_chr_ram(self):
        image = bytearray(nrom_image(2, 0, reset=0x8000))
        image[16] = 0xA9
        image[16 + 16384] = 0x60
        source = self.write_image(image)
        output = self.root / 'prg.bin'
        info = prepare_nes_module(source, output)
        raw = output.read_bytes()
        self.assertEqual((raw[0], raw[16384]), (0xA9, 0x60))
        self.assertFalse(info['prg_mirrored'])
        self.assertEqual(info['chr_omitted_bytes'], 0)
        self.assertEqual(info['entry_point'], 0x8000)

    def test_trainer_is_skipped_explicitly(self):
        source = self.write_image(nrom_image(trainer=True))
        output = self.root / 'prg.bin'
        info = prepare_nes_module(source, output)
        self.assertEqual(info['trainer_omitted_bytes'], 512)
        self.assertEqual(output.read_bytes()[0], 0xEA)

    def test_malformed_or_unsupported_headers_fail_before_output(self):
        valid = nrom_image()
        cases = {'magic': b'BAD!' + valid[4:], 'truncated_header': valid[:15],
                 'truncated_prg': valid[:100], 'truncated_chr': valid[:-1],
                 'trailing': valid + b'X', 'reset_ram': nrom_image(reset=0x7FFF),
                 'zero_prg': nrom_image(0), 'large_prg': nrom_image(3),
                 'large_chr': nrom_image(1, 2)}
        for name, offset, value in [('nes2', 7, 8), ('mapper_low', 6, 16),
                                    ('mapper_high', 7, 16), ('vs', 7, 1),
                                    ('playchoice', 7, 2), ('archaic', 7, 4),
                                    ('reserved', 15, 1), ('four_screen', 6, 8)]:
            image = bytearray(valid)
            image[offset] = value
            cases[name] = image
        for name, image in cases.items():
            with self.subTest(name=name):
                source = self.write_image(image)
                output = self.root / (name + '.bin')
                with self.assertRaises(ValueError):
                    prepare_nes_module(source, output)
                self.assertFalse(output.exists())

    def test_output_cannot_overwrite_input(self):
        source = self.write_image(nrom_image())
        before = source.read_bytes()
        with self.assertRaises(ValueError):
            prepare_nes_module(source, source)
        self.assertEqual(source.read_bytes(), before)

    def test_output_refuses_existing_regular_file(self):
        source = self.write_image(nrom_image())
        output = self.root / 'existing.bin'
        output.write_bytes(b'KEEP')
        with self.assertRaises(ValueError):
            prepare_nes_module(source, output)
        self.assertEqual(output.read_bytes(), b'KEEP')

    def test_output_refuses_existing_and_dangling_symlinks(self):
        source = self.write_image(nrom_image())
        for exists in (True, False):
            with self.subTest(target_exists=exists):
                target = self.root / ('target-' + str(exists))
                if exists:
                    target.write_bytes(b'KEEP')
                output = self.root / ('link-' + str(exists))
                output.symlink_to(target)
                with self.assertRaises(ValueError):
                    prepare_nes_module(source, output)
                self.assertTrue(output.is_symlink())
                if exists:
                    self.assertEqual(target.read_bytes(), b'KEEP')
                else:
                    self.assertFalse(target.exists())

    def test_oversized_input_is_rejected(self):
        source = self.write_image(nrom_image() + bytes(65536))
        with self.assertRaises(ValueError):
            inspect_nes_module(source)
