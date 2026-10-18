"""Synthetic flat Mega Drive ROMs test static container conversion only."""
import hashlib
from pathlib import Path
import struct
import tempfile
import unittest


def megadrive_fixture():
    data = bytearray(0x400)
    struct.pack_into('>II', data, 0, 0x00FFFFFC, 0x200)
    data[0x100:0x110] = b'SEGA MEGA DRIVE '
    struct.pack_into('>II', data, 0x1A0, 0, len(data) - 1)
    data[0x200:0x204] = b'\x70\x2a\x4e\x75'
    struct.pack_into('>H', data, 0x18E, 0xBE9F)
    return data


class MegaDriveFormatTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / 'source.bin'
        self.destination = self.root / 'derived.elf'

    def inspect(self, data):
        from gamedecomp.megadrive_format import inspect_megadrive_module
        self.source.write_bytes(data)
        return inspect_megadrive_module(self.source)

    def test_header_detection_uses_signature_and_excludes_known_addons(self):
        from gamedecomp.megadrive_format import detect_megadrive_format
        self.assertEqual(detect_megadrive_format(megadrive_fixture()), 'MEGADRIVE')
        for data in (b'', bytes(0x400), megadrive_fixture()[:0x103]):
            self.assertIsNone(detect_megadrive_format(data))
        for label in (b'SEGA 32X        ', b'SEGA SEGASATURN ', b'SEGA PICO       '):
            data = megadrive_fixture()
            data[0x100:0x110] = label
            self.assertIsNone(detect_megadrive_format(data))
            with self.assertRaises(ValueError):
                self.inspect(data)

    def test_valid_metadata_hashes_entry_and_elf_payload(self):
        from gamedecomp.megadrive_format import convert_megadrive_module
        data = megadrive_fixture()
        info = self.inspect(data)
        self.assertEqual(info['architecture'], 'm68k')
        self.assertEqual(info['entry_point'], 0x200)
        self.assertEqual(info['profile'], 'megadrive-m68k')
        self.assertEqual(info['checksum_status'], 'VERIFIED')
        self.assertEqual(info['checksum_computed'], 0xBE9F)
        result = convert_megadrive_module(self.source, self.destination)
        output = self.destination.read_bytes()
        header = struct.unpack_from('>16sHHIIIIIHHHHHH', output)
        self.assertEqual(header[0][:7], b'\x7fELF\x01\x02\x01')
        self.assertEqual(header[1:5], (2, 4, 1, 0x200))
        ph = struct.unpack_from('>IIIIIIII', output, 52)
        self.assertEqual(ph, (1, 84, 0, 0, len(data), len(data), 5, 2))
        self.assertEqual(output[84:], data)
        self.assertEqual(result['source_sha256'], hashlib.sha256(data).hexdigest())
        self.assertEqual(result['derived_sha256'], hashlib.sha256(output).hexdigest())
        second = convert_megadrive_module(self.source, self.root / 'second.elf')
        self.assertEqual(result['derived_sha256'], second['derived_sha256'])

    def test_nonzero_wrong_checksum_rejected_zero_placeholder_is_not_verified(self):
        data = megadrive_fixture()
        data[0x201] ^= 1
        with self.assertRaisesRegex(ValueError, 'checksum'):
            self.inspect(data)
        struct.pack_into('>H', data, 0x18E, 0)
        info = self.inspect(data)
        self.assertEqual(info['checksum_status'], 'NOT_PROVIDED')
        self.assertFalse(info['checksum_verified'])
        self.assertTrue(any('checksum' in note for note in info['limitations']))

    def test_checksum_zero_that_actually_matches_is_verified(self):
        data = megadrive_fixture()
        data[0x200:] = bytes(len(data) - 0x200)
        struct.pack_into('>H', data, 0x18E, 0)
        self.assertEqual(self.inspect(data)['checksum_status'], 'VERIFIED')

    def test_truncated_odd_bytes_rom_bounds_and_reset_alignment_rejected(self):
        for length in (0, 8, 0x1FF, 0x201):
            with self.subTest(length=length), self.assertRaises(ValueError):
                self.inspect(megadrive_fixture()[:length])
        for offset, value in ((4, 0), (4, 0x100), (4, 0x201), (4, 0x400),
                              (4, 0x1000200), (0x1A0, 2), (0x1A4, 0x500),
                              (0x1A4, 0x1FF), (0x1A4, 0xFFFFFFFE)):
            data = megadrive_fixture()
            struct.pack_into('>I', data, offset, value)
            with self.subTest(offset=offset, value=value), self.assertRaises(ValueError):
                self.inspect(data)

    def test_sp_must_be_even_and_write_below_pointer_to_canonical_ram(self):
        for sp in (0xFFFFFD, 0xFF0000, 0xFE0000, 0x1000002, 0x200):
            data = megadrive_fixture()
            struct.pack_into('>I', data, 0, sp)
            with self.subTest(sp=sp), self.assertRaises(ValueError):
                self.inspect(data)
        for sp in (0xFF0002, 0x1000000, 0xE1000000, 0xE0FFFFFC):
            data = megadrive_fixture()
            struct.pack_into('>I', data, 0, sp)
            info = self.inspect(data)
            self.assertEqual(info['initial_sp'], sp)

    def test_interleaved_copier_header_and_byte_swapped_inputs_are_not_guessed(self):
        data = megadrive_fixture()
        with self.assertRaises(ValueError):
            self.inspect(bytes(512) + data)
        for offset in range(0, len(data), 2):
            data[offset], data[offset + 1] = data[offset + 1], data[offset]
        with self.assertRaises(ValueError):
            self.inspect(data)

    def test_source_existing_output_and_dangling_symlinks_are_protected(self):
        from gamedecomp.megadrive_format import convert_megadrive_module
        data = megadrive_fixture()
        self.source.write_bytes(data)
        with self.assertRaises(ValueError):
            convert_megadrive_module(self.source, self.source)
        self.destination.write_bytes(b'keep')
        with self.assertRaises(ValueError):
            convert_megadrive_module(self.source, self.destination)
        self.assertEqual(self.destination.read_bytes(), b'keep')
        self.destination.unlink()
        outside = self.root / 'missing'
        self.destination.symlink_to(outside)
        with self.assertRaises(ValueError):
            convert_megadrive_module(self.source, self.destination)
        self.assertFalse(outside.exists())
        self.assertEqual(self.source.read_bytes(), data)

    def test_size_limit_rejects_bank_switched_or_oversized_rom_before_read(self):
        from gamedecomp.megadrive_format import inspect_megadrive_module
        with self.source.open('wb') as stream:
            stream.truncate(4 * 1024 * 1024 + 1)
        with self.assertRaisesRegex(ValueError, 'size|MiB'):
            inspect_megadrive_module(self.source)

    def test_invalid_source_does_not_publish_output(self):
        from gamedecomp.megadrive_format import convert_megadrive_module
        self.source.write_bytes(b'invalid')
        with self.assertRaises(ValueError):
            convert_megadrive_module(self.source, self.destination)
        self.assertFalse(self.destination.exists())
