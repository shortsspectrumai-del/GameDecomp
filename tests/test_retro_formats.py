"""Synthetic executable headers test retro conversion without running target code."""
import hashlib
import struct
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


def psx_fixture():
    data = bytearray(0x840)
    data[:8] = b'PS-X EXE'
    struct.pack_into('<I', data, 0x10, 0x80010000)
    struct.pack_into('<II', data, 0x18, 0x80010000, 0x40)
    struct.pack_into('<II', data, 0x28, 0x80020000, 0x80)
    data[0x800:0x804] = b'CODE'
    return data


def gba_fixture():
    data = bytearray(0x100)
    struct.pack_into('<I', data, 0, 0xEA00002E)
    data[0xB2] = 0x96
    data[0xBD] = (-sum(data[0xA0:0xBD]) - 0x19) & 255
    data[0xC0:0xC4] = b'CODE'
    return data


def dol_fixture():
    data = bytearray(0x140)
    struct.pack_into('>I', data, 0, 0x100)
    struct.pack_into('>I', data, 0x48, 0x80003100)
    struct.pack_into('>I', data, 0x90, 0x20)
    struct.pack_into('>I', data, 7 * 4, 0x120)
    struct.pack_into('>I', data, 0x48 + 7 * 4, 0x80003200)
    struct.pack_into('>I', data, 0x90 + 7 * 4, 0x20)
    struct.pack_into('>III', data, 0xD8, 0x80003300, 0x20, 0x80003100)
    data[0x100:0x104] = b'CODE'
    data[0x120:0x124] = b'DATA'
    return data


class RetroFormatTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / 'source'

    def inspect(self, data, kind):
        from gamedecomp.retro_formats import inspect_retro_module
        self.source.write_bytes(data)
        return inspect_retro_module(self.source, kind)

    def test_detection_requires_evidence_and_never_guesses_dol(self):
        from gamedecomp.retro_formats import detect_retro_format
        self.assertEqual(detect_retro_format(psx_fixture()), 'PSX_EXE')
        self.assertEqual(detect_retro_format(gba_fixture()), 'GBA')
        self.assertIsNone(detect_retro_format(dol_fixture()))
        for data in (b'', b'PS-X', bytes(256)):
            self.assertIsNone(detect_retro_format(data))
        bad = gba_fixture()
        bad[0xA0] ^= 1
        self.assertIsNone(detect_retro_format(bad))

    def test_valid_modules_preserve_entry_architecture_payload_and_hashes(self):
        from gamedecomp.retro_formats import convert_retro_module
        for kind, fixture, machine, endian, entry in (
            ('PSX_EXE', psx_fixture, 8, '<', 0x80010000),
            ('GBA', gba_fixture, 40, '<', 0x080000C0),
            ('DOL', dol_fixture, 20, '>', 0x80003100),
        ):
            with self.subTest(kind=kind):
                data = fixture()
                self.source.write_bytes(data)
                destination = self.root / (kind + '.elf')
                info = convert_retro_module(self.source, destination, kind)
                output = destination.read_bytes()
                header = struct.unpack_from(endian + '16sHHIIIIIHHHHHH', output)
                self.assertEqual(header[0][:5], b'\x7fELF\x01')
                self.assertEqual(header[2], machine)
                self.assertEqual(header[4], entry)
                self.assertEqual(info['entry_point'], entry)
                self.assertEqual(info['source_sha256'], hashlib.sha256(data).hexdigest())
                self.assertEqual(info['derived_sha256'], hashlib.sha256(output).hexdigest())
                for index, segment in enumerate(info['segments']):
                    ph = struct.unpack_from(endian + 'IIIIIIII', output, 52 + 32 * index)
                    self.assertEqual(ph[0], 1)
                    self.assertEqual(ph[2], segment['address'])
                    self.assertEqual(ph[4], segment['file_size'])
                    self.assertEqual(ph[5], segment['memory_size'])
                    self.assertEqual(output[ph[1]:ph[1]+ph[4]], data[segment['file_offset']:segment['file_offset']+ph[4]])
                self.assertIn(b'CODE', output)
                repeated = convert_retro_module(self.source, self.root / (kind + '-repeat.elf'), kind)
                self.assertEqual(info['derived_sha256'], repeated['derived_sha256'])

    def test_truncated_unknown_wrong_format_and_source_replacement_fail(self):
        from gamedecomp.retro_formats import convert_retro_module
        for kind, fixture in (('PSX_EXE', psx_fixture), ('GBA', gba_fixture), ('DOL', dol_fixture)):
            for length in (0, 32, 0xBF):
                with self.subTest(kind=kind, length=length), self.assertRaises(ValueError):
                    self.inspect(fixture()[:length], kind)
        with self.assertRaises(ValueError):
            self.inspect(gba_fixture(), 'PSX_EXE')
        with self.assertRaises(ValueError):
            self.inspect(gba_fixture(), 'unknown')
        self.source.write_bytes(psx_fixture())
        with self.assertRaises(ValueError):
            convert_retro_module(self.source, self.source, 'PSX_EXE')
        self.assertEqual(self.source.read_bytes(), psx_fixture())

    def test_psx_bounds_overlap_and_invalid_entry_are_rejected(self):
        for offset, value in ((0x10, 0x80020000), (0x10, 0x80010001), (0x1C, 0x10000), (0x18, 0xFFFFFFF0), (0x28, 0x80010000)):
            data = psx_fixture()
            struct.pack_into('<I', data, offset, value)
            with self.subTest(offset=offset, value=value), self.assertRaises(ValueError):
                self.inspect(data, 'PSX_EXE')

    def test_gba_requires_valid_checksum_arm_branch_and_in_file_target(self):
        for offset, value in ((0xBD, 0), (0xB2, 0), (0, 0), (3, 0xEB), (2, 0x7F)):
            data = gba_fixture()
            data[offset] = value
            with self.subTest(offset=offset, value=value), self.assertRaises(ValueError):
                self.inspect(data, 'GBA')

    def test_dol_rejects_file_overlap_memory_overlap_overflow_and_entry_in_data(self):
        for offset, value in ((0, 0x80), (7 * 4, 0x110), (0x48 + 7 * 4, 0x80003110), (0x90, 0xFFFFFFF0), (0xE0, 0x80003200), (0xD8, 0xFFFFFFF0)):
            data = dol_fixture()
            struct.pack_into('>I', data, offset, value)
            with self.subTest(offset=offset, value=value), self.assertRaises(ValueError):
                self.inspect(data, 'DOL')

    def test_dol_bss_subtracts_loaded_sections_and_never_clobbers_payload(self):
        data = dol_fixture()
        struct.pack_into('>II', data, 0xD8, 0x800030F0, 0x150)
        info = self.inspect(data, 'DOL')
        bss = [segment for segment in info['segments'] if segment['file_size'] == 0]
        self.assertEqual([(s['address'], s['memory_size']) for s in bss], [(0x800030F0, 0x10), (0x80003120, 0xE0), (0x80003220, 0x20)])

    def test_output_is_not_written_when_module_is_invalid(self):
        from gamedecomp.retro_formats import convert_retro_module
        self.source.write_bytes(dol_fixture()[:128])
        output = self.root / 'output'
        with self.assertRaises(ValueError):
            convert_retro_module(self.source, output, 'DOL')
        self.assertFalse(output.exists())

    def test_oversized_source_is_rejected_before_reading_payload(self):
        from gamedecomp.retro_formats import inspect_retro_module
        with self.source.open('wb') as stream:
            stream.truncate(256 * 1024 * 1024 + 1)
        with self.assertRaisesRegex(ValueError, 'size'):
            inspect_retro_module(self.source, 'DOL')

    def test_existing_destination_and_symlink_are_never_overwritten(self):
        from gamedecomp.retro_formats import convert_retro_module
        self.source.write_bytes(psx_fixture())
        destination = self.root / 'existing'
        destination.write_bytes(b'keep')
        with self.assertRaises(FileExistsError):
            convert_retro_module(self.source, destination, 'PSX_EXE')
        self.assertEqual(destination.read_bytes(), b'keep')
        alias = self.root / 'alias'
        alias.symlink_to(destination)
        with self.assertRaises(FileExistsError):
            convert_retro_module(self.source, alias, 'PSX_EXE')
        self.assertEqual(destination.read_bytes(), b'keep')

    def test_gba_negative_branch_and_psx_bss_overflow_are_rejected(self):
        data = gba_fixture()
        struct.pack_into('<I', data, 0, 0xEAFFFFFF)
        with self.assertRaises(ValueError):
            self.inspect(data, 'GBA')
        data = psx_fixture()
        struct.pack_into('<II', data, 0x28, 0xFFFFFFF0, 0x80)
        with self.assertRaises(ValueError):
            self.inspect(data, 'PSX_EXE')

    def test_derived_elf_size_bound_includes_program_headers(self):
        from gamedecomp.retro_formats import convert_retro_module
        data = bytearray(0x100 + 18 * 4)
        for index in range(18):
            struct.pack_into('>I', data, index * 4, 0x100 + index * 4)
            struct.pack_into('>I', data, 0x48 + index * 4, 0x80003000 + index * 16)
            struct.pack_into('>I', data, 0x90 + index * 4, 4)
        struct.pack_into('>III', data, 0xD8, 0x80003000, 18 * 16, 0x80003000)
        self.source.write_bytes(data)
        destination = self.root / 'too-large.elf'
        with patch('gamedecomp.retro_formats.MAX_BYTES', 768):
            with self.assertRaisesRegex(ValueError, 'size'):
                convert_retro_module(self.source, destination, 'DOL')
        self.assertFalse(destination.exists())
