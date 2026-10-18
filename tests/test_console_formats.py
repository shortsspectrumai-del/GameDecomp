"""Synthetic console modules exercise format boundaries without executing code."""
import hashlib
import importlib.util
import struct
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


def nro_fixture():
    data = bytearray(0x3000)
    data[0x10:0x14] = b'NRO0'
    struct.pack_into('<I', data, 0x18, len(data))
    for index in range(3):
        struct.pack_into('<II', data, 0x20 + index * 8, index * 0x1000, 0x1000)
    struct.pack_into('<I', data, 0x38, 0x1000)
    data[0x1000:0x1004] = b'RO!!'
    data[0x2000:0x2004] = b'DATA'
    return data


def nso_fixture(compressed=False):
    payloads = [b'\xc0\x03\x5f\xd6', b'RO!!', b'DATA']
    data = bytearray(0x100)
    data[:4] = b'NSO0'
    struct.pack_into('<I', data, 0xC, 0x38 | (7 if compressed else 0))
    for index, payload in enumerate(payloads):
        encoded = bytes([len(payload) << 4]) + payload if compressed else payload
        struct.pack_into('<III', data, 0x10 + index * 0x10, len(data), index * 0x1000, len(payload))
        struct.pack_into('<I', data, 0x60 + index * 4, len(encoded))
        data[0xA0 + index * 0x20:0xC0 + index * 0x20] = hashlib.sha256(payload).digest()
        data.extend(encoded)
    struct.pack_into('<I', data, 0x3C, 0x1000)
    return data


class ConsoleFormatTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / 'module'

    def inspect(self, data, kind):
        from gamedecomp.console_formats import inspect_console_module
        self.source.write_bytes(data)
        return inspect_console_module(self.source, kind)

    def test_detection_uses_magic_not_extension(self):
        from gamedecomp.console_formats import detect_console_format
        self.assertEqual(detect_console_format(nro_fixture()[:32]), 'NRO')
        self.assertEqual(detect_console_format(nso_fixture()[:32]), 'NSO')
        for data in (b'', b'NRO0', b'NSO', b'\x7fELF'):
            self.assertIsNone(detect_console_format(data))

    def test_nro_segments_and_appended_assets_are_preserved_as_source_only(self):
        info = self.inspect(nro_fixture() + b'ASET' + b'asset', 'NRO')
        self.assertEqual(info['architecture'], 'aarch64')
        self.assertEqual(info['bits'], 64)
        self.assertEqual(info['endianness'], 'little')
        self.assertEqual(info['segments'][2]['memory_size'], 0x2000)
        self.assertEqual(info['appended_bytes'], 9)
        self.assertTrue(info['limitations'])

    def test_conversion_has_load_headers_payload_bss_and_reproducible_hash(self):
        from gamedecomp.console_formats import convert_console_module
        for kind, data in [('NRO', nro_fixture()), ('NSO', nso_fixture())]:
            with self.subTest(kind=kind):
                self.source.write_bytes(data)
                first = self.root / f'{kind}.elf'
                info = convert_console_module(self.source, first)
                output = first.read_bytes()
                header = struct.unpack_from('<16sHHIQQQIHHHHHH', output)
                self.assertEqual(header[0][:7], b'\x7fELF\x02\x01\x01')
                self.assertEqual(header[1:3], (2, 183))
                self.assertEqual(header[4], 0)
                self.assertEqual(header[10], 3)
                for index, segment in enumerate(info['segments']):
                    ph = struct.unpack_from('<IIQQQQQQ', output, 64 + index * 56)
                    self.assertEqual(ph[0], 1)
                    self.assertEqual(ph[3], segment['memory_offset'])
                    self.assertEqual(ph[5], segment['size'])
                    self.assertEqual(ph[6], segment['memory_size'])
                    self.assertEqual(ph[2] % ph[7], ph[3] % ph[7])
                second = convert_console_module(self.source, self.root / f'{kind}-2.elf')
                self.assertEqual(info['derived_sha256'], second['derived_sha256'])
                self.assertEqual(info['source_sha256'], hashlib.sha256(data).hexdigest())
                self.assertEqual(info['derived_sha256'], hashlib.sha256(output).hexdigest())
                self.assertIn(b'RO!!', output)
                self.assertIn(b'DATA', output)

    def test_rejects_truncation_invalid_version_and_wrong_requested_format(self):
        for kind, data in [('NRO', nro_fixture()), ('NSO', nso_fixture())]:
            for length in (0, 4, 32, 0x7F):
                with self.subTest(kind=kind, length=length), self.assertRaises(ValueError):
                    self.inspect(data[:length], kind)
            bad = bytearray(data)
            struct.pack_into('<I', bad, 0x14 if kind == 'NRO' else 4, 1)
            with self.assertRaises(ValueError):
                self.inspect(bad, kind)
        with self.assertRaises(ValueError):
            self.inspect(nro_fixture(), 'NSO')

    def test_rejects_overlapping_unaligned_out_of_bounds_and_oversized_segments(self):
        for kind, original, offset in [('NRO', nro_fixture(), 0x28), ('NSO', nso_fixture(), 0x24)]:
            for invalid in (0, 1, 0xFFFFF000):
                bad = bytearray(original)
                struct.pack_into('<I', bad, offset, invalid)
                with self.subTest(kind=kind, invalid=invalid), self.assertRaises(ValueError):
                    self.inspect(bad, kind)
        bad = nso_fixture()
        struct.pack_into('<I', bad, 0x20, 0x100)
        with self.assertRaises(ValueError):
            self.inspect(bad, 'NSO')
        bad = nso_fixture()
        struct.pack_into('<I', bad, 0x18, 256 * 1024 * 1024 + 1)
        with self.assertRaises(ValueError):
            self.inspect(bad, 'NSO')
        bad = nro_fixture()
        struct.pack_into('<I', bad, 0x18, 0xFFFF_FFFF)
        with self.assertRaises(ValueError):
            self.inspect(bad, 'NRO')

    def test_nso_hash_failure_and_unknown_compression_are_explicit(self):
        bad = nso_fixture()
        bad[-1] ^= 1
        with self.assertRaisesRegex(ValueError, 'hash'):
            self.inspect(bad, 'NSO')
        for flag in (0x80, 0x100):
            bad = nso_fixture()
            struct.pack_into('<I', bad, 0xC, flag)
            with self.assertRaisesRegex(ValueError, 'flags|compression'):
                self.inspect(bad, 'NSO')

    def test_nso_compressed_without_lz4_fails_without_writing_destination(self):
        from gamedecomp.console_formats import convert_console_module
        self.source.write_bytes(nso_fixture(compressed=True))
        destination = self.root / 'output.elf'
        with patch('gamedecomp.console_formats._load_lz4', side_effect=ImportError):
            with self.assertRaisesRegex(ValueError, 'LZ4'):
                convert_console_module(self.source, destination)
        self.assertFalse(destination.exists())

    def test_nso_compressed_literal_block_is_decoded_if_dependency_available(self):
        try:
            available = importlib.util.find_spec('lz4.block') is not None
        except ModuleNotFoundError:
            available = False
        if not available:
            self.skipTest('Optional lz4 dependency is unavailable')
        info = self.inspect(nso_fixture(compressed=True), 'NSO')
        self.assertEqual(info['segments'][0]['size'], 4)
        self.assertTrue(info['segments'][0]['compressed'])

    def test_nro_text_must_contain_the_module_header(self):
        bad = nro_fixture()
        struct.pack_into('<I', bad, 0x24, 4)
        with self.assertRaisesRegex(ValueError, 'header'):
            self.inspect(bad, 'NRO')

    def test_bss_overflow_and_malformed_lz4_are_rejected(self):
        for kind, data, offset in [('NRO', nro_fixture(), 0x38), ('NSO', nso_fixture(), 0x3C)]:
            struct.pack_into('<I', data, offset, 0xFFFF_FFFF)
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                self.inspect(data, kind)
        bad = nso_fixture(compressed=True)
        bad[0x100] = 0xFF
        with self.assertRaises(ValueError):
            self.inspect(bad, 'NSO')

    def test_disabled_hashes_do_not_claim_integrity_and_execute_only_is_preserved(self):
        data = nso_fixture()
        struct.pack_into('<I', data, 0xC, 0x40)
        data[-1] ^= 1
        info = self.inspect(data, 'NSO')
        self.assertFalse(any(segment['hash_checked'] for segment in info['segments']))
        self.assertEqual(info['segments'][0]['elf_flags'], 1)
        self.assertEqual(info['required_profile'], 'switch-aarch64')
        self.assertTrue(any('does not encode' in limitation for limitation in info['limitations']))

    def test_invalid_input_preserves_an_existing_destination(self):
        from gamedecomp.console_formats import convert_console_module
        bad = nso_fixture()
        bad[-1] ^= 1
        self.source.write_bytes(bad)
        destination = self.root / 'existing.elf'
        destination.write_bytes(b'KEEP')
        with self.assertRaises(ValueError):
            convert_console_module(self.source, destination)
        self.assertEqual(destination.read_bytes(), b'KEEP')

    def test_valid_module_cannot_replace_existing_destination_or_follow_symlink(self):
        from gamedecomp.console_formats import convert_console_module
        self.source.write_bytes(nso_fixture())
        existing = self.root / 'existing.elf'
        existing.write_bytes(b'KEEP')
        link = self.root / 'linked.elf'
        link.symlink_to(existing)
        dangling = self.root / 'dangling.elf'
        missing_target = self.root / 'must-not-create.elf'
        dangling.symlink_to(missing_target)
        for destination in (existing, link, dangling):
            with self.subTest(destination=destination.name), self.assertRaises(ValueError):
                convert_console_module(self.source, destination)
        self.assertEqual(existing.read_bytes(), b'KEEP')
        self.assertTrue(link.is_symlink())
        self.assertTrue(dangling.is_symlink())
        self.assertFalse(missing_target.exists())
        self.assertFalse(list(self.root.glob('.console-*')))

    def test_source_cannot_be_replaced(self):
        from gamedecomp.console_formats import convert_console_module
        data = nro_fixture()
        self.source.write_bytes(data)
        with self.assertRaises(ValueError):
            convert_console_module(self.source, self.source)
        self.assertEqual(self.source.read_bytes(), data)
