import tempfile
import unittest
from pathlib import Path


class IngestTests(unittest.TestCase):
    def test_identifies_wasm_and_rejects_short_elf(self):
        from gamedecomp.ingest import inspect_binary
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'with spaces.wasm'
            path.write_bytes(b'\0asm\x01\0\0\0')
            info = inspect_binary(path)
            self.assertEqual(info['format'], 'WASM')
            self.assertEqual(info['architecture'], 'wasm32')
            self.assertEqual(len(info['sha256']), 64)
            path.write_bytes(b'\x7fELF')
            with self.assertRaises(ValueError):
                inspect_binary(path)

    def test_identifies_system_elf(self):
        from gamedecomp.ingest import inspect_binary
        info = inspect_binary(Path('/bin/true'))
        self.assertEqual(info['format'], 'ELF')
        self.assertGreater(info['size'], 0)


class StoreTests(unittest.TestCase):
    def test_cache_roundtrip_and_distinct_configurations(self):
        from gamedecomp.store import ArtifactStore, cache_key
        with tempfile.TemporaryDirectory() as directory:
            with ArtifactStore(Path(directory) / 'cache.sqlite') as store:
                a = cache_key({'binary': 'a', 'backend': 'native'})
                b = cache_key({'binary': 'a', 'backend': 'ghidra'})
                self.assertNotEqual(a, b)
                store.put(a, {'value': 7})
                self.assertEqual(store.get(a), {'value': 7})
                self.assertIsNone(store.get(b))
                store.record('job', 'VALIDATED', {'status': 'TESTED'})
                self.assertEqual(store.events('job')[0]['payload']['status'], 'TESTED')

    def test_store_reopens_and_reports_corruption(self):
        from gamedecomp.store import ArtifactStore
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'cache.sqlite'
            with ArtifactStore(path) as store:
                store.put('key', {'ok': True})
            with ArtifactStore(path) as store:
                self.assertEqual(store.get('key'), {'ok': True})
