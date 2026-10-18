"""Bounded, credential-free Studio checkpoints and artifact integrity."""
import json
import tempfile
import unittest
from pathlib import Path


class SessionStoreTests(unittest.TestCase):
    def test_checkpoint_is_allowlisted_and_crashed_work_is_interrupted(self):
        from gamedecomp.session_store import SessionStore
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'jobs').mkdir()
            job_id = 'a' * 32
            (root / 'jobs' / job_id).mkdir()
            store = SessionStore(root)
            job = {'id': job_id, 'kind': 'analyze', 'status': 'RUNNING',
                   'created_at': '2026-10-17T00:00:00+00:00',
                   'updated_at': '2026-10-17T00:00:00+00:00',
                   'logs': ['secret'], 'options': {'key': 'secret'}, 'error': 'secret'}
            store.checkpoint(job)
            data = (root / 'jobs' / job_id / 'session.json').read_text()
            self.assertNotIn('secret', data)
            jobs, skipped = store.restore()
            self.assertEqual(skipped, 0)
            self.assertEqual(jobs[0]['status'], 'FAILED')
            self.assertEqual(jobs[0]['phase'], 'Interrupted')
            self.assertTrue(jobs[0]['restored'])

    def test_success_requires_bound_result_and_full_artifact_inventory(self):
        from gamedecomp.session_store import SessionStore
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            directory = root / 'jobs' / ('b' * 32)
            (directory / 'results').mkdir(parents=True)
            (directory / 'result.json').write_text('{"summary":{"functions":2},"report":true}')
            report = directory / 'results' / 'report.json'
            report.write_text('{"functions":[]}')
            store = SessionStore(root)
            job = {'id': 'b' * 32, 'kind': 'analyze', 'status': 'SUCCEEDED',
                   'created_at': '2026-10-17T00:00:00+00:00',
                   'updated_at': '2026-10-17T00:00:00+00:00'}
            seal = store.seal(job)
            store.checkpoint(job, seal)
            jobs, skipped = store.restore()
            self.assertEqual(skipped, 0)
            self.assertEqual(jobs[0]['result']['summary']['functions'], 2)
            report.write_text('{"changed":true}')
            with self.assertRaises(ValueError):
                store.verify(job, seal)
            jobs, _ = store.restore()
            self.assertEqual(jobs[0]['status'], 'FAILED')
            self.assertNotIn('result', jobs[0])

    def test_workspace_lock_is_exclusive_and_releases(self):
        from gamedecomp.session_store import WorkspaceLock
        with tempfile.TemporaryDirectory() as tmp:
            first = WorkspaceLock(Path(tmp))
            try:
                with self.assertRaises(RuntimeError):
                    WorkspaceLock(Path(tmp))
            finally:
                first.close()
                first.close()
            WorkspaceLock(Path(tmp)).close()

    def test_invalid_manifest_and_symlink_are_ignored(self):
        from gamedecomp.session_store import SessionStore
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            directory = root / 'jobs' / ('c' * 32)
            directory.mkdir(parents=True)
            (directory / 'session.json').write_text('{broken')
            outside = root / 'outside'
            outside.mkdir()
            (root / 'jobs' / ('d' * 32)).symlink_to(outside, target_is_directory=True)
            jobs, skipped = SessionStore(root).restore()
            self.assertEqual(jobs, [])
            self.assertEqual(skipped, 2)

    def test_checkpoint_never_replaces_a_symlink(self):
        from gamedecomp.session_store import SessionStore
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            directory = root / 'jobs' / ('e' * 32)
            directory.mkdir(parents=True)
            target = root / 'target'
            target.write_text('keep')
            (directory / 'session.json').symlink_to(target)
            with self.assertRaises(ValueError):
                SessionStore(root).checkpoint({'id': 'e' * 32, 'kind': 'demo', 'status': 'QUEUED',
                    'created_at': '2026-10-17T00:00:00+00:00', 'updated_at': '2026-10-17T00:00:00+00:00'})
            self.assertEqual(target.read_text(), 'keep')

    def test_inventory_detects_added_files_and_refuses_symlinks(self):
        from gamedecomp.session_store import SessionStore
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            directory = root / 'jobs' / ('f' * 32)
            (directory / 'results').mkdir(parents=True)
            (directory / 'result.json').write_text('{"summary":{}}')
            (directory / 'results' / 'report.json').write_text('{}')
            job = {'id': 'f' * 32, 'kind': 'analyze'}
            store = SessionStore(root)
            inventory = store.seal(job)
            (directory / 'results' / 'extra').write_text('new')
            with self.assertRaises(ValueError):
                store.verify(job, inventory)
            (directory / 'results' / 'extra').unlink()
            (directory / 'results' / 'external').symlink_to(root / 'outside')
            with self.assertRaises(ValueError):
                store.seal(job)

    def test_artifact_byte_limit_is_enforced_before_reading(self):
        from gamedecomp.session_store import SessionStore
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            directory = root / 'jobs' / ('f' * 32)
            (directory / 'results').mkdir(parents=True)
            (directory / 'result.json').write_text('{"summary":{}}')
            with (directory / 'results' / 'large').open('wb') as stream:
                stream.truncate(128 * 1024**2 + 1)
            with self.assertRaises(ValueError):
                SessionStore(root).seal({'id': 'f' * 32, 'kind': 'analyze'})

    def test_checkpoint_identity_is_bound_to_its_directory(self):
        from gamedecomp.session_store import SessionStore
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            directory = root / 'jobs' / ('a' * 32)
            directory.mkdir(parents=True)
            stamp = '2026-10-17T00:00:00+00:00'
            (directory / 'session.json').write_text(json.dumps({'id': 'b' * 32, 'version': 1,
                'kind': 'demo', 'status': 'FAILED', 'created_at': stamp, 'updated_at': stamp,
                'payload': {'execute': 'malicious'}}))
            jobs, skipped = SessionStore(root).restore()
            self.assertEqual(jobs, [])
            self.assertEqual(skipped, 1)
