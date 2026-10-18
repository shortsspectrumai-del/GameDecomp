"""Studio history survives a restart without resuming programs or API calls."""
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from gamedecomp.web import _Manager


class HistoryIntegrationTests(unittest.TestCase):
    def test_restores_success_and_detects_changed_artifacts_on_demand(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manager = _Manager(root)
            job_id = 'a' * 32
            directory = root / 'jobs' / job_id
            (directory / 'results').mkdir(parents=True)
            (directory / 'result.json').write_text('{"summary":{"functions":1},"report":true}')
            report = directory / 'results' / 'report.json'
            report.write_text('{"functions":[]}')
            stamp = '2026-10-17T00:00:00+00:00'
            manager.jobs[job_id] = {'id': job_id, 'kind': 'analyze', 'status': 'RUNNING',
                'created_at': stamp, 'updated_at': stamp, 'logs': []}
            import threading
            manager.internal[job_id] = {'directory': directory, 'cancel': threading.Event(),
                                        'process': None, 'thread': None}
            manager.update(job_id, status='SUCCEEDED', phase='Completed', result={'summary': {'functions': 1}})
            manager.close()
            restored = _Manager(root)
            try:
                self.assertEqual(restored.snapshot(job_id)['status'], 'SUCCEEDED')
                self.assertTrue(restored.snapshot(job_id)['restored'])
                self.assertEqual(restored.artifact(job_id).read_text(), '{"functions":[]}')
                report.write_text('{"functions":[1]}')
                with self.assertRaises(ValueError):
                    restored.archive(job_id)
                with self.assertRaises(ValueError):
                    restored.artifact(job_id)
            finally:
                restored.close()

    def test_second_manager_fails_before_recovery_and_close_is_idempotent(self):
        with tempfile.TemporaryDirectory() as tmp:
            first = _Manager(Path(tmp))
            try:
                with self.assertRaises(RuntimeError):
                    _Manager(Path(tmp))
            finally:
                first.close()
                first.close()
            _Manager(Path(tmp)).close()

    def test_interrupted_checkpoint_is_failed_without_execution(self):
        from gamedecomp.session_store import SessionStore
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            directory = root / 'jobs' / ('b' * 32)
            directory.mkdir(parents=True)
            stamp = '2026-10-17T00:00:00+00:00'
            SessionStore(root).checkpoint({'id': 'b' * 32, 'kind': 'demo', 'status': 'RUNNING',
                'created_at': stamp, 'updated_at': stamp})
            manager = _Manager(root)
            try:
                job = manager.snapshot('b' * 32)
                self.assertEqual(job['status'], 'FAILED')
                self.assertEqual(job['phase'], 'Interrupted')
                self.assertIsNone(manager.internal['b' * 32]['thread'])
                self.assertEqual(manager.files, {})
            finally:
                manager.close()

    def test_bind_failure_releases_the_workspace_lock(self):
        from gamedecomp.web import create_server
        with tempfile.TemporaryDirectory() as tmp:
            with patch('gamedecomp.web._Server', side_effect=OSError('address in use')):
                with self.assertRaises(OSError):
                    create_server(Path(tmp), port=0)
            _Manager(Path(tmp)).close()

    def test_checkpoint_write_failure_does_not_start_a_queued_worker(self):
        with tempfile.TemporaryDirectory() as tmp:
            manager = _Manager(Path(tmp))
            try:
                with patch.object(manager.store, 'checkpoint', side_effect=OSError('disk full')):
                    job = manager.submit({'kind': 'demo'})
                self.assertEqual(job['status'], 'FAILED')
                self.assertIn('history_warning', job)
                self.assertIsNone(manager.internal[job['id']]['thread'])
                self.assertTrue(manager.history['warning'])
            finally:
                manager.close()

    def test_translation_requires_verified_analysis_and_provider(self):
        with tempfile.TemporaryDirectory() as tmp:
            manager = _Manager(Path(tmp))
            try:
                request = {'kind': 'translate', 'source_job_id': 'a' * 32, 'function_id': 'f',
                    'target_language': 'java', 'source_kind': 'baseline', 'options': {}}
                manager.jobs['a' * 32] = {'id': 'a' * 32, 'kind': 'analyze', 'status': 'SUCCEEDED'}
                with self.assertRaisesRegex(ValueError, 'LLM provider'):
                    manager.validate(request)
                request['target_language'] = 'shell'
                with self.assertRaisesRegex(ValueError, 'target or source'):
                    manager.validate(request)
                request['target_language'] = 'java'
                manager.jobs['a' * 32]['status'] = 'RUNNING'
                with self.assertRaisesRegex(ValueError, 'completed analysis'):
                    manager.validate(request)
            finally:
                manager.jobs.clear()
                manager.close()

    def test_translation_payload_preserves_origin_identity(self):
        with tempfile.TemporaryDirectory() as tmp:
            manager = _Manager(Path(tmp))
            try:
                source_id = 'a' * 32
                manager.jobs[source_id] = {'id': source_id, 'kind': 'analyze', 'status': 'SUCCEEDED'}
                request = {'kind': 'translate', 'source_job_id': source_id, 'function_id': '401000',
                    'target_language': 'cpp', 'source_kind': 'baseline', 'options': {
                        'llm': {'provider': 'ollama', 'model': 'test-model'}}}
                report = Path(tmp) / 'report.json'
                with patch.object(manager, 'artifact', return_value=report):
                    payload = manager.validate(request)
                self.assertEqual(payload['source_job_id'], source_id)
                self.assertEqual(payload['source'], str(report))
                self.assertEqual(payload['function_id'], '401000')
            finally:
                manager.jobs.clear()
                manager.close()
