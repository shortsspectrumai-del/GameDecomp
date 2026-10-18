"""Local Studio API integration: no uploaded binary is executed."""
import http.client
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch
from pathlib import Path

from tests.test_wasm import wasm_fixture


class ProcessCleanupTests(unittest.TestCase):
    def test_anthropic_configuration_survives_preflight_and_private_worker_payload(self):
        from gamedecomp.web import _Manager
        from gamedecomp import model_catalog
        with tempfile.TemporaryDirectory() as directory:
            manager = _Manager(Path(directory))
            path = Path(directory) / 'test.wasm'
            path.write_bytes(wasm_fixture())
            manager.files['fixture'] = {'kind': 'binary', 'path': str(path), 'info': {'format': 'WASM'}}
            try:
                with patch('gamedecomp.llm.LLMClient') as client, patch.object(model_catalog, 'LLMClient', client):
                    client.return_value.endpoint = 'https://api.anthropic.com/v1/messages'
                    payload = manager.validate({'kind': 'analyze', 'file_id': 'fixture', 'options': {'llm': {
                        'provider': 'anthropic', 'model': 'claude-test', 'key': 'private-test-key'}}})
                self.assertEqual(payload['options']['llm']['api_format'], 'anthropic')
                self.assertEqual(payload['options']['llm']['url'], 'https://api.anthropic.com/v1/messages')
                self.assertEqual(client.call_args.kwargs['api_format'], 'anthropic')
                self.assertEqual(client.call_args.kwargs['api_key'], 'private-test-key')
            finally:
                manager.close()

    def test_queue_is_bounded_and_queued_jobs_cancel_cleanly(self):
        from gamedecomp.web import _Manager
        with tempfile.TemporaryDirectory() as directory:
            manager = _Manager(Path(directory))
            manager.slots.acquire()
            manager.slots.acquire()
            try:
                jobs = [manager.submit({'kind': 'demo'}) for _ in range(18)]
                with self.assertRaises(OverflowError):
                    manager.submit({'kind': 'demo'})
                for job in jobs:
                    self.assertEqual(manager.cancel(job['id'])['status'], 'CANCELLED')
            finally:
                manager.close()
                manager.slots.release()
                manager.slots.release()

    @unittest.skipUnless(sys.platform.startswith('linux'), 'Linux descendant discovery')
    def test_cancellation_kills_frontends_in_separate_sessions(self):
        from gamedecomp.web import _kill
        code = ('import subprocess,sys,time; '
                'child=subprocess.Popen([sys.executable,"-c","import time;time.sleep(60)"],start_new_session=True); '
                'print(child.pid,flush=True);time.sleep(60)')
        process = subprocess.Popen([sys.executable, '-c', code], stdout=subprocess.PIPE, start_new_session=True)
        child_pid = int(process.stdout.readline())
        try:
            _kill(process)
            process.wait(timeout=5)
            deadline = time.monotonic() + 3
            while time.monotonic() < deadline:
                stat = Path(f'/proc/{child_pid}/stat')
                if not stat.exists() or stat.read_text().rsplit(')', 1)[1].split()[0] == 'Z':
                    break
                time.sleep(.02)
            else:
                self.fail('Frontend descendant is still running')
        finally:
            _kill(process)
            process.stdout.close()
            try:
                os.kill(child_pid, 9)
            except ProcessLookupError:
                pass


class StudioTests(unittest.TestCase):
    def setUp(self):
        from gamedecomp.web import create_server
        self.directory = tempfile.TemporaryDirectory()
        self.server = create_server(Path(self.directory.name), port=0)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.port = self.server.server_address[1]
        self.token = self.request('GET', '/api/bootstrap')[1]['token']

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(3)
        self.directory.cleanup()

    def request(self, method, path, body=None, headers=None):
        connection = http.client.HTTPConnection('127.0.0.1', self.port, timeout=10)
        values = dict(headers or {})
        if method == 'POST':
            values.setdefault('X-GameDecomp-Token', getattr(self, 'token', ''))
        if isinstance(body, dict):
            body = json.dumps(body)
            values['Content-Type'] = 'application/json'
        connection.request(method, path, body, values)
        response = connection.getresponse()
        raw = response.read()
        content_type = response.getheader('Content-Type', '')
        status = response.status
        connection.close()
        return status, json.loads(raw) if 'json' in content_type else raw

    def wait(self, job):
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            status, result = self.request('GET', '/api/jobs/' + job['id'])
            self.assertEqual(status, 200)
            if result['job']['status'] in ('SUCCEEDED', 'FAILED', 'CANCELLED'):
                return result['job']
            time.sleep(.05)
        self.fail('Studio job did not complete')

    def test_security_boundaries(self):
        self.assertEqual(self.request('GET', '/api/jobs', headers={'Host': 'attacker.invalid'})[0], 403)
        self.assertEqual(self.request('POST', '/api/jobs', {}, {'X-GameDecomp-Token': 'wrong'})[0], 403)
        self.assertEqual(self.request('POST', '/api/jobs', {}, {'Origin': 'https://attacker.invalid'})[0], 403)
        self.assertEqual(self.request('GET', '/../../etc/passwd')[0], 404)
        self.assertEqual(self.request('POST', '/api/upload?name=../bad&kind=binary', wasm_fixture())[0], 400)
        self.assertEqual(self.request('POST', '/api/jobs', {'kind': 'analyze', 'file_id': '/etc/passwd'})[0], 400)

    def test_upload_real_wasm_job_and_export(self):
        status, upload = self.request('POST', '/api/upload?name=sample.wasm&kind=binary', wasm_fixture())
        self.assertEqual(status, 201)
        self.assertEqual(upload['info']['format'], 'WASM')
        self.assertNotIn('path', upload['info'])
        status, result = self.request('POST', '/api/jobs', {'kind': 'analyze', 'file_id': upload['file_id'],
            'options': {'backend': 'wasm', 'workers': 2, 'timeout': 30, 'gnn_model': None}})
        self.assertEqual(status, 202)
        job = self.wait(result['job'])
        self.assertEqual(job['status'], 'SUCCEEDED', job)
        self.assertEqual(job['phase'], 'Completed')
        progress = job['progress']
        self.assertEqual(progress['stage'], 'COMPLETE')
        self.assertEqual((progress['total_units'], progress['processed_units'], progress['compiled_units']), (1, 1, 1))
        self.assertEqual((progress['tested_units'], progress['rejected_units'], progress['unknown_units']), (0, 0, 1))
        status, report = self.request('GET', job['report_url'])
        self.assertEqual(status, 200)
        self.assertEqual(report['summary']['recovered'], 1)
        evidence_url = '/api/jobs/' + job['id'] + '/evidence'
        status, page = self.request('GET', evidence_url + '?offset=0&limit=1')
        self.assertEqual(status, 200)
        self.assertEqual(page['returned_units'], 1)
        self.assertEqual(page['binary_sha256'], report['input']['sha256'])
        self.assertEqual(page['snapshot_id'], report['snapshot_id'])
        self.assertEqual(self.request('GET', evidence_url + '?limit=129')[0], 400)
        self.assertEqual(self.request('GET', evidence_url + '?limit=1&limit=2')[0], 400)
        self.assertIn('readiness', self.request('GET', '/api/bootstrap')[1])
        self.assertEqual(self.request('GET', job['report_url'] + '.html')[0], 200)
        status, archive = self.request('GET', job['export_url'])
        self.assertEqual(status, 200)
        self.assertTrue(archive.startswith(b'PK'))

    def test_console_upload_and_profile_validation_before_dispatch(self):
        from tests.test_console_formats import nso_fixture
        from tests.test_retro_formats import dol_fixture
        status, upload = self.request('POST', '/api/upload?name=module.nso&kind=binary', bytes(nso_fixture()))
        self.assertEqual(status, 201)
        self.assertEqual(upload['info']['required_profile'], 'switch-aarch64')
        request = {'kind': 'analyze', 'file_id': upload['file_id']}
        for options in ({}, {'console_profile': 'gba-arm'},
                        {'console_profile': 'switch-aarch64', 'backend': 'native'}):
            self.assertEqual(self.request('POST', '/api/jobs', dict(request, options=options))[0], 400)
        validated = self.server.manager.validate(dict(request, options={'console_profile': 'switch-aarch64'}))
        self.assertEqual(validated['options']['console_profile'], 'switch-aarch64')
        self.assertEqual(self.server.manager.jobs, {})
        self.assertEqual(self.request('POST', '/api/upload?name=game.dol&kind=binary', bytes(dol_fixture()))[0], 400)
        status, dol = self.request('POST', '/api/upload?name=game.dol&kind=binary&profile=dol-ppc', bytes(dol_fixture()))
        self.assertEqual(status, 201)
        self.assertEqual(dol['info']['format'], 'DOL')
        self.assertEqual(self.request('POST', '/api/upload?name=game&kind=binary&profile=invalid', bytes(dol_fixture()))[0], 400)

    def test_custom_gnn_model_upload_is_used_by_analysis(self):
        from tests.test_gnn import hand_model
        model_status, model = self.request('POST', '/api/upload?name=model.json&kind=model', json.dumps(hand_model()).encode())
        self.assertEqual(model_status, 201)
        upload = self.request('POST', '/api/upload?name=sample.wasm&kind=binary', wasm_fixture())[1]
        status, result = self.request('POST', '/api/jobs', {'kind': 'analyze', 'file_id': upload['file_id'],
            'options': {'model_file_id': model['file_id'], 'timeout': 30}})
        self.assertEqual(status, 202)
        job = self.wait(result['job'])
        self.assertEqual(job['status'], 'SUCCEEDED', job)
        report = self.request('GET', job['report_url'])[1]
        self.assertEqual(report['gnn']['model_hash'], model['info']['sha256'])
        self.assertTrue(report['gnn']['predictions'])

    @unittest.skipUnless(importlib.util.find_spec('torch'), 'Optional PyTorch unavailable')
    def test_dataset_upload_training_and_model_export(self):
        from tests.test_gnn import TrainingTests
        dataset = json.dumps(TrainingTests().dataset()).encode()
        status, upload = self.request('POST', '/api/upload?name=dataset.json&kind=dataset', dataset)
        self.assertEqual(status, 201)
        status, result = self.request('POST', '/api/jobs', {'kind': 'train_gnn', 'file_id': upload['file_id'],
            'epochs': 2, 'seed': 17, 'options': {'timeout': 60}})
        self.assertEqual(status, 202)
        job = self.wait(result['job'])
        self.assertEqual(job['status'], 'SUCCEEDED', job)
        metrics = self.request('GET', job['report_url'])[1]
        self.assertEqual(metrics['training']['epochs'], 2)
        self.assertEqual(metrics['test_evaluations'], 1)
        import io
        import zipfile
        archive = self.request('GET', job['export_url'])[1]
        with zipfile.ZipFile(io.BytesIO(archive)) as exported:
            self.assertEqual(set(exported.namelist()), {'model.json', 'metrics.json'})

    def test_invalid_upload_and_options_do_not_leak_key(self):
        self.assertEqual(self.request('POST', '/api/upload?name=x.json&kind=model', b'{"oops":1}')[0], 400)
        self.assertEqual(self.request('POST', '/api/upload?name=x&kind=binary', b'bad')[0], 400)
        status, result = self.request('POST', '/api/jobs', {'kind': 'demo', 'options': {
            'llm': {'provider': 'custom', 'model': 'example', 'url': 'invalid', 'key': 'secret-test-key'}}})
        self.assertEqual(status, 400)
        self.assertNotIn('secret-test-key', json.dumps(result))
        self.assertNotIn('secret-test-key', json.dumps(self.request('GET', '/api/jobs')[1]))

    def test_cancel_has_terminal_state(self):
        status, result = self.request('POST', '/api/jobs', {'kind': 'gnn_demo', 'samples': 64, 'epochs': 1000})
        self.assertEqual(status, 202)
        job_id = result['job']['id']
        self.assertEqual(self.request('POST', '/api/jobs/' + job_id + '/cancel', {})[0], 200)
        job = self.wait({'id': job_id})
        self.assertEqual(job['status'], 'CANCELLED')

    def test_api_key_is_only_in_transport_and_echo_is_redacted(self):
        key = 'studio-ephemeral-secret-112233'
        requests = []
        bodies = []
        class Provider(BaseHTTPRequestHandler):
            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
                requests.append(self.headers.get('Authorization'))
                bodies.append(body)
                context = json.loads(body['messages'][1]['content'])
                result = {'source': context['source'] + '\n/* ' + key + ' */',
                          'evidence_ids': [context['context']['evidence'][0]['id']], 'assumptions': []}
                raw = json.dumps({'choices': [{'message': {'content': json.dumps(result)}}]}).encode()
                self.send_response(200)
                self.send_header('Content-Length', str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)
            def log_message(self, *args):
                pass
        provider = ThreadingHTTPServer(('127.0.0.1', 0), Provider)
        thread = threading.Thread(target=provider.serve_forever, daemon=True)
        thread.start()
        try:
            upload = self.request('POST', '/api/upload?name=sample.wasm&kind=binary', wasm_fixture())[1]
            with patch('gamedecomp.web.subprocess.Popen', wraps=subprocess.Popen) as spawn:
                status, result = self.request('POST', '/api/jobs', {'kind': 'analyze', 'file_id': upload['file_id'],
                    'options': {'backend': 'wasm', 'timeout': 30, 'llm': {'provider': 'custom', 'model': 'fixture',
                    'url': f'http://127.0.0.1:{provider.server_port}/v1', 'key': key,
                    'json_mode': 'prompt', 'temperature': 0.25}}})
                self.assertEqual(status, 202)
                job = self.wait(result['job'])
                self.assertEqual(job['status'], 'SUCCEEDED', job)
                self.assertNotIn(key, repr(spawn.call_args))
            self.assertTrue(requests)
            self.assertEqual(requests[0], 'Bearer ' + key)
            self.assertNotIn('response_format', bodies[0])
            self.assertEqual(bodies[0]['temperature'], 0.25)
            self.assertNotIn(key, json.dumps(self.request('GET', '/api/jobs')[1]))
            report = self.request('GET', job['report_url'])[1]
            self.assertNotIn(key, json.dumps(report))
            self.assertIn('[REDACTED]', json.dumps(report))
            for file in Path(self.directory.name).rglob('*'):
                if file.is_file():
                    self.assertNotIn(key.encode(), file.read_bytes(), str(file))
        finally:
            provider.shutdown()
            provider.server_close()
            thread.join(3)

    def test_invalid_llm_transport_options_are_rejected_before_dispatch(self):
        upload = self.request('POST', '/api/upload?name=sample.wasm&kind=binary', wasm_fixture())[1]
        for values in ({'json_mode': 'arbitrary'}, {'temperature': True}, {'temperature': -1},
                       {'temperature': 3}, {'temperature': '0.5'}, {'api_format': 'invalid'},
                       {'api_format': 'anthropic', 'reasoning_effort': 'high'},
                       {'api_format': 'anthropic', 'temperature': 1.1}):
            with self.subTest(values=values):
                status, _ = self.request('POST', '/api/jobs', {'kind': 'analyze', 'file_id': upload['file_id'],
                    'options': {'llm': dict(provider='custom', model='fixture', url='http://127.0.0.1:9/v1', **values)}})
                self.assertEqual(status, 400)
        self.assertEqual(self.request('GET', '/api/jobs')[1]['jobs'], [])

    def test_native_anthropic_loopback_job_propagates_protocol_and_redacts_echo(self):
        key = 'studio-anthropic-private-fixture'
        requests = []
        class Provider(BaseHTTPRequestHandler):
            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
                requests.append((self.path, {name.lower(): value for name, value in self.headers.items()}, body))
                context = json.loads(body['messages'][0]['content'])
                result = {'source': context['source'] + '\n/* ' + key + ' */',
                          'evidence_ids': [context['context']['evidence'][0]['id']], 'assumptions': []}
                raw = json.dumps({'type': 'message', 'role': 'assistant',
                    'content': [{'type': 'text', 'text': json.dumps(result)}],
                    'stop_reason': 'end_turn', 'usage': {'input_tokens': 30, 'output_tokens': 20}}).encode()
                self.send_response(200)
                self.send_header('Content-Length', str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)
            def log_message(self, *args):
                pass
        provider = ThreadingHTTPServer(('127.0.0.1', 0), Provider)
        thread = threading.Thread(target=provider.serve_forever, daemon=True)
        thread.start()
        try:
            upload = self.request('POST', '/api/upload?name=sample.wasm&kind=binary', wasm_fixture())[1]
            status, result = self.request('POST', '/api/jobs', {'kind': 'analyze', 'file_id': upload['file_id'],
                'options': {'backend': 'wasm', 'timeout': 30, 'llm': {'provider': 'custom', 'model': 'fixture',
                'api_format': 'anthropic', 'url': f'http://127.0.0.1:{provider.server_port}/v1', 'key': key,
                'json_mode': 'prompt'}}})
            self.assertEqual(status, 202, result)
            job = self.wait(result['job'])
            self.assertEqual(job['status'], 'SUCCEEDED', job)
            self.assertTrue(requests)
            path, headers, body = requests[0]
            self.assertEqual(path, '/v1/messages')
            self.assertEqual(headers.get('x-api-key'), key)
            self.assertNotIn('authorization', headers)
            self.assertIn('system', body)
            self.assertNotIn('reasoning_effort', body)
            self.assertNotIn('response_format', body)
            report = self.request('GET', job['report_url'])[1]
            self.assertIn('[REDACTED]', json.dumps(report))
            self.assertNotIn(key, json.dumps(report))
            self.assertNotIn(key, json.dumps(self.request('GET', '/api/jobs')[1]))
            for file in Path(self.directory.name).rglob('*'):
                if file.is_file():
                    self.assertNotIn(key.encode(), file.read_bytes(), str(file))
        finally:
            provider.shutdown()
            provider.server_close()
            thread.join(3)

    def test_symlink_workspace_and_remote_binding_rejected(self):
        from gamedecomp.web import create_server
        with self.assertRaises(ValueError):
            create_server(Path(self.directory.name), host='0.0.0.0', port=0)
        alias = Path(self.directory.name) / 'alias'
        alias.symlink_to(Path(self.directory.name), target_is_directory=True)
        with self.assertRaises(ValueError):
            create_server(alias, port=0)

    def test_occupied_port_preserves_os_error(self):
        from gamedecomp.web import create_server
        with self.assertRaises(OSError):
            create_server(Path(self.directory.name) / 'other', port=self.port)

    def test_upload_and_artifacts_reject_internal_symlinks(self):
        status, upload = self.request('POST', '/api/upload?name=x.wasm&kind=binary', wasm_fixture())
        self.assertEqual(status, 201)
        path = next((Path(self.directory.name) / 'uploads').iterdir())
        outside = Path(self.directory.name) / 'not-an-upload'
        outside.write_bytes(wasm_fixture())
        path.unlink()
        path.symlink_to(outside)
        self.assertEqual(self.request('POST', '/api/jobs', {'kind': 'analyze', 'file_id': upload['file_id']})[0], 400)
