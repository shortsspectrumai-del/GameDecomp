import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import http.client
import io
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch


class CatalogProtocolTests(unittest.TestCase):
    def test_api_protocol_is_explicit_and_rejects_preset_mismatches(self):
        from gamedecomp import model_catalog
        self.assertEqual(model_catalog.resolve_api_format({'provider': 'anthropic'}), 'anthropic')
        self.assertEqual(model_catalog.resolve_api_format({'provider': 'deepseek'}), 'openai')
        self.assertEqual(model_catalog.resolve_api_format({'provider': 'custom'}), 'openai')
        self.assertEqual(model_catalog.resolve_api_format({'provider': 'custom', 'api_format': 'anthropic'}), 'anthropic')
        for value in ({'provider': 'anthropic', 'api_format': 'openai'},
                      {'provider': 'deepseek', 'api_format': 'anthropic'},
                      {'provider': 'custom', 'api_format': 'unknown'},
                      {'provider': 'custom', 'api_format': []}):
            with self.subTest(value=value), self.assertRaises(ValueError):
                model_catalog.resolve_api_format(value)

    def test_native_catalog_maps_limits_and_reports_incomplete_page(self):
        from gamedecomp.model_catalog import fetch_models
        seen = []
        class Provider(BaseHTTPRequestHandler):
            def do_GET(self):
                seen.append((self.path, self.headers.get('X-Api-Key'),
                             self.headers.get('anthropic-version'), self.headers.get('Authorization')))
                raw = json.dumps({'data': [
                    {'id': 'claude-test', 'max_input_tokens': 200000, 'max_tokens': 32000},
                    {'id': 'unknown-limits', 'max_input_tokens': True, 'max_tokens': -1},
                    {'id': 'secret-native-test'}, {'id': 'claude-test'}], 'has_more': True}).encode()
                self.send_response(200); self.send_header('Content-Length', str(len(raw)))
                self.end_headers(); self.wfile.write(raw)
            def log_message(self, *args): pass
        provider = ThreadingHTTPServer(('127.0.0.1', 0), Provider)
        thread = threading.Thread(target=provider.serve_forever, daemon=True); thread.start()
        try:
            result = fetch_models({'provider': 'custom', 'api_format': 'anthropic',
                                   'url': f'http://127.0.0.1:{provider.server_port}/v1/messages',
                                   'key': 'secret-native-test'})
            self.assertEqual(result['status'], 'AVAILABLE')
            self.assertEqual(result['models'], [
                {'id': 'claude-test', 'context_window': 200000, 'max_output_tokens': 32000},
                {'id': 'unknown-limits'}])
            self.assertTrue(result['truncated'])
            self.assertEqual(seen, [('/v1/models', 'secret-native-test', '2023-06-01', None)])
            self.assertNotIn('secret-native-test', json.dumps(result))
        finally:
            provider.shutdown(); provider.server_close(); thread.join(3)

    def test_anthropic_preset_requires_key_and_preserves_connection_tuple(self):
        from gamedecomp.model_catalog import resolve_connection
        from gamedecomp.cli import LLM_PROVIDERS
        with patch.dict(LLM_PROVIDERS, {'anthropic': ('https://api.anthropic.com/v1', 'ANTHROPIC_API_KEY')}), patch.dict('os.environ', {}, clear=True):
            with self.assertRaisesRegex(ValueError, 'key'):
                resolve_connection({'provider': 'anthropic'})
            endpoint, key = resolve_connection({'provider': 'anthropic', 'key': 'native-test-key'})
            self.assertEqual(endpoint, 'https://api.anthropic.com/v1/messages')
            self.assertEqual(key, 'native-test-key')

    def test_catalog_bounds_model_count_and_response_size(self):
        from gamedecomp.model_catalog import fetch_models
        value = {'provider': 'custom', 'api_format': 'anthropic',
                 'url': 'http://127.0.0.1:1/v1'}
        raw = json.dumps({'data': [{'id': f'model-{index}'} for index in range(129)],
                          'has_more': False}).encode()
        with patch('gamedecomp.model_catalog.urllib.request.build_opener') as opener:
            opener.return_value.open.return_value = io.BytesIO(raw)
            result = fetch_models(value)
        self.assertEqual(result['status'], 'AVAILABLE')
        self.assertEqual(len(result['models']), 128)
        self.assertTrue(result['truncated'])
        with patch('gamedecomp.model_catalog.urllib.request.build_opener') as opener:
            opener.return_value.open.return_value = io.BytesIO(b' ' * 1048577)
            result = fetch_models(value)
        self.assertEqual(result['status'], 'UNAVAILABLE')
        self.assertEqual(result['models'], [])

    def test_native_custom_endpoint_can_use_an_unauthenticated_local_gateway(self):
        from gamedecomp.model_catalog import resolve_connection
        with patch.dict('os.environ', {}, clear=True):
            endpoint, key = resolve_connection({'provider': 'custom', 'api_format': 'anthropic',
                                                'url': 'http://127.0.0.1:8080/v1'})
        self.assertEqual(endpoint, 'http://127.0.0.1:8080/v1/messages')
        self.assertIsNone(key)


class ModelCatalogTests(unittest.TestCase):
    def setUp(self):
        from gamedecomp.web import create_server
        self.directory = tempfile.TemporaryDirectory()
        self.server = create_server(Path(self.directory.name), port=0)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.token = self.request('GET', '/api/bootstrap')[1]['token']

    def tearDown(self):
        self.server.shutdown(); self.server.server_close(); self.thread.join(3)
        self.directory.cleanup()

    def request(self, method, path, value=None):
        connection = http.client.HTTPConnection('127.0.0.1', self.server.server_port, timeout=10)
        headers = {'X-GameDecomp-Token': getattr(self, 'token', ''), 'Content-Type': 'application/json'}
        connection.request(method, path, json.dumps(value) if value is not None else None, headers)
        response = connection.getresponse(); body = response.read(); status = response.status
        connection.close()
        return status, json.loads(body)

    def test_local_models_are_discovered_without_inference_or_saved_credentials(self):
        seen = []; secret = 'catalog-test-private-key'
        class Provider(BaseHTTPRequestHandler):
            def do_GET(self):
                seen.append((self.path, self.headers.get('Authorization')))
                raw = json.dumps({'data': [{'id': 'local-code', 'context_window': 32768},
                                          {'id': secret}, {'id': 'local-code'}, {'id': 12}]}).encode()
                self.send_response(200); self.send_header('Content-Length', str(len(raw)))
                self.end_headers(); self.wfile.write(raw)
            def log_message(self, *args): pass
        provider = ThreadingHTTPServer(('127.0.0.1', 0), Provider)
        thread = threading.Thread(target=provider.serve_forever, daemon=True); thread.start()
        try:
            status, result = self.request('POST', '/api/llm/models', {
                'provider': 'ollama', 'url': f'http://127.0.0.1:{provider.server_port}/v1', 'key': secret})
            self.assertEqual(status, 200)
            self.assertEqual(result['status'], 'AVAILABLE')
            self.assertEqual(result['location'], 'LOCAL')
            self.assertEqual(result['models'], [{'id': 'local-code', 'context_window': 32768}])
            self.assertEqual(seen, [('/v1/models', 'Bearer ' + secret)])
            self.assertNotIn(secret, json.dumps(result))
            self.assertEqual(self.request('GET', '/api/jobs')[1]['jobs'], [])
            for file in Path(self.directory.name).rglob('*'):
                if file.is_file(): self.assertNotIn(secret.encode(), file.read_bytes())
        finally:
            provider.shutdown(); provider.server_close(); thread.join(3)

    def test_local_preset_rejects_remote_endpoints(self):
        status, result = self.request('POST', '/api/llm/models', {
            'provider': 'lmstudio', 'url': 'https://example.invalid/v1'})
        self.assertEqual(status, 400)
        self.assertIn('loopback', result['error'])

    def test_failed_connection_has_no_reflected_credentials(self):
        status, result = self.request('POST', '/api/llm/models', {
            'provider': 'custom', 'url': 'http://127.0.0.1:1/v1', 'key': 'never-reflect-this'})
        self.assertEqual(status, 200)
        self.assertEqual(result['status'], 'UNAVAILABLE')
        self.assertEqual(result['models'], [])
        self.assertNotIn('never-reflect-this', json.dumps(result))

    def test_bootstrap_has_local_presets(self):
        providers = {p['id']: p for p in self.request('GET', '/api/bootstrap')[1]['providers']}
        self.assertIn('lmstudio', providers)
        self.assertEqual(providers['lmstudio']['url'], 'http://127.0.0.1:1234/v1')
