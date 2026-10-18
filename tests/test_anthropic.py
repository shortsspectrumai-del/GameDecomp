"""Native Messages API contract tested against an isolated local HTTP server."""
import json
import ctypes
import hashlib
from pathlib import Path
import shutil
import subprocess
import tempfile
import threading
import unittest
from unittest.mock import patch
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from gamedecomp.llm import LLMClient, LLMError


class AnthropicTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        class Handler(BaseHTTPRequestHandler):
            def respond(self):
                length = int(self.headers.get('Content-Length', '0'))
                cls.server.requests.append({'path': self.path, 'method': self.command,
                    'headers': {key.lower(): value for key, value in self.headers.items()}, 'body': json.loads(self.rfile.read(length)) if length else None})
                body = cls.server.replies.pop(0) if self.command == 'POST' and cls.server.replies else cls.server.reply
                self.send_response(cls.server.status)
                self.send_header('Content-Type', 'application/json')
                if cls.server.status == 302:
                    self.send_header('Location', '/credential-trap')
                self.end_headers()
                self.wfile.write(json.dumps(body).encode() if not isinstance(body, bytes) else body)
            do_POST = respond
            do_GET = respond
            def log_message(self, *args):
                pass
        cls.server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.url = f'http://127.0.0.1:{cls.server.server_port}/v1'

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown(); cls.server.server_close(); cls.thread.join(3)

    def setUp(self):
        self.server.requests = []; self.server.replies = []; self.server.status = 200
        self.result = {'source': 'int f(void) { return 42; }', 'evidence_ids': ['i:1'], 'assumptions': []}
        self.server.reply = {'type': 'message', 'role': 'assistant', 'stop_reason': 'end_turn',
            'content': [{'type': 'text', 'text': json.dumps(self.result)}],
            'usage': {'input_tokens': 10, 'output_tokens': 5}}

    def client(self, **kwargs):
        return LLMClient(self.url, 'claude-fixture', api_key='private-test-key', api_format='anthropic', **kwargs)

    def test_native_request_and_shared_structured_validation(self):
        client = self.client()
        self.assertEqual(self.server.requests, [])
        result = client.refine('int f(void);', {'evidence_ids': ['i:1']}, ['Preserve ABI'])
        self.assertEqual(result['source'], self.result['source'])
        request = self.server.requests[-1]; body = request['body']
        self.assertEqual(request['path'], '/v1/messages')
        self.assertEqual(request['headers'].get('x-api-key'), 'private-test-key')
        self.assertEqual(request['headers'].get('anthropic-version'), '2023-06-01')
        self.assertNotIn('authorization', request['headers'])
        self.assertIn('immutable compiler ABI', body['system'])
        self.assertEqual([m['role'] for m in body['messages']], ['user'])
        self.assertEqual(json.loads(body['messages'][0]['content'])['feedback'], ['Preserve ABI'])
        self.assertEqual(body['max_tokens'], 4096)
        self.assertNotIn('response_format', body); self.assertNotIn('reasoning_effort', body)
        self.assertEqual(result['usage'], {'prompt_tokens': 10, 'completion_tokens': 5, 'total_tokens': 15})

    def test_translation_uses_native_messages_and_separate_prompt(self):
        client = self.client()
        context = {'evidence': [{'id': 'i:1'}]}
        size = client.translation_request_size('int f();', context, 'cpp')
        result = client.translate('int f();', context, 'cpp')
        request = self.server.requests[-1]
        body = request['body']
        self.assertEqual(request['path'], '/v1/messages')
        self.assertIn('C++17', body['system'])
        self.assertNotIn('response_format', body)
        self.assertEqual(result['usage']['total_tokens'], 15)
        self.assertEqual(size, len(client._request_payload('int f();', dict(context, target_language='cpp'),
            None, system_prompt=body['system'])))

    def test_only_explicit_native_protocol_changes_endpoint(self):
        self.assertTrue(LLMClient('https://api.anthropic.com', 'fixture', api_format='anthropic').endpoint.endswith('/v1/messages'))
        self.assertEqual(self.client().endpoint, self.client_endpoint('/messages'))
        self.assertEqual(LLMClient(self.url + '/messages', 'fixture', api_format='anthropic').endpoint, self.client_endpoint('/messages'))
        for format in ('auto', True, None):
            with self.assertRaises(ValueError):
                LLMClient(self.url, 'fixture', api_format=format)
        with self.assertRaises(ValueError):
            LLMClient(self.url + '/chat/completions', 'fixture', api_format='anthropic')

    def client_endpoint(self, suffix):
        return self.url + suffix

    def test_unsupported_native_options_are_rejected_before_any_request(self):
        for options in ({'reasoning_effort': 'high'}, {'temperature': 1.5}):
            with self.subTest(options=options), self.assertRaises(ValueError):
                self.client(**options)
        self.assertEqual(self.server.requests, [])
        self.client(max_output_tokens=1024, temperature=0, reasoning_effort='none').refine('int f(void);', {})
        self.assertEqual(self.server.requests[-1]['body']['max_tokens'], 1024)
        self.assertEqual(self.server.requests[-1]['body']['temperature'], 0)

    def test_credentials_cannot_be_embedded_in_public_configuration_fields(self):
        from gamedecomp.pipeline import AnalysisConfig
        key = 'private-test-credential'
        for api_format in ('openai', 'anthropic'):
            for endpoint, model in ((self.url + '/' + key, 'fixture'), (self.url, 'fixture-' + key)):
                with self.subTest(api_format=api_format, endpoint=endpoint), self.assertRaises(ValueError):
                    LLMClient(endpoint, model, api_key=key, api_format=api_format)
                with self.assertRaises(ValueError):
                    AnalysisConfig(llm_endpoint=endpoint, llm_model=model, llm_api_key=key, llm_api_format=api_format)
        self.assertEqual(self.server.requests, [])

    def test_native_json_mode_reports_the_effective_prompt_protocol(self):
        from gamedecomp.pipeline import AnalysisConfig
        self.assertEqual(self.client(json_mode='object').json_mode, 'prompt')
        config = AnalysisConfig(llm_endpoint=self.url, llm_model='fixture', llm_api_format='anthropic', llm_json_mode='object')
        self.assertEqual(config.llm_json_mode, 'prompt')

    def test_cached_input_tokens_are_counted_and_private_fields_dropped(self):
        self.server.reply['usage'].update(cache_creation_input_tokens=20, cache_read_input_tokens=30,
                                          private='private-test-key', total_tokens=999)
        usage = self.client().refine('int f(void);', {})['usage']
        self.assertEqual(usage, {'prompt_tokens': 60, 'completion_tokens': 5, 'total_tokens': 65})

    def test_nonfinal_responses_are_never_accepted_and_usage_survives(self):
        for stop, code in (('max_tokens', 'output_truncated'),
                           ('model_context_window_exceeded', 'context_length_exceeded'),
                           ('tool_use', 'invalid_structured_response'), ('pause_turn', 'invalid_structured_response'),
                           ('stop_sequence', 'invalid_structured_response'), (None, 'invalid_structured_response')):
            self.server.reply['stop_reason'] = stop
            with self.subTest(stop=stop), self.assertRaises(LLMError) as raised:
                self.client().refine('int f(void);', {})
            self.assertEqual(raised.exception.code, code)
            self.assertEqual(raised.exception.usage['total_tokens'], 15)

    def test_tool_blocks_refusals_and_wrong_envelopes_fail_closed(self):
        valid = dict(self.server.reply)
        for patch in ({'content': valid['content'] + [{'type': 'tool_use', 'name': 'shell'}]},
                      {'stop_details': {'type': 'refusal', 'explanation': 'private-test-key'}},
                      {'role': 'user'}, {'type': 'error'}, {'content': []}):
            self.server.reply = dict(valid, **patch)
            with self.subTest(patch=patch), self.assertRaises(LLMError) as raised:
                self.client().refine('int f(void);', {})
            self.assertNotIn('private-test-key', str(raised.exception))

    def test_thinking_is_discarded_and_split_text_is_validated_as_one_json(self):
        content = json.dumps(self.result)
        self.server.reply['content'] = [{'type': 'thinking', 'thinking': 'private reasoning'},
            {'type': 'text', 'text': content[:12]}, {'type': 'redacted_thinking', 'data': 'hidden'},
            {'type': 'text', 'text': content[12:]}]
        result = self.client().refine('int f(void);', {})
        self.assertEqual(result['source'], self.result['source'])
        self.assertNotIn('thinking', result)

    def test_duplicate_keys_and_echoed_credentials_use_shared_guard(self):
        content = json.dumps(self.result)[:-1] + ',"source":"int f(void){return 0;}"}'
        self.server.reply['content'][0]['text'] = content
        with self.assertRaises(LLMError): self.client().refine('int f(void);', {})
        self.result['assumptions'] = ['private-test-key']
        self.server.reply['content'][0]['text'] = json.dumps(self.result)
        self.assertEqual(self.client().refine('int f(void);', {})['assumptions'], ['[REDACTED]'])

    def test_model_metadata_uses_native_auth_and_declared_limits_only(self):
        self.server.reply = {'id': 'claude-fixture', 'type': 'model', 'max_input_tokens': 200000, 'max_tokens': 8192}
        limits = self.client().model_limits()
        self.assertEqual(limits, {'status': 'AVAILABLE', 'context_window': 200000, 'max_output_tokens': 8192})
        request = self.server.requests[-1]
        self.assertEqual(request['method'], 'GET'); self.assertEqual(request['path'], '/v1/models/claude-fixture')
        self.assertEqual(request['headers'].get('x-api-key'), 'private-test-key')
        self.server.reply = {'id': 'claude-fixture', 'type': 'model', 'max_input_tokens': True, 'max_tokens': '8192'}
        self.assertEqual(self.client().model_limits(), {'status': 'AVAILABLE'})

    def test_native_context_error_is_sanitized_and_redirect_is_not_followed(self):
        self.server.status = 400
        self.server.reply = {'type': 'error', 'error': {'type': 'invalid_request_error',
            'message': 'prompt is too long: 201000 tokens > 200000 maximum private-test-key'}}
        with self.assertRaises(LLMError) as raised: self.client().refine('int f(void);', {})
        self.assertEqual(raised.exception.code, 'context_length_exceeded')
        self.assertNotIn('private-test-key', str(raised.exception))
        self.server.status = 302
        with self.assertRaises(LLMError): self.client().refine('int f(void);', {})
        self.assertEqual([r['path'] for r in self.server.requests], ['/v1/messages', '/v1/messages'])

    @unittest.skipUnless(shutil.which('gcc'), 'GCC required for the trusted finite fixture')
    def test_native_feedback_repairs_disproved_fixture_and_exports_only_tested_candidate(self):
        from gamedecomp.models import Analysis, Function, Instruction
        from gamedecomp.pipeline import AnalysisConfig, run_analysis
        from tests.test_wasm import wasm_fixture
        wrong = 'uint32_t fn(uint32_t p){return p+2;}'
        right = 'uint32_t fn(uint32_t p){return p+1;}'
        for source in (wrong, right):
            result = {'source': source, 'evidence_ids': ['i:1'], 'assumptions': []}
            self.server.replies.append({'type': 'message', 'role': 'assistant', 'stop_reason': 'end_turn',
                'content': [{'type': 'text', 'text': json.dumps(result)}],
                'usage': {'input_tokens': 10, 'output_tokens': 5}})
        self.server.reply = {'type': 'model', 'id': 'claude-fixture', 'max_input_tokens': 200000, 'max_tokens': 4096}
        observations = []
        def validate(function, candidate, *, timeout):
            # Only these two locally authored fixture bodies can be executed.
            self.assertIn(candidate['source'], (wrong, right))
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory); unit = root/'candidate.c'; library = root/'candidate.so'
                unit.write_text('#include <stdint.h>\n' + candidate['source'])
                subprocess.run(['gcc', '-shared', '-fPIC', str(unit), '-o', str(library)],
                               check=True, capture_output=True, timeout=timeout)
                function = ctypes.CDLL(str(library)).fn
                function.argtypes = [ctypes.c_uint32]; function.restype = ctypes.c_uint32
                cases = (0, 1, 127, 0xfffffffe, 0xffffffff)
                failures = [{'input': [value], 'expected': (value+1)&0xffffffff, 'actual': function(value)}
                            for value in cases if function(value) != (value+1)&0xffffffff]
            status = 'DISPROVED' if failures else 'TESTED'; observations.append(status)
            result = {'status': status, 'candidate_source_sha256': candidate['source_sha256'],
                      'scope': 'Five finite inputs of an authored scalar fixture; no equivalence proof.',
                      'cases_checked': len(cases), 'mismatches': len(failures)}
            if failures: result['counterexample'] = failures[0]
            return result
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); binary = root/'input.wasm'; binary.write_bytes(wasm_fixture())
            function = Function('f', 'fn', 1, [Instruction(1, 'add', 'EDI, 1')], source=right,
                                metadata={'export_name': 'fn', 'return_bits': 32, 'parameter_bits': [32], 'language': 'c'})
            analysis = Analysis(hashlib.sha256(binary.read_bytes()).hexdigest(), 'WASM', 'wasm32', 'wasm', [function])
            with patch('gamedecomp.pipeline._analyze', return_value=analysis):
                report = run_analysis(binary, root/'output', AnalysisConfig(backend='wasm', cache_path=root/'cache.sqlite',
                    llm_endpoint=self.url, llm_model='claude-fixture', llm_api_format='anthropic',
                    llm_attempts=2), candidate_validator=validate)
        self.assertEqual(observations, ['DISPROVED', 'TESTED'])
        self.assertEqual(report['ai_project']['summary']['exported_units'], 1)
        record = report['functions'][0]
        self.assertEqual(record['candidate']['source'], right)
        self.assertEqual(record['candidate']['semantic_status'], 'TESTED')
        posts = [request for request in self.server.requests if request['method'] == 'POST']
        data = [json.loads(request['body']['messages'][0]['content']) for request in posts]
        self.assertEqual(data[0]['context']['validator_contract'], data[1]['context']['validator_contract'])
        self.assertIn('counterexample', '\n'.join(data[1]['feedback']).lower())
        self.assertTrue(all(a['usage']['total_tokens'] == 15 for a in record['ai_attempts']))
