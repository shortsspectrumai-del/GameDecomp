"""Adversarial full-prompt budgets and UTF-8 feedback, without provider calls."""
import hashlib
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

from gamedecomp.llm import LLMClient
from gamedecomp.models import Analysis, Function, Instruction
from gamedecomp.pipeline import AnalysisConfig, run_analysis
from tests.test_wasm import wasm_fixture


class PromptSerializationTests(unittest.TestCase):
    def test_request_size_is_exact_lazy_and_matches_both_wire_formats(self):
        for api_format in ('openai', 'anthropic'):
            client = LLMClient('http://127.0.0.1:9/v1', 'fixture', api_format=api_format)
            source, context, feedback = 'int f(void);', {'escaped': '\\"界'*20}, ['compiler: 😀\\"'*20]
            size = client.request_size(source, context, feedback)
            body = {'type': 'message', 'role': 'assistant', 'stop_reason': 'end_turn',
                'content': [{'type': 'text', 'text': '{"source":"int f(void){return 0;}","evidence_ids":[],"assumptions":[]}'}]}
            if api_format == 'openai':
                body = {'choices': [{'message': {'content': body['content'][0]['text']}}]}
            class Response:
                def __enter__(self): return self
                def __exit__(self, *args): pass
                def read1(self, size):
                    raw = getattr(self, 'raw', json.dumps(body).encode()); self.raw = b''; return raw
            with patch('gamedecomp.llm.urllib.request.build_opener') as opener:
                opener.return_value.open.return_value = Response()
                client.refine(source, context, feedback)
                self.assertEqual(size, len(opener.return_value.open.call_args.args[0].data))

    def test_compiler_feedback_is_bounded_by_bytes_with_explicit_omissions(self):
        from gamedecomp.ai_engine import bounded_feedback
        from gamedecomp.llm import _string_list
        messages = bounded_feedback(['界'*2048, '😀'*2048, 'ordinary', 'bad\ud800unicode'] + ['diagnostic']*100)
        self.assertLessEqual(len(messages), 96)
        self.assertTrue(all(len(message.encode()) <= 2048 for message in messages))
        self.assertIn('TRUNCATED', messages[0]); self.assertIn('TRUNCATED', messages[1])
        self.assertIn('omitted', ' '.join(messages).lower())
        _string_list(messages, 'feedback')


@unittest.skipUnless(shutil.which('gcc'), 'GCC required for the authored scalar fixture')
class PromptBudgetTests(unittest.TestCase):
    def run_case(self, *, huge_feedback=False, dense=False, model_window=131072, serialized_sizes=None):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); source = root/'input.wasm'; source.write_bytes(wasm_fixture())
            function = Function('f', 'fn', 1, [Instruction(i, 'add', '\\"'*(1024 if dense else 100)) for i in range(1, 801)],
                source='uint32_t fn(uint32_t p){return p+1;}',
                metadata={'export_name': 'fn', 'return_bits': 32, 'parameter_bits': [32], 'language': 'c'})
            analysis = Analysis(hashlib.sha256(source.read_bytes()).hexdigest(), 'WASM', 'wasm32', 'wasm', [function])
            seen = []
            def refine(client, seed, context, feedback, **kwargs):
                seen.append({'size': client.request_size(seed, context, feedback), 'context': context, 'feedback': feedback})
                return {'source': seed, 'evidence_ids': ['i:1'], 'assumptions': []}
            patches = [patch('gamedecomp.pipeline._analyze', return_value=analysis),
                patch('gamedecomp.llm.LLMClient.model_limits', return_value={'status': 'AVAILABLE', 'context_window': 4000000 if dense else model_window}),
                patch('gamedecomp.llm.LLMClient.refine', refine)]
            if serialized_sizes is not None:
                original_size = LLMClient.request_size
                def measure(client, *args, **kwargs):
                    size = original_size(client, *args, **kwargs)
                    serialized_sizes.append(size)
                    return size
                patches.append(patch.object(LLMClient, 'request_size', measure))
            if huge_feedback:
                patches.append(patch('gamedecomp.pipeline.compile_source', return_value={
                    'status': 'COMPILE_FAILED', 'diagnostics': [str(index)+'\\"'*1022 for index in range(32)]}))
            from contextlib import ExitStack
            with ExitStack() as stack:
                for item in patches: stack.enter_context(item)
                report = run_analysis(source, root/'output', AnalysisConfig(backend='wasm', cache_path=root/'cache.sqlite',
                    llm_endpoint='http://127.0.0.1:9/v1', llm_model='fixture', llm_attempts=2, llm_context_bytes=1048576 if dense else 65536))
            return seen, report['functions'][0]

    def test_full_serialized_payload_is_fit_before_inference_with_abi_retained(self):
        sizes = []
        # Force a clear overflow, rather than depending on a few hundred bytes
        # of incidental metadata around the model's conservative threshold.
        seen, record = self.run_case(model_window=110592, serialized_sizes=sizes)
        self.assertEqual(len(seen), 1)
        self.assertLess(seen[0]['context']['context_policy']['budget_bytes'], 65536)
        preflight = record['ai_context']['prompt_preflight']
        self.assertGreater(sizes[0], preflight['conservative_budget_bytes'])
        self.assertLessEqual(seen[0]['size'], preflight['conservative_budget_bytes'])
        self.assertEqual(preflight['serialized_request_bytes'], seen[0]['size'])
        self.assertTrue(seen[0]['context']['validator_contract'])
        self.assertEqual(record['candidate']['compilation']['status'], 'COMPILED')

    def test_unfit_required_feedback_stops_before_any_inference(self):
        seen, record = self.run_case(huge_feedback=True)
        self.assertEqual(seen, [])
        self.assertIsNone(record['candidate'])
        self.assertEqual(record['ai_context']['prompt_preflight']['status'], 'UNAVAILABLE')
        self.assertIn('prompt', record['ai_attempts'][0]['diagnostics'][0].lower())

    def test_encoder_size_limit_also_reduces_evidence_before_abandoning(self):
        seen, record = self.run_case(dense=True)
        self.assertEqual(len(seen), 1)
        self.assertLess(seen[0]['size'], 2000000)
        self.assertLess(seen[0]['context']['context_policy']['budget_bytes'], 1048576)
        self.assertTrue(record['ai_context']['request_reduced_context'])
        self.assertEqual(record['candidate']['compilation']['status'], 'COMPILED')
