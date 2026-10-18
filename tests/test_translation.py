"""Translation is a separate, provenance-bound, compile-only operation."""
import hashlib
import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from gamedecomp.pipeline import AnalysisConfig


class TranslationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.report = self.root / 'original.json'
        self.original = {'input': {'sha256': 'abc'}, 'functions': [{
            'id': 'f', 'name': 'add', 'address': 16,
            'source': 'int add(int a, int b) { return a + b; }',
            'semantic_status': 'TESTED', 'metadata': {}}]}
        self.save()
        self.config = AnalysisConfig(llm_endpoint='http://127.0.0.1:1/v1', llm_model='fixture', timeout=30)

    def save(self):
        self.report.write_text(json.dumps(self.original))

    def run_translation(self, target='cpp', replies=None, **kwargs):
        from gamedecomp.translation import translate_function
        if replies is None:
            replies = ['int recovered(int a, int b) { return a + b; }']
        def reply(source, context, target_language, feedback=None, **unused):
            return {'source': replies.pop(0), 'evidence_ids': [context['evidence'][0]['id']],
                    'assumptions': [], 'usage': {'total_tokens': 12}}
        with patch('gamedecomp.translation.LLMClient.translate', side_effect=reply) as mocked:
            result = translate_function(self.report, self.root / 'output', 'f', target,
                                        self.config, source_job_id='a' * 32, **kwargs)
        return result, mocked

    @unittest.skipUnless(shutil.which('g++') or shutil.which('clang++'), 'C++ compiler required')
    def test_cpp_preserves_origin_and_never_inherits_equivalence(self):
        before = self.report.read_bytes()
        report, mocked = self.run_translation()
        function = report['functions'][0]
        self.assertEqual(function['compilation']['status'], 'COMPILED')
        self.assertEqual(function['semantic_status'], 'UNKNOWN')
        self.assertEqual(report['summary']['proved'], 0)
        self.assertEqual(report['translation']['source_semantic_status'], 'TESTED')
        self.assertEqual(report['translation']['source_report_sha256'], hashlib.sha256(before).hexdigest())
        self.assertEqual(self.report.read_bytes(), before)
        self.assertEqual(mocked.call_count, 1)
        self.assertTrue((self.root / 'output' / 'RecoveredFunction.cpp').is_file())
        self.assertTrue((self.root / 'output' / 'report.html').is_file())

    def test_disproved_candidate_rejected_before_inference(self):
        self.original['functions'][0]['candidate'] = {'source': 'int x;',
            'compilation': {'status': 'COMPILED'}, 'semantic_status': 'DISPROVED'}
        self.save()
        with patch('gamedecomp.translation.LLMClient.translate') as mocked:
            with self.assertRaisesRegex(ValueError, 'candidate'):
                self.run_translation(source_kind='candidate')
            mocked.assert_not_called()

    def test_unknown_function_and_target_rejected(self):
        from gamedecomp.translation import translate_function
        for function, target in [('absent', 'cpp'), ('f', 'python')]:
            with self.assertRaises(ValueError):
                translate_function(self.report, self.root / 'output', function, target, self.config)

    def test_java_failure_is_fed_back_then_repaired(self):
        from gamedecomp.translation import compile_java
        if compile_java('public final class RecoveredFunction { public static int recovered() { return 1; } }')['status'] == 'UNKNOWN':
            self.skipTest('javac required')
        result, mocked = self.run_translation('java', replies=[
            'public final class RecoveredFunction { public static int recovered(int a,int b) { return missing; } }',
            'public final class RecoveredFunction { public static int recovered(int a,int b) { return a+b; } }'])
        self.assertEqual(result['functions'][0]['compilation']['status'], 'COMPILED')
        self.assertEqual(result['functions'][0]['semantic_status'], 'UNKNOWN')
        self.assertEqual(mocked.call_count, 2)
        self.assertIn('missing', str(mocked.call_args_list[1]))
        self.assertTrue((self.root / 'output' / 'RecoveredFunction.java').is_file())

    def test_context_overflow_never_calls_model_or_truncates_source(self):
        self.original['functions'][0]['source'] += '\n/*' + 'x' * 24000 + '*/'
        self.save()
        self.config.llm_context_bytes = 16384
        report, mocked = self.run_translation()
        self.assertEqual(mocked.call_count, 0)
        self.assertEqual(report['functions'][0]['compilation']['status'], 'UNKNOWN')
        self.assertEqual(report['translation']['attempts'][0]['status'], 'CONTEXT_LIMIT')

    def test_no_evidence_and_missing_entry_are_rejected(self):
        result, _ = self.run_translation(replies=['int different() { return 1; }'] * 2)
        self.assertEqual(result['functions'][0]['compilation']['status'], 'REJECTED')
        self.assertFalse((self.root / 'output' / 'RecoveredFunction.cpp').exists())
        from gamedecomp.translation import translation_issues
        self.assertTrue(translation_issues('int recovered() {return 1;}', 'cpp', [], 'source:one'))
        self.assertTrue(translation_issues('public final class RecoveredFunction {}', 'java', ['source:one'], 'source:one'))

    def test_java_without_compiler_is_unknown(self):
        from gamedecomp.translation import compile_java
        with patch('gamedecomp.translation.shutil.which', return_value=None), patch.dict(os.environ, {'JAVA_HOME': '/absent'}):
            result = compile_java('public final class RecoveredFunction { public static int recovered() {return 1;} }')
        self.assertEqual(result['status'], 'UNKNOWN')

    def test_disproved_baseline_is_rejected_before_inference(self):
        self.original['functions'][0]['semantic_status'] = 'DISPROVED'
        self.save()
        with self.assertRaisesRegex(ValueError, 'disproved'):
            self.run_translation()

    def test_nested_java_entry_does_not_satisfy_outer_class(self):
        from gamedecomp.translation import compile_java
        code = ('public final class RecoveredFunction { public static class Nested {'
                ' public static int recovered() { return 42; } } }')
        result = compile_java(code)
        if result['toolchain']['compiler'] is None:
            self.skipTest('javac required')
        self.assertEqual(result['status'], 'REJECTED')

    def test_provider_window_reserves_output_before_inference(self):
        with patch('gamedecomp.translation.LLMClient.model_limits',
                   return_value={'status': 'AVAILABLE', 'context_window': 2048, 'max_output_tokens': 512}):
            result, mocked = self.run_translation()
        mocked.assert_not_called()
        self.assertEqual(result['translation']['attempts'][0]['status'], 'CONTEXT_LIMIT')

    def test_existing_output_is_rejected_before_inference_to_avoid_stale_exports(self):
        output = self.root / 'output'
        output.mkdir()
        (output / 'RecoveredFunction.cpp').write_text('stale output')
        with self.assertRaisesRegex(ValueError, 'empty'):
            self.run_translation()

