import hashlib
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

from gamedecomp.ai_engine import recovery_context, recovery_issues, abi_assertion
from gamedecomp.evidence import function_context
from gamedecomp.models import Analysis, Function, Instruction
from gamedecomp.pipeline import AnalysisConfig, run_analysis
from gamedecomp.validation import compile_source
from tests.test_wasm import wasm_fixture


class AIEngineTests(unittest.TestCase):
    def test_large_cfg_and_pcode_are_compacted_with_explicit_omissions(self):
        function = Function('f', 'f', 1, instructions=[Instruction(i,'ADD','EAX, EDI') for i in range(40000)],
                            metadata={'export_name': 'f', 'return_bits':32, 'parameter_bits':[32],
                                      'pcode': ['INT_ADD '*20 for _ in range(8192)]})
        context = function_context(function, 'binary', {})
        compact, summary = recovery_context(context, {'status':'COMPILE_FAILED'}, budget=16384)
        self.assertLessEqual(summary['bytes'],16384)
        self.assertLess(summary['instruction_included'],40000)
        self.assertFalse(summary['complete'])
        self.assertEqual(compact['evidence'][-1]['metadata']['export_name'],'f')
        self.assertEqual(context['evidence'][-1]['metadata']['pcode'],function.metadata['pcode'])
        again, _ = recovery_context(context, {'status':'COMPILE_FAILED'}, budget=16384)
        self.assertEqual(compact,again)

    def test_semantic_proposals_need_observed_evidence_ids(self):
        context={'evidence':[{'id':'i:10'}]}
        self.assertTrue(recovery_issues({'types':[{'name':'Actor','evidence_ids':['invented']}]},context))
        self.assertFalse(recovery_issues({'renamings':[{'suggested':'health','evidence_ids':['i:10']}]},context))

    @unittest.skipUnless(shutil.which('gcc'),'gcc required')
    def test_compiler_enforces_pointer_and_return_type_identity(self):
        original='unsigned char fn(unsigned char *p, unsigned int *score){return 1;}'
        assertion=abi_assertion(original,'fn')
        valid=compile_source(original+assertion)
        invalid=compile_source('unsigned long fn(unsigned char *p, unsigned long *score){return 1;}'+assertion)
        self.assertEqual(valid['status'],'COMPILED')
        self.assertEqual(invalid['status'],'COMPILE_FAILED')
        self.assertIn('Observed function ABI changed','\n'.join(invalid['diagnostics']))

    @unittest.skipUnless(shutil.which('gcc'),'gcc required')
    def test_abi_shape_allows_pointee_recovery_but_rejects_scalar_and_callback_changes(self):
        original='void fn(unsigned long *p, int (*cb)(int)){ }'
        valid='typedef unsigned char byte;\nvoid fn(byte *p, int (*cb)(int)){p[0]=1;}'
        assertion=abi_assertion(original,'fn',candidate=valid)
        self.assertEqual(compile_source(valid+assertion)['status'],'COMPILED')
        for invalid in ('void fn(unsigned long p, int (*cb)(int)){}',
                        'void fn(unsigned char *p, int (*cb)(long)){}',
                        'void fn(unsigned char *p){}',
                        'long fn(unsigned char *p, int (*cb)(int)){return 0;}'):
            assertion=abi_assertion(original,'fn',candidate=invalid)
            self.assertIsNotNone(assertion)
            self.assertEqual(compile_source(invalid+assertion)['status'],'COMPILE_FAILED')

    @unittest.skipUnless(shutil.which('gcc'),'gcc required')
    def test_context_overflow_and_malformed_output_are_retried_automatically(self):
        from gamedecomp.llm import LLMError
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);binary=root/'input.wasm';binary.write_bytes(wasm_fixture())
            seen=[]
            def recover(client, source, context, feedback, **request_options):
                seen.append((context['context_policy']['budget_bytes'],feedback))
                if len(seen)==1:
                    raise LLMError('context too large',code='context_length_exceeded')
                if len(seen)==2:
                    raise LLMError('incomplete JSON',code='invalid_structured_response')
                return {'source':source,'evidence_ids':['signature:wasm:0'],'assumptions':[]}
            with patch('gamedecomp.llm.LLMClient.model_limits',return_value={'status':'AVAILABLE','context_window':131072}), \
                 patch('gamedecomp.llm.LLMClient.refine',recover):
                report=run_analysis(binary,root/'output',AnalysisConfig(backend='wasm',cache_path=root/'cache.sqlite',
                    llm_endpoint='http://127.0.0.1:9/v1',llm_model='test-model',llm_attempts=3,llm_context_bytes=65536))
            function=report['functions'][0]
            self.assertEqual([x[0] for x in seen],[65536,32768,32768])
            self.assertIn('JSON',seen[2][1][0])
            self.assertEqual(function['candidate']['compilation']['status'],'COMPILED')
            self.assertTrue(function['ai_context']['provider_rejected_larger_context'])
            self.assertEqual(len(function['ai_attempts']),3)

    @unittest.skipUnless(shutil.which('gcc'),'gcc required')
    def test_llm_recovers_missing_body_and_receives_compiler_feedback_automatically(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); binary=root/'input.wasm';binary.write_bytes(wasm_fixture())
            function=Function('wasm:0','add',0,instructions=[Instruction(1,'i32.add','')],
                metadata={'export_name':'add','return_bits':32,'parameter_bits':[32,32],'language':'c'})
            analysis=Analysis(hashlib.sha256(binary.read_bytes()).hexdigest(),'WASM','wasm32','wasm',[function])
            requests=[]
            def recover(client, source, context, feedback, **request_options):
                requests.append((source,context,feedback))
                return {'source': 'uint32_t add(uint32_t a,uint32_t b){return '+('missing(a,b)' if len(requests)==1 else 'a+b')+';}',
                        'evidence_ids':['i:1'],'assumptions':[],
                        'recovery':{'intent':'addition','renamings':[],'types':[],'unresolved':[],'status':'HYPOTHESIS'}}
            with patch('gamedecomp.llm.LLMClient.model_limits',return_value={'status':'UNAVAILABLE'}), patch('gamedecomp.pipeline._analyze',return_value=analysis), patch('gamedecomp.llm.LLMClient.refine',recover):
                report=run_analysis(binary,root/'output',AnalysisConfig(backend='wasm',cache_path=root/'cache.sqlite',
                    llm_endpoint='http://127.0.0.1:9/v1',llm_model='test-model'))
            self.assertEqual(report['engine']['mode'],'LLM')
            self.assertIsNone(report['functions'][0]['source'])
            candidate=report['functions'][0]['candidate']
            self.assertEqual(candidate['compilation']['status'],'COMPILED')
            self.assertEqual(candidate['semantic_status'],'UNKNOWN')
            self.assertTrue(requests[1][2])
            self.assertIn('missing',requests[1][0])
            self.assertEqual(report['ai_project']['summary']['exported_units'],1)
            self.assertTrue((root/'output/project-ai/manifest.json').is_file())
            self.assertEqual(report['functions'][0]['reconstruction_source'],'llm_candidate')
