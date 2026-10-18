import copy
import hashlib
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch
from gamedecomp.ai_engine import recovery_context
from gamedecomp.evidence import function_context
from gamedecomp.models import Function, Instruction, Analysis
from gamedecomp.pipeline import run_analysis, AnalysisConfig
from tests.test_wasm import wasm_fixture

class ValidatorContractTests(unittest.TestCase):
    def fixture(self, source='char fn(unsigned long p){return p==7;}', metadata=None):
        return Function('f','fn',1,[Instruction(1,'cmp','RDI, 7')],source=source,
            metadata=metadata or {'language':'c','signature':'undefined fn(void)'})

    def test_listing_is_not_the_validator_contract(self):
        from gamedecomp.ai_engine import validator_contract
        function=self.fixture()
        contract=validator_contract(function.source,function.metadata,function.name)
        context,_=recovery_context(function_context(function,'dummy',{}),{'status':'COMPILED'},contract=contract)
        self.assertEqual(context['validator_contract']['declaration'],'char fn(unsigned long p);')
        self.assertEqual(context['validator_contract']['source_sha256'],hashlib.sha256(function.source.encode()).hexdigest())
        self.assertEqual(context['evidence'][-1]['metadata']['signature'],'undefined fn(void)')
        self.assertIn('inferred',context['validator_contract']['listing_signature_scope'])

    def test_scalar_contract_without_body_and_unavailable_contract(self):
        from gamedecomp.ai_engine import validator_contract
        contract=validator_contract(None,{'export_name':'fn','return_bits':32,'parameter_bits':[64]},'fn')
        self.assertEqual(contract['declaration'],'uint32_t fn(uint64_t p0);')
        self.assertEqual(contract['provenance'],'observed_scalar_metadata')
        self.assertIsNone(validator_contract(None,{'signature':'undefined fn(void)'},'fn'))
        with self.assertRaisesRegex(ValueError,'ABI'):
            recovery_context(function_context(self.fixture(source=None),'dummy',{}),{'status':'UNKNOWN'})

    def test_explicit_missing_contract_cannot_fall_back_to_scalar_metadata(self):
        function=self.fixture(source='int fn(p) int p; {return p;}',metadata={
            'export_name':'fn','return_bits':32,'parameter_bits':[32],'language':'c'})
        context=function_context(function,'dummy',{})
        with self.assertRaisesRegex(ValueError,'ABI'):
            recovery_context(context,{'status':'UNKNOWN'},contract=None)
        fallback,_=recovery_context(context,{'status':'UNKNOWN'})
        self.assertEqual(fallback['validator_contract']['provenance'],'observed_scalar_metadata')

    def test_unrecognized_nonempty_baseline_does_not_trigger_scalar_fallback_llm(self):
        function=self.fixture(source='int fn(p) int p; {return p;}',metadata={
            'export_name':'fn','return_bits':32,'parameter_bits':[32],'language':'c'})
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);binary=root/'input.wasm';binary.write_bytes(wasm_fixture())
            analysis=Analysis(hashlib.sha256(binary.read_bytes()).hexdigest(),'WASM','wasm32','wasm',[function])
            with patch('gamedecomp.pipeline._analyze',return_value=analysis),patch('gamedecomp.llm.LLMClient.model_limits',return_value={'status':'UNAVAILABLE'}),patch('gamedecomp.llm.LLMClient.refine',return_value={'source':'uint32_t fn(uint32_t p){return p;}','evidence_ids':['i:1'],'assumptions':[]}) as llm:
                report=run_analysis(binary,root/'output',AnalysisConfig(backend='wasm',cache_path=root/'cache.sqlite',llm_endpoint='http://127.0.0.1:9/v1',llm_model='dummy'))
            llm.assert_not_called()
            self.assertIsNone(report['functions'][0]['candidate'])
            self.assertEqual(report['functions'][0]['ai_attempts'][0]['status'],'UNKNOWN')
            self.assertEqual(report['ai_project']['summary']['exported_units'],0)

    def test_contract_check_matches_annotated_abi_and_pointee_policy(self):
        from gamedecomp.ai_engine import validator_contract, abi_assertion
        ordinary=validator_contract('void fn(unsigned long *p){}',{},'fn')
        self.assertEqual(ordinary['check'],'COMPILER_ABI_SHAPE')
        self.assertIn('data-pointee',ordinary['repair_policy'])
        self.assertIn('hypotheses',ordinary['repair_policy'])
        self.assertIn('callbacks',ordinary['repair_policy'])
        for source in ('char __cdecl fn(unsigned long p){return 0;}',
                       'char __attribute__((sysv_abi)) fn(unsigned long p){return 0;}',
                       'char fn(unsigned long p __attribute__((unused))){return 0;}'):
            with self.subTest(source=source):
                contract=validator_contract(source,{},'fn')
                self.assertEqual(contract['check'],'COMPILER_TYPE_IDENTITY')
                self.assertNotIn('data-pointee refinements are permitted',contract['repair_policy'])
                self.assertNotIn('_shape',abi_assertion(source,'fn',candidate=source))
        cpp=validator_contract('void fn(unsigned long *p){}',{},'fn','c++')
        self.assertEqual(cpp['check'],'COMPILER_TYPE_IDENTITY')

    def test_minimum_budget_preserves_full_contract_or_rejects(self):
        from gamedecomp.ai_engine import validator_contract
        function=self.fixture()
        contract=validator_contract(function.source,function.metadata,function.name)
        context,summary=recovery_context(function_context(function,'dummy',{}),{'status':'COMPILED'},budget=16384,contract=contract)
        self.assertEqual(context['validator_contract'],contract)
        self.assertLessEqual(summary['bytes'],16384)
        huge=copy.deepcopy(contract);huge['declaration']='x'*20000
        with self.assertRaisesRegex(ValueError,'ABI'):
            recovery_context(function_context(function,'dummy',{}),{'status':'COMPILED'},budget=16384,contract=huge)

    def test_pipeline_without_contract_is_unknown_before_llm(self):
        function=self.fixture(source=None)
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); binary=root/'input.wasm'; binary.write_bytes(wasm_fixture())
            analysis=Analysis(hashlib.sha256(binary.read_bytes()).hexdigest(),'WASM','wasm32','wasm',[function])
            with patch('gamedecomp.pipeline._analyze',return_value=analysis),patch('gamedecomp.llm.LLMClient.model_limits',return_value={'status':'UNAVAILABLE'}),patch('gamedecomp.llm.LLMClient.refine') as llm:
                report=run_analysis(binary,root/'output',AnalysisConfig(backend='wasm',cache_path=root/'cache.sqlite',llm_endpoint='http://127.0.0.1:9/v1',llm_model='dummy'))
            llm.assert_not_called()
            self.assertIsNone(report['functions'][0]['candidate'])
            self.assertEqual(report['functions'][0]['ai_attempts'][0]['status'],'UNKNOWN')
            self.assertEqual(report['ai_project']['summary']['exported_units'],0)

    @unittest.skipUnless(shutil.which('gcc'),'gcc required')
    def test_retry_has_immutable_contract_and_actionable_feedback(self):
        function=self.fixture(source='char fn(unsigned long p){return (unsigned int)p==7;}'); seen=[]
        function.instructions=[Instruction(1,'cmp','EDI, 7')]
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); binary=root/'input.wasm'; binary.write_bytes(wasm_fixture())
            analysis=Analysis(hashlib.sha256(binary.read_bytes()).hexdigest(),'WASM','wasm32','wasm',[function])
            def recover(client,seed,context,feedback,**options):
                seen.append((seed,copy.deepcopy(context),list(feedback)))
                source=('char fn(unsigned int p){return p==7;}' if len(seen)==1 else
                        'char fn(unsigned long p){unsigned int narrow=(unsigned int)p;return narrow==7;}')
                return {'source':source,'evidence_ids':['i:1'],'assumptions':['Local cast is a hypothesis requiring behavioral validation.']}
            with patch('gamedecomp.pipeline._analyze',return_value=analysis),patch('gamedecomp.llm.LLMClient.model_limits',return_value={'status':'UNAVAILABLE'}),patch('gamedecomp.llm.LLMClient.refine',recover):
                report=run_analysis(binary,root/'output',AnalysisConfig(backend='wasm',cache_path=root/'cache.sqlite',llm_endpoint='http://127.0.0.1:9/v1',llm_model='dummy',llm_attempts=2))
        self.assertEqual(len(seen),2)
        self.assertEqual(seen[0][1]['validator_contract'],seen[1][1]['validator_contract'])
        self.assertIn('unsigned int',seen[1][0])
        feedback='\n'.join(seen[1][2])
        self.assertIn('Expected external signature: char fn(unsigned long p);',feedback)
        self.assertIn('Proposed external signature: char fn(unsigned int p);',feedback)
        self.assertIn('binary evidence',feedback)
        self.assertEqual(report['functions'][0]['candidate']['compilation']['status'],'COMPILED')
        self.assertEqual(report['functions'][0]['candidate']['semantic_status'],'UNKNOWN')
