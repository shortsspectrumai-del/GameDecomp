import copy
import ctypes
import hashlib
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from gamedecomp.models import Analysis, Function, Instruction
from gamedecomp.pipeline import AnalysisConfig, run_analysis
from tests.test_wasm import wasm_fixture


@unittest.skipUnless(shutil.which('gcc'), 'GCC required')
class SemanticRefinementTests(unittest.TestCase):
    def run_fixture(self, validator, sources):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); binary=root/'input.wasm';binary.write_bytes(wasm_fixture())
            function=Function('f','fn',1,[Instruction(1,'add','EDI, 1')],
                source='uint32_t fn(uint32_t p){return p+1;}',metadata={
                    'export_name':'fn','return_bits':32,'parameter_bits':[32],'language':'c'})
            analysis=Analysis(hashlib.sha256(binary.read_bytes()).hexdigest(),'WASM','wasm32','wasm',[function])
            self.requests=[]
            def refine(client,seed,context,feedback,**options):
                index=len(self.requests);self.requests.append((seed,copy.deepcopy(context),list(feedback)))
                return {'source':sources[min(index,len(sources)-1)],'evidence_ids':['i:1'],'assumptions':[],
                        'usage':{'prompt_tokens':10,'completion_tokens':5,'total_tokens':15}}
            with patch('gamedecomp.pipeline._analyze',return_value=analysis),patch('gamedecomp.llm.LLMClient.model_limits',return_value={'status':'UNAVAILABLE'}),patch('gamedecomp.llm.LLMClient.refine',refine):
                report=run_analysis(binary,root/'output',AnalysisConfig(backend='wasm',cache_path=root/'cache.sqlite',llm_endpoint='http://127.0.0.1:9/v1',llm_model='fixture',llm_attempts=len(sources)),candidate_validator=validator)
            self.candidate_sources=[x.read_text() for x in (root/'output/functions').glob('*.candidate.c')]
            self.project_sources=[x.read_text() for x in (root/'output/project-ai').rglob('*.c')]
            return report

    def outcome(self,candidate,status='TESTED',**overrides):
        result={'status':status,'candidate_source_sha256':candidate['source_sha256'],
            'scope':'Trusted finite fixture: p=0 and p=4294967295; not equivalence proof.',
            'cases_checked':2,'mismatches':0}
        if status=='DISPROVED':result.update(mismatches=1,counterexample={'input':[0],'expected':1,'actual':2})
        result.update(overrides);return result

    def test_disproved_compilable_candidate_is_refined_and_only_tested_exported(self):
        seen=[]
        def validate(function,candidate,*,timeout):
            seen.append((copy.deepcopy(function),copy.deepcopy(candidate),timeout))
            with tempfile.TemporaryDirectory() as directory:
                root=Path(directory); source=root/'candidate.c';library=root/'candidate.so'
                source.write_text('#include <stdint.h>\n'+candidate['source'])
                subprocess.run(['gcc','-shared','-fPIC',str(source),'-o',str(library)],check=True,capture_output=True,timeout=timeout)
                recovered=ctypes.CDLL(str(library)).fn
                recovered.argtypes=[ctypes.c_uint32];recovered.restype=ctypes.c_uint32
                mismatches=[{'input':[value],'expected':(value+1)&0xffffffff,'actual':recovered(value)}
                            for value in (0,0xffffffff) if recovered(value)!=((value+1)&0xffffffff)]
            function['source']='MUTATED';candidate['source']='MUTATED'
            result=self.outcome(seen[-1][1],'DISPROVED' if mismatches else 'TESTED')
            result['mismatches']=len(mismatches)
            if mismatches:result['counterexample']=mismatches[0]
            return result
        wrong='uint32_t fn(uint32_t p){return p+2;}'
        right='uint32_t fn(uint32_t p){return p+1;}'
        report=self.run_fixture(validate,[wrong,right]);record=report['functions'][0]
        self.assertEqual(len(seen),2);self.assertTrue(all(x[2]>0 for x in seen))
        self.assertEqual(record['source'],'uint32_t fn(uint32_t p){return p+1;}')
        self.assertEqual(record['candidate']['semantic_status'],'TESTED')
        self.assertTrue(record['candidate']['selection_eligible'])
        self.assertEqual(report['ai_project']['summary']['exported_units'],1)
        self.assertEqual(self.requests[0][1]['validator_contract'],self.requests[1][1]['validator_contract'])
        self.assertIn('counterexample','\n'.join(self.requests[1][2]).lower())
        self.assertIn('Expected external signature','\n'.join(self.requests[1][2]))
        self.assertIn(right,'\n'.join(self.project_sources));self.assertNotIn(wrong,'\n'.join(self.project_sources))
        self.assertEqual(record['ai_attempts'][0]['semantic_validation']['status'],'DISPROVED')
        self.assertEqual([a['usage']['total_tokens'] for a in record['ai_attempts']], [15,15])
        self.assertEqual(record['rejected_candidates'][0]['source'],wrong)

    def test_last_disproved_is_retained_but_not_exported(self):
        report=self.run_fixture(lambda f,c,**kw:self.outcome(c,'DISPROVED'),['uint32_t fn(uint32_t p){return p+2;}'])
        candidate=report['functions'][0]['candidate']
        self.assertEqual(candidate['semantic_status'],'DISPROVED');self.assertFalse(candidate['selection_eligible'])
        self.assertEqual(report['ai_project']['summary']['exported_units'],0)
        self.assertTrue(self.candidate_sources)

    def test_unknown_invalid_hash_nonfinite_and_exception_stop_without_export(self):
        variants=[lambda c:self.outcome(c,'UNKNOWN'),lambda c:self.outcome(c,'PROVED'),lambda c:[],
            lambda c:self.outcome(c,candidate_source_sha256='wrong'),
            lambda c:self.outcome(c,cases_checked=True),lambda c:self.outcome(c,mismatches=1),
            lambda c:self.outcome(c,scope=''),lambda c:self.outcome(c,extra=float('nan')),
            lambda c:self.outcome(c,'DISPROVED',counterexample={'x':float('inf')}),
            lambda c:self.outcome(c,'DISPROVED',counterexample={'x':'x'*9000}),
            lambda c: (_ for _ in ()).throw(RuntimeError('secret-do-not-persist'))]
        for outcome in variants:
            with self.subTest(outcome=outcome):
                report=self.run_fixture(lambda f,c,**kw:outcome(c),['uint32_t fn(uint32_t p){return p+1;}']*2)
                self.assertEqual(len(self.requests),1)
                candidate=report['functions'][0]['candidate']
                self.assertEqual(candidate['semantic_status'],'UNKNOWN');self.assertFalse(candidate['selection_eligible'])
                self.assertEqual(report['ai_project']['summary']['exported_units'],0)
                self.assertNotIn('secret-do-not-persist',str(report))

    def test_callback_is_not_called_for_compile_failure_or_changed_abi(self):
        for source in ('uint32_t fn(uint32_t p){return missing;}', 'uint32_t fn(uint64_t p){return p;}'):
            with self.subTest(source=source):
                validator=unittest.mock.Mock()
                report=self.run_fixture(validator,[source]);validator.assert_not_called()
                self.assertEqual(report['ai_project']['summary']['exported_units'],0)

    def test_no_callback_preserves_compile_only_legacy_behavior(self):
        report=self.run_fixture(None,['uint32_t fn(uint32_t p){return p+1;}'])
        candidate=report['functions'][0]['candidate']
        self.assertEqual(candidate['semantic_status'],'UNKNOWN')
        self.assertEqual(report['ai_project']['summary']['exported_units'],1)


class SemanticFeedbackTests(unittest.TestCase):
    def test_large_bounded_counterexample_survives_pipeline_feedback_caps(self):
        import json
        from gamedecomp.semantic import semantic_feedback
        validation={'status':'DISPROVED','scope':'Finite trusted fixture only.',
                    'cases_checked':2,'mismatches':1,'counterexample':{'values':'x'*7000}}
        messages=semantic_feedback(validation)
        self.assertTrue(all(len(message)<=2048 for message in messages))
        chunks=[message.split(': ',1)[1] for message in messages if message.startswith('Counterexample JSON chunk ')]
        self.assertEqual(json.loads(''.join(chunks))['counterexample'],validation['counterexample'])


class CandidateUsabilityTests(unittest.TestCase):
    def test_fail_closed_semantics_with_legacy_compatibility(self):
        from gamedecomp.semantic import candidate_is_usable
        self.assertFalse(candidate_is_usable(None))
        legacy={'compilation':{'status':'COMPILED'},'semantic_status':'UNKNOWN'}
        self.assertTrue(candidate_is_usable(legacy))
        for updates in ({'semantic_status':'DISPROVED'},{'selection_eligible':False},{'compilation':{'status':'UNKNOWN'}}):
            self.assertFalse(candidate_is_usable(dict(legacy,**updates)))
