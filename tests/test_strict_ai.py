"""Regressions for unsupported directives, fake signatures and missing ABI gates."""
import hashlib
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

from gamedecomp.evidence import candidate_issues, function_context
from gamedecomp.models import Analysis, Function, Instruction
from gamedecomp.pipeline import AnalysisConfig, run_analysis
from tests.test_wasm import wasm_fixture


class StrictCandidateTests(unittest.TestCase):
    def context(self):
        return function_context(Function('native:10','fn',16,[Instruction(16,'ret','')],
            metadata={'export_name':'fn','return_bits':32,'parameter_bits':[32]}),'hash',{})

    def test_alternative_preprocessor_spellings_cannot_include_arbitrary_headers(self):
        body='\nuint32_t fn(uint32_t p){return p;}'
        for directive in ('%:include <stdio.h>', '/* comment */ #include <stdio.h>',
                          '??=include <stdio.h>', '#inc\\\nlude <stdio.h>',
                          '#include /*hidden*/ <stdio.h>', '_Pragma("GCC diagnostic ignored \\\"-Wreturn-type\\\"")'):
            with self.subTest(directive=directive):
                self.assertTrue(candidate_issues(directive+body,self.context(),['i:10']))

    def test_strings_and_comments_do_not_look_like_directives_or_inline_assembly(self):
        source='''/* #include <stdio.h> asm("x") */
#include <stdint.h>
uint32_t fn(uint32_t p){const char *s="#define EVIL 1";return p;}
'''
        self.assertEqual(candidate_issues(source,self.context(),['i:10']),[])

    def test_compiler_extended_line_splices_cannot_hide_assembly_or_pragmas(self):
        for whitespace, newline in ((' ', '\n'), ('\t', '\n'), (' \t', '\n'),
                                    ('', '\r'), (' ', '\r'), ('', '\r\n'), ('', '\n\r')):
            splice = '\\' + whitespace + newline
            for statement in ('__a' + splice + 'sm__("nop");',
                              '_Pr' + splice + 'agma("GCC diagnostic ignored \\"-Wuninitialized\\"")'):
                with self.subTest(whitespace=whitespace, statement=statement):
                    source = 'uint32_t fn(uint32_t p){' + statement + 'return p;}'
                    self.assertTrue(candidate_issues(source, self.context(), ['i:10']))

    def test_a_signature_in_a_comment_cannot_mask_wrong_scalar_widths(self):
        source='/* uint32_t fn(uint32_t p){ */\nuint64_t fn(uint64_t p){return p;}'
        self.assertTrue(candidate_issues(source,self.context(),['i:10']))

    def test_function_identity_requires_a_real_definition_even_without_export_metadata(self):
        context=self.context();context['evidence'][-1]['metadata'].pop('export_name')
        for source in ('int other(void){return 1;}', '/* int fn(int p){return p;} */ int other(void){return 1;}',
                       'int fn(int p); int other(void){return fn(1);}'): 
            with self.subTest(source=source):
                self.assertTrue(candidate_issues(source,context,['i:10']))

    def test_unresolved_machine_state_and_forged_validator_symbols_are_rejected(self):
        for source in ('uint32_t fn(uint32_t p){uint32_t in_EAX=0;return in_EAX;}',
                       'uint32_t fn(uint32_t p){uint32_t __gd_abi_override=0;return p;}',
                       'uint32_t fn(uint32_t p){return unaff_RBX;}',
                       'uint32_t __gd_load(int x){return 0;}\nuint32_t fn(uint32_t p){return p;}'):
            with self.subTest(source=source):
                self.assertTrue(candidate_issues(source,self.context(),['i:10']))


@unittest.skipUnless(shutil.which('gcc'),'GCC required')
class StrictPipelineTests(unittest.TestCase):
    def run_fixture(self, root, function, response):
        binary=root/'input.wasm';binary.write_bytes(wasm_fixture())
        analysis=Analysis(hashlib.sha256(binary.read_bytes()).hexdigest(),'WASM','wasm32','wasm',[function])
        with patch('gamedecomp.pipeline._analyze',return_value=analysis), \
             patch('gamedecomp.llm.LLMClient.model_limits',return_value={'status':'UNAVAILABLE'}), \
             patch('gamedecomp.llm.LLMClient.refine',return_value=response):
            return run_analysis(binary,root/'output',AnalysisConfig(backend='wasm',cache_path=root/'cache.sqlite',
                llm_endpoint='http://127.0.0.1:9/v1',llm_model='fixture',llm_attempts=1))

    def test_unavailable_abi_never_exports_candidate_as_compiled(self):
        function=Function('f','fn',1,instructions=[Instruction(1,'ret','')],
            source='int fn(p) int p; {return p;}',metadata={'language':'c'})
        with tempfile.TemporaryDirectory() as directory:
            report=self.run_fixture(Path(directory),function,{'source':'long fn(long p){return p;}',
                'evidence_ids':['i:1'],'assumptions':[]})
            candidate=report['functions'][0].get('candidate')
            self.assertIsNone(candidate)
            self.assertEqual(report['functions'][0]['ai_attempts'][0]['status'],'UNKNOWN')
            self.assertEqual(report['ai_project']['summary']['exported_units'],0)

    def test_metadata_contract_enforces_abi_when_original_body_is_missing(self):
        function=Function('f','fn',1,instructions=[Instruction(1,'i32.add','')],
            metadata={'export_name':'fn','return_bits':32,'parameter_bits':[32,32],'language':'c'})
        with tempfile.TemporaryDirectory() as directory:
            report=self.run_fixture(Path(directory),function,{'source':'uint32_t fn(uint32_t a,uint32_t b){return a+b;}',
                'evidence_ids':['i:1'],'assumptions':[]})
            candidate=report['functions'][0]['candidate']
            self.assertEqual(candidate['compilation']['status'],'COMPILED')
            self.assertNotEqual(candidate['compilation']['abi_check'],'UNAVAILABLE')

    def test_missing_return_is_not_accepted_by_llm_pipeline(self):
        function=Function('f','fn',1,instructions=[Instruction(1,'ret','')],
            source='int fn(int p){return p;}',metadata={'language':'c'})
        with tempfile.TemporaryDirectory() as directory:
            report=self.run_fixture(Path(directory),function,{'source':'int fn(int p){}',
                'evidence_ids':['i:1'],'assumptions':[]})
            self.assertNotEqual(report['functions'][0]['candidate']['compilation']['status'],'COMPILED')
            self.assertEqual(report['ai_project']['summary']['exported_units'],0)
