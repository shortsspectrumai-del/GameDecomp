"""Behavioral checks for Studio status labels, local presets and safe preferences."""
import json
from collections import Counter
from html.parser import HTMLParser
from pathlib import Path
import shutil
import subprocess
import unittest

ROOT=Path(__file__).resolve().parents[1]
SCRIPT=(ROOT/'gamedecomp/ui/app.js').read_text()


def functions_between(first,last):
    return SCRIPT[SCRIPT.index('  function '+first+'('):SCRIPT.index('  function '+last+'(')]


class Markup(HTMLParser):
    def __init__(self):
        super().__init__();self.elements=[]
    def handle_starttag(self,tag,attributes):
        self.elements.append((tag,dict(attributes)))


class StudioStructureTests(unittest.TestCase):
    def test_settings_share_unique_form_controls_and_accessible_live_regions(self):
        parser=Markup();parser.feed((ROOT/'gamedecomp/ui/index.html').read_text())
        ids=Counter(attributes['id'] for _,attributes in parser.elements if 'id' in attributes)
        self.assertFalse([identity for identity,count in ids.items() if count!=1])
        by_id={attributes['id']:(tag,attributes) for tag,attributes in parser.elements if 'id' in attributes}
        self.assertEqual(next(attrs for tag,attrs in parser.elements if tag=='html')['lang'],'en')
        for identity in ('backend','workers','timeout','provider','llm-model','llm-url','llm-key','llm-api-format'):
            self.assertEqual(by_id[identity][1]['form'],'analysis-form')
        for identity in ('settings-provider-slot','workspace-provider-slot','settings-analysis-slot','workspace-analysis-slot'):
            self.assertIn(identity,by_id)
        for identity in ('llm-connection-status','preferences-status','progress-summary'):
            self.assertEqual(by_id[identity][1]['aria-live'],'polite')
        self.assertNotIn('required',by_id['llm-key'][1])
        for identity in ('test-llm-connection','refresh-llm-models','save-preferences','clear-preferences'):
            self.assertEqual(by_id[identity][1]['type'],'button')


@unittest.skipUnless(shutil.which('node'),'Node.js required for actual UI helper execution')
class StudioBehaviorTests(unittest.TestCase):
    def execute(self,source):
        process=subprocess.run(['node','-e',source],capture_output=True,text=True,timeout=10)
        self.assertEqual(process.returncode,0,process.stderr)
        return json.loads(process.stdout)

    def test_function_translation_requires_original_completed_source_and_llm(self):
        self.assertTrue('  function translationSelection(' in SCRIPT, 'Function translation controls are missing')
        functions=functions_between('translationSelection','renderCode')
        result=self.execute("""
          const fields={provider:{value:'off'},'translation-language':{value:'cpp'},'translate-function':{},'translation-status':{}};
          const $=(id)=>fields[id];const state={activeFunction:'fn1',codeTab:'baseline',submitting:false,
            reportJob:{id:'origin',kind:'analyze',status:'SUCCEEDED'},report:{functions:[{id:'fn1',source:'int f(){return 1;}',candidate:{source:'int f(){return 2;}',compilation:{status:'COMPILED'}}}]}};
        """+functions+"""
          const results=[];const snapshot=()=>{updateTranslationControls();results.push({disabled:$('translate-function').disabled,message:$('translation-status').textContent,sourceKind:translationSelection().sourceKind});};
          snapshot();$('provider').value='anthropic';snapshot();state.codeTab='candidate';snapshot();
          state.codeTab='disassembly';snapshot();state.codeTab='baseline';state.reportJob.kind='translate';snapshot();
          console.log(JSON.stringify(results));
        """)
        self.assertTrue(result[0]['disabled']);self.assertIn('Configure an LLM',result[0]['message'])
        self.assertFalse(result[1]['disabled']);self.assertEqual(result[1]['sourceKind'],'baseline')
        self.assertFalse(result[2]['disabled']);self.assertEqual(result[2]['sourceKind'],'candidate')
        self.assertTrue(result[3]['disabled']);self.assertIn('Baseline or AI reconstruction',result[3]['message'])
        self.assertTrue(result[4]['disabled']);self.assertIn('original analysis',result[4]['message'])

    def test_translation_submission_uses_selected_source_and_clears_credentials_on_error(self):
        self.assertTrue('  function translationSelection(' in SCRIPT, 'Function translation action is missing')
        functions=functions_between('translationSelection','renderCode')
        result=self.execute("""
          const fields={provider:{value:'anthropic'},'translation-language':{value:'java'},'translate-function':{},'translation-status':{},'llm-key':{value:'private-key'}};
          const $=(id)=>fields[id];const state={activeFunction:'fn1',codeTab:'candidate',submitting:false,
            reportJob:{id:'origin',kind:'demo',status:'SUCCEEDED'},report:{functions:[{id:'fn1',candidate:{source:'int f(){return 2;}',compilation:{status:'COMPILED'}}}]}};
          let submitted,error;const analysisOptions=()=>({llm:{provider:'anthropic',key:'private-key'}});
          const submitJob=async(value)=>{submitted=structuredClone(value);throw Error('bad private-key');};
          const showError=(message)=>{error=message;};const updateRunButton=()=>{};
        """+functions+"""
          (async()=>{await translateFunction();console.log(JSON.stringify({submitted,error,key:$('llm-key').value,busy:state.submitting}));})();
        """)
        self.assertEqual(result['submitted'],{'kind':'translate','source_job_id':'origin','function_id':'fn1',
            'target_language':'java','source_kind':'candidate','options':{'llm':{'provider':'anthropic','key':'private-key'}}})
        self.assertEqual(result['error'],'bad [KEY REDACTED]');self.assertEqual(result['key'],'');self.assertFalse(result['busy'])

    def test_translation_refuses_disproved_baseline_and_uncompiled_candidate(self):
        functions=functions_between('translationSelection','renderCode')
        result=self.execute("""
          const fields={provider:{value:'custom'},'translation-language':{value:'cpp'}};
          const $=(id)=>fields[id];const state={activeFunction:'f',codeTab:'baseline',reportJob:{status:'SUCCEEDED',kind:'analyze'},
            report:{functions:[{id:'f',source:'int f(){return 0;}',semantic_status:'DISPROVED',candidate:{source:'int f(){return 0;}',compilation:{status:'COMPILE_FAILED'}}}]}};
        """+functions+"""
          const baseline=translationSelection();state.codeTab='candidate';const candidate=translationSelection();
          console.log(JSON.stringify({baseline:baseline.available,candidate:candidate.available}));
        """)
        self.assertEqual(result,{'baseline':False,'candidate':False})

    def test_translation_result_identifies_generated_language_without_semantic_claim(self):
        functions=functions_between('renderCode','section')
        result=self.execute("""
          const fields={};const $=(id)=>fields[id]||(fields[id]={});
          const state={activeFunction:'fn1',codeTab:'baseline',reportJob:{kind:'translate'},report:{translation:{target_language:'java'},
            functions:[{id:'fn1',name:'RecoveredFunction',source:'public final class RecoveredFunction {}',metadata:{language:'Java'},compilation:{status:'COMPILED'},semantic_status:'UNKNOWN'}]}};
          const updateTranslationControls=()=>{};const address=()=>'',safeText=(value,fallback)=>value||fallback;
          const document={querySelectorAll:()=>[]};
        """+functions+"""
          renderCode();console.log(JSON.stringify({status:$('code-status').textContent,language:$('function-address').textContent,code:$('code-output').textContent}));
        """)
        self.assertEqual(result['status'],'LLM TRANSLATION · COMPILED · SEMANTICS UNKNOWN')
        self.assertIn('Java',result['language']);self.assertIn('RecoveredFunction',result['code'])

    def test_loopback_detection_and_credential_endpoint_rejection(self):
        functions=functions_between('localEndpoint','updateProviderLocation')
        result=self.execute(functions+"""
          console.log(JSON.stringify({
            local:['http://127.0.0.1:11434/v1','http://localhost:1234/v1','http://[::1]:1234/v1','https://127.1.2.3/v1'].map(localEndpoint),
            remote:['https://api.deepseek.com/v1','http://192.168.1.2:1234/v1','ftp://127.0.0.1/v1'].map(localEndpoint),
            bad:['http://user:password@127.0.0.1/v1','http://127.0.0.1/v1?key=secret','http://127.0.0.1/v1#secret','http://127.0.0.1/sk-1234567890123456'].map(safePreferenceEndpoint),
            good:safePreferenceEndpoint('http://127.0.0.1:11434/v1')
          }));
        """)
        self.assertEqual(result['local'],[True]*4);self.assertEqual(result['remote'],[False]*3)
        self.assertEqual(result['bad'],['']*4);self.assertEqual(result['good'],'http://127.0.0.1:11434/v1')

    def test_candidate_status_never_equates_compilation_with_behavior(self):
        functions=functions_between('candidateStatus','renderProgress')
        result=self.execute("const safeText=(value,fallback)=>value||fallback;\n"+functions+"""
          const values=[null,{semantic_status:'DISPROVED',compilation:{status:'COMPILED'}},
            {semantic_status:'TESTED',compilation:{status:'COMPILED'}},
            {semantic_status:'UNKNOWN',selection_eligible:false,compilation:{status:'COMPILED'}},
            {semantic_status:'UNKNOWN',compilation:{status:'COMPILED'}}];
          console.log(JSON.stringify(values.map(candidateStatus)));
        """)
        self.assertEqual(result,['NO AI CANDIDATE','REJECTED · behavior mismatch','TESTED ON FINITE CASES',
                                 'VALIDATION UNAVAILABLE · NOT EXPORTED','AI CANDIDATE · COMPILED · UNVERIFIED SEMANTICS'])

    def test_preferences_exclude_credentials_even_if_pasted_in_other_fields(self):
        functions=functions_between('localEndpoint','updateProviderLocation')+functions_between('savePreferences','restorePreferences')
        result=self.execute("""
          const fields={'llm-url':{value:'http://127.0.0.1:1234/v1/credential-private'},
            'llm-key':{value:'credential-private'},'llm-model':{value:'model-credential-private'},
            'provider':{value:'lmstudio'},'workers':{value:'4'},'preferences-status':{textContent:''}};
          const $=(id)=>fields[id]; const preferenceFields=['provider','workers'];const preferenceKey='prefs';
          let saved;const localStorage={setItem:(key,value)=>{saved=JSON.parse(value);}};
        """+functions+"savePreferences();console.log(JSON.stringify(saved));")
        self.assertEqual(result,{'provider':'lmstudio','workers':'4','llm-url':''})

    def test_local_provider_presets_remain_editable_and_optional_key(self):
        functions=functions_between('providerChanged','analysisOptions')
        result=self.execute("""
          const fields={}; const $=(id)=>fields[id] || (fields[id]={value:'',removeAttribute:()=>{}});
          const state={providers:[]};const modelDefaults={};
          const localDefaults={ollama:'http://127.0.0.1:11434/v1',lmstudio:'http://127.0.0.1:1234/v1'};
          const resetModelDiscovery=()=>{};const updateProviderLocation=()=>{};
        """+functions+"""
          const result=[];for(const id of ['ollama','lmstudio']) {
            $('provider').value=id;$('llm-key').value='secret';providerChanged();
            result.push({url:$('llm-url').value,readOnly:$('llm-url').readOnly,key:$('llm-key').value,required:$('llm-model').required});
          }
          console.log(JSON.stringify(result));
        """)
        self.assertEqual(result,[{'url':'http://127.0.0.1:11434/v1','readOnly':False,'key':'','required':True},
                                 {'url':'http://127.0.0.1:1234/v1','readOnly':False,'key':'','required':True}])

    def test_native_anthropic_controls_force_protocol_and_disable_reasoning(self):
        functions=functions_between('providerChanged','analysisOptions')
        result=self.execute("""
          const fields={};const $=(id)=>fields[id] || (fields[id]={value:'',removeAttribute:()=>{}});
          const state={providers:[{id:'anthropic',url:'https://api.anthropic.com/v1',key_env:'ANTHROPIC_API_KEY'}]};
          const modelDefaults={},localDefaults={};const resetModelDiscovery=()=>{},updateProviderLocation=()=>{};
        """+functions+"""
          $('provider').value='anthropic';$('llm-reasoning-effort').value='high';providerChanged();
          const native={format:apiFormat(),locked:$('llm-api-format').disabled,
            reasoningDisabled:$('llm-reasoning-effort').disabled,reasoning:$('llm-reasoning-effort').value,
            jsonMode:$('llm-json-mode').value,jsonModeDisabled:$('llm-json-mode').disabled,
            temperatureMax:$('llm-temperature').max,url:$('llm-url').value};
          $('provider').value='custom';$('llm-api-format').value='anthropic';providerChanged();
          const custom={format:apiFormat(),locked:$('llm-api-format').disabled,reasoningDisabled:$('llm-reasoning-effort').disabled};
          $('llm-api-format').value='openai';updateApiCompatibility();
          console.log(JSON.stringify({native,custom,restoredReasoning:!$('llm-reasoning-effort').disabled}));
        """)
        self.assertEqual(result,{'native':{'format':'anthropic','locked':True,'reasoningDisabled':True,
            'reasoning':'auto','jsonMode':'prompt','jsonModeDisabled':True,'temperatureMax':'1','url':'https://api.anthropic.com/v1'},
            'custom':{'format':'anthropic','locked':False,'reasoningDisabled':True},'restoredReasoning':True})
