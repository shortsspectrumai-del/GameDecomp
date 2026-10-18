#!/usr/bin/env python3
"""Recheck immutable API-generated bodies after an ABI-validator update.

No provider requests. Historical reports and failed compilations remain intact.
Only the pinned trusted game may be executed by the separate evaluator.
"""
import argparse
import copy
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from benchmarks.llm_real_game import FILES, mapped_symbol_addresses, evaluate_report
from gamedecomp import __version__
from gamedecomp.ai_engine import abi_assertion, recovery_context, recovery_issues, validator_contract, abi_check_kind
from gamedecomp.evidence import candidate_issues
from gamedecomp.pipeline import _compilation_source
from gamedecomp.project_export import export_project
from gamedecomp.validation import compile_source


def run(previous, normal, stress, output):
    if output.exists():
        raise ValueError('Output must be new')
    manifests = [json.loads(path.read_text()) for path in (normal, stress)]
    historical = json.loads((previous/'verification.json').read_text())
    output.mkdir(parents=True)
    rows = []
    for old in historical['results']:
        matches = [(path,manifest) for path,manifest in zip((normal,stress),manifests)
                   if any(build['variant']==old['variant'] for build in manifest['builds'])]
        if len(matches)!=1:
            raise ValueError('Variant absent or ambiguous in evaluator manifests')
        manifest_path,manifest = matches[0]
        source = manifest_path.parent/'source/2048.c'
        if hashlib.sha256(source.read_bytes()).hexdigest()!=FILES['2048.c']:
            raise ValueError('Original source changed')
        build = next(x for x in manifest['builds'] if x['variant']==old['variant'])
        binary = Path(build['binary'])
        if hashlib.sha256(binary.read_bytes()).hexdigest()!=build['binary_sha256']:
            raise ValueError('Binary changed')
        label = old['variant']+'-'+old['function']
        prior_path = previous/label/'analysis/report.json'
        prior = json.loads(prior_path.read_text())
        record = copy.deepcopy(prior['functions'][0])
        candidate = record['candidate']
        if (hashlib.sha256(record['source'].encode()).hexdigest()!=candidate['baseline_sha256'] or
            hashlib.sha256(candidate['source'].encode()).hexdigest()!=candidate['source_sha256']):
            raise ValueError('Immutable candidate changed')
        language = record['metadata'].get('language', 'c')
        contract = validator_contract(record['source'], record['metadata'], record['name'], language)
        context, _ = recovery_context(record['context'],record['compilation'],record.get('compatibility'),
            budget=(record.get('ai_context') or {}).get('budget_bytes',196608),support=candidate.get('compile_support',''),contract=contract)
        issues = candidate_issues(candidate['source'],context,candidate['evidence_ids'])
        issues += recovery_issues(candidate.get('recovery'),context)
        if issues:
            raise ValueError('Candidate rejected by strict evidence gate: '+'; '.join(issues))
        unit, _ = _compilation_source(candidate['source'],record['metadata'],prior['backend'])
        assertion = abi_assertion(record['source'],record['metadata'].get('export_name') or record['name'],language,candidate=candidate['source'])
        if not assertion:
            raise ValueError('ABI check unavailable')
        unit = candidate.get('compile_support','')+'\n'+unit+assertion
        candidate['prior_compilation'] = candidate['compilation']
        candidate['compilation'] = compile_source(unit,compiler=build.get('compiler_path'),language=language,strict=True)
        candidate['compilation'].update(abi_check=abi_check_kind(record['source'],contract['symbol'],language,candidate=candidate['source']),unit_sha256=hashlib.sha256(unit.encode()).hexdigest())
        record['post_generation_validation'] = {'historical_report':str(prior_path),
            'historical_report_sha256':hashlib.sha256(prior_path.read_bytes()).hexdigest(),
            'reason':'Strict lexical/evidence gate, fail-closed ABI shape and targeted uninitialized/missing-return diagnostics',
            'api_calls':0,'source_changed':False,'semantic_status':'UNKNOWN'}
        folder = output/label; folder.mkdir()
        (folder/'candidate.unit.c').write_text(unit)
        (folder/'candidate.c').write_text(candidate['source'])
        report = copy.deepcopy(prior);report['functions']=[record];report['program_version']=__version__
        (folder/'report.json').write_text(json.dumps(report,indent=2)+'\n')
        metadata = dict(record['metadata'])
        metadata['compile_preamble'] = candidate.get('compile_support','')+'\n'+metadata.get('compile_preamble','')
        project = export_project(dict(report,functions=[dict(record,source=candidate['source'],
            compilation=candidate['compilation'],metadata=metadata)]),folder)
        project['origin']='Unchanged LLM hypothesis after ABI-validator update; not equivalence proof'
        (folder/'project/manifest.json').write_text(json.dumps(project,indent=2)+'\n')
        readme=folder/'project/README.md'
        readme.write_text(readme.read_text().replace('baseline compilabili','ricostruzioni LLM compilabili'))
        merged = json.loads(Path(build['runs'][0]['report']).read_text())
        merged['functions']=[record if x['address']==record['address'] else x for x in merged['functions']]
        merged_path=folder/'evaluation-report.json';merged_path.write_text(json.dumps(merged,indent=2)+'\n')
        addresses,_=mapped_symbol_addresses(binary,merged,(binary.parent/'symbols-ground-truth.txt').read_text(),set(manifest['authored_functions']))
        verification=evaluate_report(source,merged_path,addresses,folder/'differential',
            compiler=build.get('compiler_path') or 'gcc',random_cases=1024,compatibility=True,use_ai=True)
        row=next(x for x in verification['functions'] if x['function']==old['function'])
        selection=next((x.get('source_selection') for x in row.get('artifacts',[])
                        if x.get('original_function')==old['function']),None)
        target_used=selection=='llm_reconstruction' and row.get('tested_cases',0)>0
        rows.append({'variant':old['variant'],'function':old['function'],'model':historical['model'],
            'llm_used':target_used,'llm_target_used':target_used,'target_source_selection':selection,
            'llm_dependency_functions':[x['original_function'] for x in row.get('artifacts',[])
                if x.get('source_selection')=='llm_reconstruction' and x.get('original_function')!=old['function']],
            'status':row['status'],'tested_cases':row.get('tested_cases',0),'mismatches':row.get('mismatches',0),
            'source_sha256':candidate['source_sha256'],'compilation':candidate['compilation'],
            'verification':str(folder/'differential/verification.json')})
    result={'results':rows,'api_calls':0,'sources_changed':False,
        'program_version':__version__, 'strict_candidate_checks':True,
        'scope':'Three evaluator-selected targets; finite comparisons, not universal equivalence or discovery benchmark',
        'summary':{'targets':len(rows),'llm_targets_matched':sum(x['llm_used'] and x['status']=='MATCHED_FINITE_CASES' for x in rows),
            'tested_cases':sum(x['tested_cases'] for x in rows),'mismatches':sum(x['mismatches'] for x in rows)}}
    (output/'verification.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result['summary']),flush=True)
    return result


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--trusted',action='store_true')
    for name in ('previous','normal','stress','output'):
        parser.add_argument('--'+name,type=Path,required=True)
    args=parser.parse_args()
    if not args.trusted:parser.error('--trusted required to execute pinned original and recovered code')
    run(args.previous,args.normal,args.stress,args.output)
