#!/usr/bin/env python3
"""Audit selected live LLM candidates on a predeclared independent finite stream.

No provider calls, baseline substitution or feedback to the model occurs here.
Only the pinned trusted 2048 benchmark and selected source-bound bodies execute.
Generated compilation support must be absent or an empty string.
"""
import argparse
from collections import Counter
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from benchmarks.repair_llm import (
    REPAIR_TARGETS, TrustedGameValidator, _digest, _read, _record, _verify_inputs,
    _sha,
)
from benchmarks.repair_unseen import _bound_record
from benchmarks.real_game_differential import function_cases
from gamedecomp import __version__
from gamedecomp.semantic import candidate_is_usable


_EXPECTED_STREAMS = [
    {'seed': 2048, 'random_cases': 128}, {'seed': 2048, 'random_cases': 4096},
    {'seed': 5741, 'random_cases': 4096}, {'seed': 89123, 'random_cases': 4096},
    {'seed': 20261018, 'random_cases': 4096},
]


def _protocol_check(protocol):
    if (type(protocol) is not dict or type(protocol.get('schema_version')) is not int or
            protocol['schema_version'] != 1 or protocol.get('feedback_to_model') is not False or
            type(protocol.get('random_seed')) is not int or protocol['random_seed'] != 20261019 or
            type(protocol.get('random_cases')) is not int or protocol['random_cases'] != 4096 or
            protocol.get('targets') != [list(pair) for pair in REPAIR_TARGETS] or
            protocol.get('excluded_streams') != _EXPECTED_STREAMS):
        raise ValueError('Independent audit protocol differs from the predeclared finite experiment')
    for stream in protocol['excluded_streams']:
        if type(stream.get('seed')) is not int or type(stream.get('random_cases')) is not int:
            raise ValueError('Audit stream fields must be integers')


def _prior_cases(name, protocol):
    return [case for stream in protocol['excluded_streams']
            for case in function_cases(name, random_cases=stream['random_cases'], seed=stream['seed'])]


def _pairs(rows):
    if type(rows) is not list or len(rows) != len(REPAIR_TARGETS):
        raise ValueError('Complete fixed target set required')
    pairs = [(row['variant'], row['function']) for row in rows]
    if len(set(pairs)) != len(REPAIR_TARGETS) or set(pairs) != set(REPAIR_TARGETS):
        raise ValueError('Target identity is incomplete or ambiguous')
    return dict(zip(pairs, rows))


def _summary(rows):
    return {'planned_targets': len(REPAIR_TARGETS), 'completed_targets': len(rows),
            'status_counts': dict(Counter(row['validation']['status'] for row in rows)),
            'cases_checked': sum(row['validation'].get('cases_checked', 0) for row in rows),
            'mismatches': sum(row['validation'].get('mismatches', 0) for row in rows)}


def _bound_json(path):
    """Hash and decode the same regular-file bytes, avoiding separate read identities."""
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise ValueError('Expected a regular provenance file')
    raw = path.read_bytes()
    return json.loads(raw), _sha(raw), raw


def run(experiment, output, audit_plan):
    experiment, output, audit_plan = (Path(path).resolve() for path in (experiment, output, audit_plan))
    if output.exists():
        raise ValueError('Output must be new')
    protocol, protocol_hash, protocol_raw = _bound_json(audit_plan)
    _protocol_check(protocol)
    plan_path, verified_path = experiment/'plan.json', experiment/'verification.json'
    plan, plan_hash, plan_raw = _bound_json(plan_path)
    verified, verification_hash, verification_raw = _bound_json(verified_path)
    if verified.get('plan_sha256') != plan_hash:
        raise ValueError('Live experiment plan changed')
    targets, selected = _pairs(plan['targets']), _pairs(verified['results'])
    output.mkdir(parents=True)
    for name, raw in (('audit-plan.json', protocol_raw), ('source-plan.json', plan_raw),
                      ('source-verification.json', verification_raw)):
        (output/name).write_bytes(raw)
    code_hashes = {}
    for source in sorted([*ROOT.glob('gamedecomp/**/*.py'), *ROOT.glob('benchmarks/*.py')]):
        relative = source.relative_to(ROOT)
        destination = output/'executed-code'/relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(source.read_bytes())
        code_hashes[str(relative)] = _digest(destination)
    (output/'executed-code-sha256.json').write_text(json.dumps(code_hashes, indent=2)+'\n')
    results = []
    result = {'schema_version': 1, 'program_version': __version__,
        'experiment': 'Predeclared independent current-candidate finite audit',
        'source_experiment': str(experiment), 'plan_sha256': plan_hash,
        'source_verification_sha256': verification_hash, 'audit_plan_sha256': protocol_hash,
        'random_seed': protocol['random_seed'], 'random_cases': protocol['random_cases'],
        'excluded_streams': protocol['excluded_streams'], 'provider_calls': 0,
        'feedback_to_model': False, 'new_generation': False, 'results': results,
        'compile_support_policy': 'Absent or empty string only; no generated support outside the bound source.',
        'limitations': ['Finite tests do not establish universal semantic equivalence.',
            'This audit evaluates already selected live candidates; it makes no provider requests.',
            'Unknown and failed targets remain in the fixed four-target denominator.',
            'Generated compilation support must be absent or an empty string.']}
    for pair in REPAIR_TARGETS:
        target, selection = targets[pair], selected[pair]
        row = {'variant': pair[0], 'function': pair[1], 'provider_calls': 0,
               'candidate_source_sha256': selection.get('candidate_source_sha256')}
        try:
            if (_digest(audit_plan) != protocol_hash or _digest(plan_path) != plan_hash or
                    _digest(verified_path) != verification_hash):
                raise ValueError('Immutable audit inputs changed')
            path = experiment/(pair[0]+'-'+pair[1])/'analysis/report.json'
            if selection.get('analysis_report') and Path(selection['analysis_report']).resolve() != path:
                raise ValueError('Selected report path changed')
            report, report_hash, report_raw = _bound_json(path)
            row.update(analysis_report=str(path), analysis_report_sha256=report_hash)
            if report.get('input', {}).get('sha256') != target['binary_sha256']:
                raise ValueError('Selected report binary changed')
            record = _record(report, target)
            candidate = record.get('candidate') or {}
            if candidate:
                record = _bound_record(report, target, selection.get('candidate_source_sha256'))
            elif selection.get('candidate_source_sha256') is not None:
                raise ValueError('Selected candidate body is missing')
            provenance = plan['provenance'][target['group']]
            _verify_inputs(target, provenance)
            if selection.get('status') == 'ERROR':
                row['validation'] = {'status': 'ERROR', 'cases_checked': 0, 'mismatches': 0,
                                     'reason': 'Live generation failed; no fallback'}
            elif not candidate_is_usable(candidate):
                row['validation'] = {'status': 'UNKNOWN', 'cases_checked': 0, 'mismatches': 0,
                                     'reason': 'No eligible selected candidate; no execution or fallback'}
            else:
                prior = _prior_cases(pair[1], protocol)
                validator = TrustedGameValidator(target, provenance, output/(pair[0]+'-'+pair[1]),
                    random_cases=protocol['random_cases'], seed=protocol['random_seed'],
                    scope='heldout', exclude_cases=prior)
                seen = {json.dumps(case, sort_keys=True) for case in prior}
                fresh = [json.dumps(case, sort_keys=True) for case in validator.cases]
                if not fresh or len(fresh) != len(set(fresh)) or seen.intersection(fresh):
                    raise ValueError('Audit cases are duplicated or previously observed')
                row['validation'] = validator.evaluate(record, candidate, timeout=150, probe=False)
            if (_digest(audit_plan) != protocol_hash or _digest(plan_path) != plan_hash or
                    _digest(verified_path) != verification_hash or _digest(path) != report_hash):
                raise ValueError('Immutable audit inputs changed during validation')
        except Exception as error:
            row['validation'] = {'status': 'ERROR', 'cases_checked': 0, 'mismatches': 0,
                                 'reason': 'Independent audit unavailable; no fallback',
                                 'error_type': type(error).__name__}
        results.append(row)
        result['summary'] = _summary(results)
        (output/'verification.partial.json').write_text(json.dumps(result, indent=2)+'\n')
    (output/'verification.json').write_text(json.dumps(result, indent=2)+'\n')
    (output/'verification.partial.json').unlink()
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--trusted', action='store_true', required=True)
    parser.add_argument('--experiment', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--audit-plan', type=Path, required=True)
    args = parser.parse_args()
    result = run(args.experiment, args.output, args.audit_plan)
    print(json.dumps(result['summary'], indent=2))
