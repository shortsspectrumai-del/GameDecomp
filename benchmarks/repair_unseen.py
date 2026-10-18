#!/usr/bin/env python3
"""Final offline audit on unique cases absent from every previous test stream."""
import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from benchmarks.repair_llm import TrustedGameValidator, _digest, _read, _record, _sha
from benchmarks.real_game_differential import function_cases
from gamedecomp.semantic import candidate_is_usable


def _bound_record(report, target, selected_source_sha256):
    """Reject substituted binary/report bodies before compiling or executing."""
    record = _record(report, target)
    candidate = record.get('candidate') or {}
    if type(candidate.get('compile_support', '')) is not str or candidate.get('compile_support', ''):
        raise ValueError('This audit permits no generated compilation support outside the selected source')
    if (report.get('input', {}).get('sha256') != target['binary_sha256'] or
            not isinstance(selected_source_sha256, str) or len(selected_source_sha256) != 64 or
            candidate.get('source_sha256') != selected_source_sha256 or
            not isinstance(candidate.get('source'), str) or
            _sha(candidate['source']) != selected_source_sha256):
        raise ValueError('Selected candidate or input binary identity changed')
    return record


def _excluded_streams(seed, exclude_seeds):
    """Declare every prior stream; reject invalid or self-excluding seeds early."""
    if type(seed) is not int or not 0 <= seed < 2**64:
        raise ValueError('Audit seed must be an unsigned 64-bit integer')
    if not isinstance(exclude_seeds, (tuple, list)):
        raise ValueError('Excluded seeds must be a sequence of unsigned 64-bit integers')
    streams = [{'seed': 2048, 'random_cases': 128},
               {'seed': 2048, 'random_cases': 4096},
               {'seed': 5741, 'random_cases': 4096}]
    seen = {2048, 5741}
    for excluded in exclude_seeds:
        if type(excluded) is not int or not 0 <= excluded < 2**64:
            raise ValueError('Excluded seed must be an unsigned 64-bit integer')
        if excluded not in seen:
            streams.append({'seed': excluded, 'random_cases': 4096})
            seen.add(excluded)
    if seed in seen:
        raise ValueError('Audit seed cannot be an excluded prior seed')
    return streams


def run(experiment, seeded, output, *, seed=89123, exclude_seeds=()):
    excluded_streams = _excluded_streams(seed, exclude_seeds)
    experiment, seeded, output = map(lambda p: Path(p).resolve(), (experiment, seeded, output))
    if output.exists():
        raise ValueError('Output must be new')
    plan, verified = _read(experiment / 'plan.json'), _read(experiment / 'verification.json')
    if _digest(experiment / 'plan.json') != verified['plan_sha256']:
        raise ValueError('Experiment plan changed')
    seeded_result = _read(seeded / 'verification.json')
    if seeded_result['plan_sha256'] != verified['plan_sha256']:
        raise ValueError('Seeded challenge and experiment plans differ')
    target_rows, selected_rows = plan['targets'], verified['results']
    if (type(target_rows) is not list or type(selected_rows) is not list or
            not target_rows or len(selected_rows) != len(target_rows)):
        raise ValueError('Selected target set incomplete or ambiguous')
    target_pairs = [(row['variant'], row['function']) for row in target_rows]
    selected_pairs = [(row['variant'], row['function']) for row in selected_rows]
    if (len(set(target_pairs)) != len(target_pairs) or
            len(set(selected_pairs)) != len(selected_pairs) or set(selected_pairs) != set(target_pairs)):
        raise ValueError('Selected target set incomplete or ambiguous')
    selected = {pair: row['candidate_source_sha256'] for pair, row in zip(selected_pairs, selected_rows)}
    output.mkdir(parents=True)
    hashes = {}
    for path in sorted([*ROOT.glob('gamedecomp/**/*.py'), *ROOT.glob('benchmarks/*.py')]):
        relative = path.relative_to(ROOT)
        destination = output / 'executed-code' / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(path.read_bytes())
        hashes[str(relative)] = _digest(destination)
    (output / 'executed-code-sha256.json').write_text(json.dumps(hashes, indent=2) + '\n')
    results = []
    for target in plan['targets']:
        name = target['function']
        seen = [case for stream in excluded_streams
                for case in function_cases(name, random_cases=stream['random_cases'], seed=stream['seed'])]
        sources = [('refined', experiment / (target['variant'] + '-' + name) / 'analysis/report.json')]
        if name == 'findTarget':
            sources += [('historical', Path(target['previous_analysis_report'])),
                        ('seeded_repair', seeded / 'analysis/report.json')]
        for label, path in sources:
            if label == 'historical':
                if _digest(path) != target['previous_analysis_report_sha256']:
                    raise ValueError('Historical report changed')
                expected = seeded_result['historical_source_sha256']
            elif label == 'seeded_repair':
                expected = seeded_result['heldout']['candidate_source_sha256']
            else:
                expected = selected[(target['variant'], name)]
            record = _bound_record(_read(path), target, expected)
            candidate = record.get('candidate') or {}
            row = {'origin': label, 'function': name, 'variant': target['variant'],
                   'analysis_report_sha256': _digest(path), 'provider_calls': 0}
            if not candidate_is_usable(candidate):
                row['validation'] = {'status': 'UNKNOWN', 'cases_checked': 0, 'mismatches': 0,
                                     'reason': 'Candidate not eligible; no fallback or provider call'}
            else:
                validator = TrustedGameValidator(target, plan['provenance'][target['group']],
                    output / (label + '-' + name), random_cases=4096, seed=seed,
                    scope='heldout', exclude_cases=seen)
                observed = {json.dumps(case, sort_keys=True) for case in seen}
                if any(json.dumps(case, sort_keys=True) in observed for case in validator.cases):
                    raise ValueError('Seen input leaked into final unseen audit')
                row['validation'] = validator.evaluate(record, candidate, timeout=150, probe=label == 'historical')
            results.append(row)
    result = {'experiment': 'Final unique unseen-input audit', 'random_seed': seed,
              'excluded_streams': excluded_streams,
              'provider_calls': 0, 'results': results,
              'limitation': 'Finite tests after candidate selection; no universal proof. Shared cases across candidates are not independent samples. Generated compilation support must be absent or an empty string.'}
    (output / 'verification.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps([{'origin': row['origin'], 'function': row['function'],
                      'status': row['validation']['status'], 'cases': row['validation']['cases_checked'],
                      'mismatches': row['validation']['mismatches']} for row in results], indent=2))
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--trusted', action='store_true', required=True)
    parser.add_argument('--experiment', type=Path, required=True)
    parser.add_argument('--seeded', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--seed', type=int, default=89123,
                        help='Fresh audit stream seed (legacy default: 89123)')
    parser.add_argument('--exclude-seed', type=int, action='append', default=[],
                        help='Additional prior 4096-random-case stream to exclude; repeatable')
    args = parser.parse_args()
    run(args.experiment, args.seeded, args.output, seed=args.seed, exclude_seeds=args.exclude_seed)
