#!/usr/bin/env python3
"""Controlled historical-error challenge; not an independent generation benchmark.

Inject the exact historical wrong body as the first candidate without an API
call. All later completions use the real provider and normal production pipeline.
Original source stays inside the trusted evaluator. Held-out results are final.
"""
import argparse
import getpass
import json
from pathlib import Path
import sys
import time
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from benchmarks.repair_llm import (
    TrustedGameValidator, _digest, _historical_replay, _read, _record, _select_model, _usage_summary,
)
from gamedecomp.llm import LLMClient
from gamedecomp.pipeline import AnalysisConfig, run_analysis
from gamedecomp.semantic import candidate_is_usable


def run(plan_path, output, ghidra_home, *, key=None, model='auto'):
    output = Path(output).resolve()
    if output.exists():
        raise ValueError('Output must be new')
    plan = _read(plan_path)
    target = plan['targets'][0]
    if target['function'] != 'findTarget':
        raise ValueError('Expected the predeclared historical findTarget target')
    if _digest(target['previous_analysis_report']) != target['previous_analysis_report_sha256']:
        raise ValueError('Historical report changed')
    historical = _record(_read(target['previous_analysis_report']), target)['candidate']
    output.mkdir(parents=True)
    hashes = {}
    for path in sorted([*ROOT.glob('gamedecomp/**/*.py'), *ROOT.glob('benchmarks/*.py')]):
        relative = path.relative_to(ROOT)
        destination = output / 'executed-code' / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(path.read_bytes())
        hashes[str(relative)] = _digest(destination)
    (output / 'executed-code-sha256.json').write_text(json.dumps(hashes, indent=2) + '\n')
    replay = _historical_replay(target, plan['provenance'][target['group']], output / 'replay')
    if replay['status'] != 'DISPROVED':
        raise ValueError('Historical error did not reproduce; challenge aborted before provider calls')
    if key is None:
        key = getpass.getpass('DeepSeek API key (memory only, no echo): ')
    model = _select_model(model, key)
    provenance = plan['provenance'][target['group']]
    validator = TrustedGameValidator(target, provenance, output / 'training', scope='training')
    original_refine = LLMClient.refine
    calls = []

    def refine(client, source, context, feedback=None, **options):
        if not calls:
            calls.append({'origin': 'injected_historical_error', 'provider_call': False})
            ids = {item['id'] for item in context['evidence']}
            return {'source': historical['source'],
                    'evidence_ids': [item for item in historical['evidence_ids'] if item in ids],
                    'assumptions': [],
                    'usage': {'prompt_tokens': 0, 'completion_tokens': 0, 'total_tokens': 0}}
        calls.append({'origin': 'live_provider_completion', 'provider_call': True,
                      'counterexample_feedback_present': any('counterexample' in item.lower()
                                                            for item in (feedback or []))})
        return original_refine(client, source, context, feedback, **options)

    started = time.monotonic()
    # Process-local, single-analysis injection; production behavior stays unchanged.
    with patch.object(LLMClient, 'refine', refine):
        report = run_analysis(Path(target['binary']), output / 'analysis', AnalysisConfig(
            backend='ghidra', ghidra_home=ghidra_home, cache_path=Path(target['cache']),
            function_pattern=target['observed_name'], llm_endpoint='https://api.deepseek.com',
            llm_model=model, llm_api_key=key, llm_attempts=4, llm_max_output_tokens=16384,
            llm_reasoning_effort='low', llm_context_bytes=131072, timeout=600, phase_timeout=150),
            candidate_validator=validator)
    record = _record(report, target)
    candidate = record.get('candidate') or {}
    heldout = None
    if candidate_is_usable(candidate) and candidate.get('semantic_status') == 'TESTED':
        evaluator = TrustedGameValidator(target, provenance, output / 'heldout',
                                        random_cases=4096, seed=5741, scope='heldout')
        heldout = evaluator.evaluate(record, candidate, timeout=150, probe=False)
    result = {'experiment': 'Controlled historical-error injection followed by real LLM repair',
              'model': model, 'plan_sha256': _digest(plan_path),
              'historical_source_sha256': historical['source_sha256'],
              'calls': calls, 'attempts': record['ai_attempts'], 'training_history': validator.history,
              'heldout': heldout, 'elapsed_seconds': time.monotonic() - started,
              'usage': _usage_summary([{'status': 'COMPLETE', 'attempts': record['ai_attempts']}]),
              'api_key_persisted': False,
              'limitation': 'Known-error controlled challenge, finite tests; not independent generalization or equivalence proof'}
    encoded = json.dumps(result, indent=2)
    if key in encoded or any(key.encode() in path.read_bytes() for path in output.rglob('*') if path.is_file()):
        raise RuntimeError('Credential redaction failed')
    (output / 'verification.json').write_text(encoded + '\n')
    print('Controlled repair result: ' + str(heldout and heldout['status']), flush=True)
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--trusted', action='store_true', required=True)
    parser.add_argument('--plan', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--ghidra-home', type=Path, required=True)
    args = parser.parse_args()
    try:
        run(args.plan, args.output, args.ghidra_home)
    except Exception as error:
        print('Controlled repair failed: ' + type(error).__name__, file=sys.stderr)
        raise SystemExit(2)
