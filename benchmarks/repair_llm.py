#!/usr/bin/env python3
"""Trusted finite-counterexample LLM repair benchmark for the pinned 2048 game.

Original source is evaluator-only. Callback feedback contains at most one
observed counterexample; held-out observations are never sent to the model.
"""
import argparse
from collections import Counter
import copy
import getpass
import hashlib
import json
import math
from pathlib import Path
import re
import shutil
import sys
import threading
import time
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from benchmarks.real_game import FILES, mapped_symbol_addresses
from benchmarks.real_game_differential import (
    _command, _compile_closure, check_original_signatures, function_cases,
)
from gamedecomp import __version__
from gamedecomp.llm import _NoRedirect
from gamedecomp.pipeline import AnalysisConfig, run_analysis
from gamedecomp.semantic import candidate_is_usable

REPAIR_TARGETS = (
    ('clang-O2-debug', 'findTarget'),
    ('clang-O2-stripped', 'getDigitCount'),
    ('gcc-O2-stripped', 'moveRight'),
    ('gcc-O0-stripped', 'countEmpty'),
)


def _sha(value):
    return hashlib.sha256(value if isinstance(value, bytes) else value.encode()).hexdigest()


def _digest(path):
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise ValueError('Expected a regular provenance file')
    return _sha(path.read_bytes())


def _read(path):
    _digest(path)
    return json.loads(Path(path).read_text())


def _record(report, target):
    items = [row for row in report['functions'] if row['address'] == target['address']
             and row['name'] == target['observed_name']]
    if len(items) != 1:
        raise ValueError('Target observed identity is missing or ambiguous')
    return items[0]


def _verify_inputs(target, provenance):
    checks = ((provenance['manifest'], provenance['manifest_sha256']),
              (provenance['source'], FILES['2048.c']),
              (Path(provenance['source']).parent / 'LICENSE', FILES['LICENSE']),
              (target['binary'], target['binary_sha256']),
              (target['baseline_report'], target['baseline_report_sha256']),
              (target['symbols'], target['symbols_sha256']))
    for path, expected in checks:
        if _digest(path) != expected:
            raise ValueError('Pinned evaluator provenance changed')
    baseline = _read(target['baseline_report'])
    if baseline.get('input', {}).get('sha256') != target['binary_sha256']:
        raise ValueError('Baseline report and binary differ')
    _record(baseline, target)
    return baseline


def _remaining(deadline, cap=15):
    remaining = min(cap, deadline - time.monotonic())
    if remaining <= 0:
        raise TimeoutError('Trusted finite validation deadline exceeded')
    return remaining


# _compile_closure keeps its normal 30-second command limit. This executable
# compiler proxy bounds each real compiler/link process by the shared deadline
# and kills its process group before returning. No shared globals are patched.
_COMPILER_PROXY = '''#!{python}
import json, os, signal, subprocess, sys, time
from pathlib import Path
settings=json.loads(Path(__file__).with_suffix('.json').read_text())
remaining=min(20.0,settings['deadline']-time.monotonic())
if remaining<=0:raise SystemExit(124)
process=subprocess.Popen([settings['compiler'],*sys.argv[1:]],start_new_session=True)
try:
    raise SystemExit(process.wait(timeout=remaining))
except subprocess.TimeoutExpired:
    try:os.killpg(process.pid,signal.SIGKILL)
    except ProcessLookupError:pass
    process.wait()
    raise SystemExit(124)
'''


class TrustedGameValidator:
    """Synchronous callback for a single sealed target; finite tests, not proof."""
    def __init__(self, target, provenance, output, *, random_cases=128, seed=2048, scope='training', exclude_cases=None):
        if scope not in ('training', 'heldout', 'replay'):
            raise ValueError('Unsupported trusted validation scope')
        self.target, self.provenance = copy.deepcopy(target), copy.deepcopy(provenance)
        self.output = Path(output).resolve()
        self.cases = function_cases(target['function'], random_cases=random_cases, seed=seed)
        if exclude_cases is not None:
            if scope != 'heldout' or not isinstance(exclude_cases, list):
                raise ValueError('Case exclusion requires an explicit heldout case list')
            excluded = {json.dumps(case, sort_keys=True) for case in exclude_cases}
            unique = {}
            for case in self.cases:
                identity = json.dumps(case, sort_keys=True)
                if identity not in excluded:
                    unique[identity] = case
            self.cases = list(unique.values())
            if not self.cases:
                raise ValueError('No unseen heldout cases remain')
        self.seed, self.random_cases, self.scope = seed, random_cases, scope
        self.case_hash = _sha(json.dumps(self.cases, sort_keys=True))
        self.baseline = _verify_inputs(self.target, self.provenance)
        check_original_signatures(Path(self.provenance['source']).read_text())
        self.baseline_record = copy.deepcopy(_record(self.baseline, self.target))
        self.compiler = shutil.which(str(target['compiler']))
        if not self.compiler:
            raise ValueError('Trusted evaluator compiler unavailable')
        manifest = _read(self.provenance['manifest'])
        addresses, _ = mapped_symbol_addresses(Path(self.target['binary']), self.baseline,
            Path(self.target['symbols']).read_text(), set(manifest['authored_functions']))
        originals = {address: name for name, address in addresses.items()}
        self.mapping = {row['name']: originals[row['address']] for row in self.baseline['functions']
                        if row['address'] in originals}
        self.mapping[self.target['observed_name']] = self.target['function']
        if any(not re.fullmatch(r'[A-Za-z_]\w*', name, re.ASCII)
               for pair in self.mapping.items() for name in pair):
            raise ValueError('Unsupported observed symbol identity')
        self._lock = threading.Lock()
        self._calls = 0
        self.history = []
        if self.output.exists():
            raise ValueError('Validator output must be new')
        self.output.mkdir(parents=True)

    def __call__(self, function, candidate, *, timeout):
        return self.evaluate(function, candidate, timeout=timeout, probe=True)

    def evaluate(self, function, candidate, *, timeout, probe=True):
        started = time.monotonic()
        source = candidate.get('source') if isinstance(candidate, dict) else None
        source_hash = _sha(source) if isinstance(source, str) else _sha('')
        result = {'status': 'UNKNOWN', 'candidate_source_sha256': source_hash,
                  'cases_checked': 0, 'mismatches': 0,
                  'scope': 'Trusted pinned 2048.c minimal AI-only ' + self.scope +
                           ' finite comparisons; no universal semantic equivalence.',
                  'cases_sha256': self.case_hash, 'random_seed': self.seed}
        folder, audit = None, {}
        try:
            if (isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or
                    not math.isfinite(timeout) or timeout <= 0):
                raise ValueError('Invalid total validation timeout')
            deadline = started + timeout
            _verify_inputs(self.target, self.provenance)
            _remaining(deadline)
            if (not isinstance(function, dict) or function.get('address') != self.target['address'] or
                    function.get('name') != self.target['observed_name'] or
                    _sha(function.get('source') or '') != _sha(self.baseline_record.get('source') or '')):
                raise ValueError('Callback target differs from sealed immutable baseline')
            if (not isinstance(source, str) or len(source.encode()) > 131072 or
                    source_hash != candidate.get('source_sha256') or
                    candidate.get('baseline_sha256') != _sha(self.baseline_record.get('source') or '') or
                    candidate.get('compilation', {}).get('status') != 'COMPILED' or
                    candidate['compilation'].get('abi_check') not in ('COMPILER_ABI_SHAPE', 'COMPILER_TYPE_IDENTITY') or
                    (not probe and not candidate_is_usable(candidate))):
                raise ValueError('Candidate source, immutable baseline or ABI binding invalid')
            # Executable metadata/preamble comes from the sealed baseline, not
            # mutable callback metadata. Only the actual generated body/support
            # and its already-checked compilation record are attached.
            record = copy.deepcopy(self.baseline_record)
            record['candidate'] = copy.deepcopy(candidate)
            with self._lock:
                self._calls += 1
                folder = self.output / (f'{self._calls:02d}-' + source_hash[:16])
                folder.mkdir()
            proxy = folder / 'bounded-compiler'
            proxy.write_text(_COMPILER_PROXY.format(python=sys.executable))
            proxy.with_suffix('.json').write_text(json.dumps({'compiler': self.compiler, 'deadline': deadline}))
            proxy.chmod(0o700)
            _remaining(deadline)
            compilation = _compile_closure({'records': {self.target['function']: record},
                'identity_mapping': self.mapping}, str(proxy), folder / 'ai-unit',
                compatibility=False, use_ai=True, validation_probe=probe)
            audit['unit_compilation'] = compilation
            _remaining(deadline)
            artifacts = compilation.get('artifacts', [])
            label = 'llm_validation_probe' if probe else 'llm_reconstruction'
            if (len(artifacts) != 1 or artifacts[0].get('source_selection') != label or
                    artifacts[0].get('original_function') != self.target['function'] or
                    artifacts[0].get('source_sha256') != source_hash):
                raise ValueError('Trusted probe body attribution failed')
            if compilation['status'] != 'AVAILABLE':
                result['reason'] = 'Minimal AI-only unit did not compile/link; no game helper or baseline body added'
            else:
                original = folder / 'original.so'
                oracle_compile = _command([self.compiler, '-std=c11', '-O0', '-fPIC', '-shared', '-Wl,-Bsymbolic',
                    self.provenance['source'], '-o', original], timeout=_remaining(deadline))
                audit['oracle_compile'] = oracle_compile
                _remaining(deadline)
                if oracle_compile['returncode'] or oracle_compile['timed_out']:
                    result['reason'] = 'Separate original oracle compilation unavailable'
                else:
                    job_path = folder / 'worker-input.json'
                    job_path.write_text(json.dumps({'function': self.target['function'],
                        'original_library': str(original), 'recovered_library': compilation['library'],
                        'cases': self.cases}, indent=2) + '\n')
                    process = _command([sys.executable, ROOT / 'benchmarks/real_game_differential.py',
                        '--trusted', '--worker', job_path], timeout=_remaining(deadline))
                    audit['worker'] = process
                    _remaining(deadline)
                    if process['returncode'] or process['timed_out']:
                        result['reason'] = 'Finite observation worker failed or exceeded total deadline'
                    else:
                        comparison = json.loads(process['stdout'])
                        count, mismatches = comparison.get('tested_cases'), comparison.get('mismatches')
                        if (type(count) is not int or count != len(self.cases) or
                                type(mismatches) is not int or not 0 <= mismatches <= count or
                                comparison.get('status') != ('MISMATCH' if mismatches else 'MATCHED_FINITE_CASES')):
                            raise ValueError('Incomplete finite comparison result')
                        result.update(status='DISPROVED' if mismatches else 'TESTED',
                                      cases_checked=count, mismatches=mismatches)
                        if mismatches:
                            examples = comparison.get('mismatch_examples')
                            if not isinstance(examples, list) or not examples or not isinstance(examples[0], dict):
                                raise ValueError('Finite counterexample missing')
                            example = examples[0]
                            if len(json.dumps(example).encode()) > 8192:
                                raise ValueError('Counterexample exceeds feedback budget')
                            result['counterexample'] = example
        except Exception as error:
            result.update(status='UNKNOWN', cases_checked=0, mismatches=0,
                          reason='Trusted finite comparison unavailable', error_type=type(error).__name__)
            result.pop('counterexample', None)
        result['elapsed_seconds'] = time.monotonic() - started
        if folder:
            (folder / 'verification.json').write_text(json.dumps(dict(result, **audit), indent=2) + '\n')
            result['verification'] = str(folder / 'verification.json')
        with self._lock:
            self.history.append(copy.deepcopy(result))
        return result


def build_repair_plan(plan_path, previous, *, target_limit=4):
    if type(target_limit) is not int or not 1 <= target_limit <= 4:
        raise ValueError('target_limit must be an integer from 1 to 4')
    plan_path, previous = Path(plan_path).resolve(), Path(previous).resolve()
    if previous.is_dir():
        previous = previous / 'verification.json'
    expanded, historical = _read(plan_path), _read(previous)
    if (expanded.get('profile') != 'expanded' or historical.get('profile') != 'expanded' or
            len(expanded['targets']) != 22 or len(historical['results']) != 22 or
            historical.get('plan_sha256') != _digest(plan_path) or
            historical.get('api_key_persisted') is not False):
        raise ValueError('An immutable expanded plan and all 22 final results are required')
    targets = {(row['variant'], row['function']): row for row in expanded['targets']}
    results = {(row['variant'], row['function']): row for row in historical['results']}
    if len(targets) != 22 or set(targets) != set(results) or len(results) != 22:
        raise ValueError('Expanded target set mismatch')
    selected = []
    for pair in REPAIR_TARGETS[:target_limit]:
        if pair not in targets:
            raise ValueError('Fixed repair target unavailable')
        target = copy.deepcopy(targets[pair])
        _verify_inputs(target, expanded['provenance'][target['group']])
        prior = results[pair]
        default_report = previous.parent / (pair[0] + '-' + pair[1]) / 'analysis/report.json'
        prior_path = Path(prior.get('analysis_report') or default_report).resolve()
        target.update(previous_status=prior['status'], previous_analysis_report=str(prior_path),
                      previous_analysis_report_sha256=_digest(prior_path) if prior_path.exists() else None)
        selected.append(target)
    return {'schema_version': 1, 'program_version': __version__, 'experiment': 'trusted finite-counterexample LLM repair',
            'expanded_plan': str(plan_path), 'expanded_plan_sha256': _digest(plan_path),
            'previous_verification': str(previous), 'previous_verification_sha256': _digest(previous),
            'selection': 'Four predeclared previously problematic targets, in fixed order; bounded prefix only',
            'targets': selected, 'provenance': expanded['provenance'],
            'training': {'random_seed': 2048, 'random_cases': 128, 'finite_and_boundary_cases': True,
                         'feedback': 'At most one observed counterexample per disproved candidate; no source/oracle implementation'},
            'heldout': {'random_seed': 5741, 'random_cases': 4096, 'finite_and_boundary_cases': True,
                        'feedback': 'Never supplied to the model; evaluated only after candidate selection'},
            'limits': {'attempts_per_target': 3, 'analysis_timeout_seconds': 600,
                       'phase_timeout_seconds': 150, 'max_output_tokens': 16384},
            'limitations': ['Trusted pinned-source oracle benchmark only; callback does not authorize arbitrary uploaded program execution.',
                            'Random streams differ; deterministic exhaustive/boundary cases intentionally overlap training and held-out.',
                            'These are targeted repairs after a diagnostic experiment, not independent generalization or SOTA evidence.',
                            'Finite tests do not prove equivalence; minimal AI units requiring missing external game helpers remain UNKNOWN.']}


def _select_model(model, key):
    request = urllib.request.Request('https://api.deepseek.com/models', headers={'Authorization': 'Bearer ' + key})
    try:
        with urllib.request.build_opener(_NoRedirect()).open(request, timeout=30) as response:
            raw = response.read(1048577)
        if len(raw) > 1048576:
            raise ValueError('Provider model list exceeds budget')
        data = json.loads(raw)
        available = [item['id'] for item in data['data']
                     if isinstance(item, dict) and isinstance(item.get('id'), str)]
    except urllib.error.HTTPError as error:
        status = error.code
        error.close()
        raise RuntimeError(f'DeepSeek model discovery HTTP {status}') from None
    except Exception:
        raise RuntimeError('Provider model discovery unavailable') from None
    if model == 'auto':
        model = next((item for item in ('deepseek-flash', 'deepseek-chat', 'deepseek-v4-pro', 'deepseek-reasoner')
                      if item in available), None)
    if model not in available:
        raise ValueError('Requested supported model unavailable')
    return model


def _historical_replay(target, provenance, folder):
    """Replay immutable prior body; this is explicitly zero new generation."""
    path = Path(target['previous_analysis_report'])
    if not target.get('previous_analysis_report_sha256'):
        return {'status': 'UNKNOWN', 'api_calls': 0, 'new_generation': False,
                'reason': 'Historical analysis body unavailable'}
    if _digest(path) != target['previous_analysis_report_sha256']:
        raise ValueError('Historical analysis report changed')
    report = _read(path)
    if len(report['functions']) != 1 or report.get('input', {}).get('sha256') != target['binary_sha256']:
        raise ValueError('Historical report target identity mismatch')
    record = _record(report, target)
    candidate = record.get('candidate') or {}
    if candidate.get('compilation', {}).get('status') != 'COMPILED':
        return {'status': 'UNKNOWN', 'api_calls': 0, 'new_generation': False,
                'reason': 'Historical body was not compiled'}
    validator = TrustedGameValidator(target, provenance, folder, scope='replay')
    result = validator(record, candidate, timeout=30)
    return dict(result, api_calls=0, new_generation=False,
                historical_report=str(path), historical_report_sha256=_digest(path))


def _summary(results, planned):
    heldout = [row['heldout'] for row in results if row.get('heldout')]
    return {'planned_targets': planned, 'completed_targets': len(results),
            'status_counts': dict(Counter(row['status'] for row in results)),
            'selected_training_tested': sum(row.get('training_status') == 'TESTED' for row in results),
            'heldout_tested_targets': sum(row['status'] == 'TESTED' for row in heldout),
            'heldout_disproved_targets': sum(row['status'] == 'DISPROVED' for row in heldout),
            'heldout_cases_checked': sum(row.get('cases_checked', 0) for row in heldout),
            'heldout_mismatches': sum(row.get('mismatches', 0) for row in heldout),
            'live_semantic_disproofs': sum(attempt.get('semantic_validation', {}).get('status') == 'DISPROVED'
                                           for row in results for attempt in row.get('attempts', []))}


def _usage_summary(results):
    """Sum every recorded completion, including rejected/truncated attempts."""
    attempts = [attempt for row in results for attempt in row.get('attempts', [])]
    keys = ('prompt_tokens', 'completion_tokens', 'total_tokens')
    totals = {key: sum(attempt.get('usage', {}).get(key, 0) for attempt in attempts)
              for key in keys}
    missing = sum(not all(type(attempt.get('usage', {}).get(key)) is int
                          for key in keys) for attempt in attempts)
    return dict(totals, recorded_attempts=len(attempts), attempts_without_full_usage=missing,
                complete=bool(attempts) and missing == 0 and
                         all(row.get('status') != 'ERROR' for row in results))


def run(plan_path, previous, output, ghidra_home, *, model='auto', key=None, target_limit=4, plan_only=False):
    output = Path(output).resolve()
    if output.exists():
        raise ValueError('Output must be new')
    plan = build_repair_plan(plan_path, previous, target_limit=target_limit)
    output.mkdir(parents=True)
    # Freeze the implementation before any provider call; never rewrite older experiments.
    snapshot = output / 'executed-code'
    hashes = {}
    for path in sorted([*ROOT.glob('gamedecomp/**/*.py'), *ROOT.glob('benchmarks/*.py')]):
        relative = path.relative_to(ROOT)
        destination = snapshot / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(path.read_bytes())
        hashes[str(relative)] = _digest(destination)
    (output / 'executed-code-sha256.json').write_text(json.dumps(hashes, indent=2) + '\n')
    frozen_plan = output / 'plan.json'
    frozen_plan.write_text(json.dumps(plan, indent=2) + '\n')
    plan_hash = _digest(frozen_plan)
    if plan_only:
        return plan
    # This optional immutable-body replay precedes paid generation and never
    # becomes a generated result or gets supplied as source to the model.
    replays = []
    first = plan['targets'][0]
    try:
        replay = _historical_replay(first, plan['provenance'][first['group']], output / 'historical-replay')
    except Exception as error:
        replay = {'status': 'UNKNOWN', 'api_calls': 0, 'new_generation': False, 'error_type': type(error).__name__}
    replays.append(dict(replay, variant=first['variant'], function=first['function']))
    (output / 'historical-replay.json').write_text(json.dumps(replays, indent=2) + '\n')
    if key is None:
        key = getpass.getpass('Chiave DeepSeek (solo memoria, nessuna eco): ')
    if not isinstance(key, str) or not key.strip():
        raise ValueError('API key required')
    model = _select_model(model, key)
    print('Selected provider model: ' + model, flush=True)
    results = []
    for target in plan['targets']:
        label = target['variant'] + '-' + target['function']
        row = {'variant': target['variant'], 'function': target['function'], 'status': 'UNKNOWN',
               'new_generation': True, 'llm_target_selected': False, 'heldout': None}
        started = time.monotonic()
        try:
            if (_digest(frozen_plan) != plan_hash or _digest(plan['expanded_plan']) != plan['expanded_plan_sha256'] or
                    _digest(plan['previous_verification']) != plan['previous_verification_sha256']):
                raise ValueError('Immutable repair experiment inputs changed')
            provenance = plan['provenance'][target['group']]
            _verify_inputs(target, provenance)
            validator = TrustedGameValidator(target, provenance, output / label / 'training', scope='training')
            print(label + ': live LLM generation with trusted finite validator', flush=True)
            report = run_analysis(Path(target['binary']), output / label / 'analysis', AnalysisConfig(
                backend='ghidra', ghidra_home=ghidra_home, cache_path=Path(target['cache']),
                function_pattern=''.join({'[': '[[]', '*': '[*]', '?': '[?]'}.get(c, c) for c in target['observed_name']),
                llm_endpoint='https://api.deepseek.com', llm_model=model, llm_api_key=key,
                llm_attempts=3, llm_max_output_tokens=16384, llm_reasoning_effort='low',
                llm_context_bytes=131072, timeout=600, phase_timeout=150), candidate_validator=validator)
            if len(report['functions']) != 1:
                raise ValueError('Live analysis returned unexpected target count')
            record = _record(report, target)
            if report.get('input', {}).get('sha256') != target['binary_sha256']:
                raise ValueError('Live analysis binary identity changed')
            candidate = record.get('candidate') or {}
            row.update(attempts=record.get('ai_attempts', []), training_history=validator.history,
                       candidate_compilation=candidate.get('compilation'), candidate_usage=candidate.get('usage'),
                       candidate_source_sha256=candidate.get('source_sha256'),
                       training_status=candidate.get('semantic_status'),
                       analysis_report=str(output / label / 'analysis/report.json'))
            if candidate_is_usable(candidate) and candidate.get('semantic_status') == 'TESTED':
                row['llm_target_selected'] = True
                # Independent random stream and immutable candidate; no further
                # LLM request is made with these held-out observations.
                heldout = TrustedGameValidator(target, provenance, output / label / 'heldout',
                    random_cases=4096, seed=5741, scope='heldout')
                result = heldout.evaluate(record, candidate, timeout=150, probe=False)
                row.update(heldout=result, status=result['status'])
            else:
                row.update(status=candidate.get('semantic_status') if candidate.get('semantic_status') in
                           ('DISPROVED', 'UNKNOWN') else 'UNKNOWN',
                           reason='No training-tested eligible AI candidate; no baseline fallback')
        except Exception as error:
            row.update(status='ERROR', error_type=type(error).__name__)
        row['elapsed_seconds'] = time.monotonic() - started
        results.append(row)
        partial = {'program_version': __version__, 'model': model, 'plan_sha256': plan_hash,
                   'replays': replays, 'results': results, 'summary': _summary(results, len(plan['targets'])),
                   'scope': 'Targeted trusted finite-counterexample repair with separate held-out random stream'}
        encoded = json.dumps(partial, indent=2)
        if key in encoded:
            raise RuntimeError('Credential redaction failed')
        (output / 'verification.partial.json').write_text(encoded + '\n')
        print(label + ': ' + row['status'] + ', training selected: ' + str(row['llm_target_selected']), flush=True)
    if any(key.encode() in path.read_bytes() for path in output.rglob('*') if path.is_file()):
        raise RuntimeError('Credential found in artifacts; do not distribute')
    usage = _usage_summary(results)
    result = dict(partial, api_key_persisted=False, limitations=plan['limitations'],
                  usage=usage, usage_complete=usage['complete'],
                  usage_scope='All recorded completion attempts, including rejected outputs; transport failures may lack provider usage')
    (output / 'verification.json').write_text(json.dumps(result, indent=2) + '\n')
    (output / 'verification.partial.json').unlink()
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--trusted', action='store_true')
    parser.add_argument('--plan', type=Path, required=True)
    parser.add_argument('--previous', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--ghidra-home', type=Path)
    parser.add_argument('--model', default='auto')
    parser.add_argument('--target-limit', type=int, default=4)
    parser.add_argument('--plan-only', action='store_true')
    args = parser.parse_args()
    if not args.plan_only and (not args.trusted or not args.ghidra_home):
        parser.error('--trusted and --ghidra-home required for evaluator-only trusted game execution')
    try:
        run(args.plan, args.previous, args.output, args.ghidra_home, model=args.model,
            target_limit=args.target_limit, plan_only=args.plan_only)
    except Exception as error:
        print('Repair benchmark failed: ' + (str(error) if isinstance(error, (ValueError, RuntimeError)) else type(error).__name__), file=sys.stderr)
        raise SystemExit(2)
