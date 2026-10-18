#!/usr/bin/env python3
"""DeepSeek reconstruction benchmark with a separate finite oracle.

The fixed expanded profile samples 22 function/build pairs before inference.
Reads the API key without echo and never supplies original source to the LLM.
"""
import argparse
from collections import Counter
import getpass
import hashlib
import json
from pathlib import Path
import sys
import time
import urllib.request
import urllib.error

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from benchmarks.real_game import FILES, mapped_symbol_addresses
from benchmarks.real_game_differential import SPECS, evaluate_report
from gamedecomp import __version__
from gamedecomp.pipeline import AnalysisConfig, run_analysis
from gamedecomp.llm import _NoRedirect

TARGETED = (
    ('normal', 'clang-O2-debug', 'findTarget'),
    ('stress', 'gcc-O3-pie', 'rotateBoard'),
    ('stress', 'gcc-O3-lto-pie', 'rotateBoard'),
)
# Fixed sampling specification: never filter these pairs using outcomes.
EXPANDED = (
    ('normal', 'gcc-O0-debug', 'getDigitCount'),
    ('normal', 'clang-O2-stripped', 'getDigitCount'),
    ('normal', 'clang-O2-debug', 'findTarget'),
    ('stress', 'gcc-O3-pie', 'findTarget'),
    ('normal', 'gcc-O0-stripped', 'slideArray'),
    ('stress', 'clang-O3-pie', 'slideArray'),
    ('stress', 'gcc-O3-pie', 'rotateBoard'),
    ('stress', 'gcc-O3-lto-pie', 'rotateBoard'),
    ('normal', 'clang-O0-debug', 'moveUp'),
    ('stress', 'gcc-Os-lto-pie', 'moveUp'),
    ('normal', 'gcc-O2-debug', 'moveLeft'),
    ('normal', 'clang-O0-stripped', 'moveLeft'),
    ('normal', 'clang-O2-stripped', 'moveDown'),
    ('stress', 'gcc-O3-pie', 'moveDown'),
    ('normal', 'gcc-O2-stripped', 'moveRight'),
    ('stress', 'clang-O3-pie', 'moveRight'),
    ('normal', 'clang-O0-debug', 'findPairDown'),
    ('stress', 'gcc-Os-lto-pie', 'findPairDown'),
    ('normal', 'clang-O2-debug', 'countEmpty'),
    ('normal', 'gcc-O0-stripped', 'countEmpty'),
    ('stress', 'gcc-O3-pie', 'gameEnded'),
    ('normal', 'clang-O0-stripped', 'gameEnded'),
)


def _digest(path):
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise ValueError('Expected regular provenance file')
    return hashlib.sha256(path.read_bytes()).hexdigest()


def exact_function_pattern(name):
    if not isinstance(name, str) or not name:
        raise ValueError('Observed function name unavailable')
    # Pipeline uses fnmatchcase (whole-string glob), not regular expressions.
    escapes = {'[': '[[]', '*': '[*]', '?': '[?]'}
    return ''.join(escapes.get(character, character) for character in name)


def _exact_record(report, address, name=None):
    records = [item for item in report['functions'] if item['address'] == address
               and (name is None or item['name'] == name)]
    if len(records) != 1:
        raise ValueError('Expected exactly one observed target entry')
    return records[0]


def build_plan(normal, stress, *, profile='targeted', random_cases=1024):
    """Resolve and seal inputs without credentials, network or inference."""
    if type(random_cases) is not int or not 0 <= random_cases <= 4096:
        raise ValueError('random_cases must be an integer from 0 to 4096')
    if profile not in ('targeted', 'expanded'):
        raise ValueError('Unknown benchmark profile')
    paths = {'normal': Path(normal).resolve(), 'stress': Path(stress).resolve()}
    manifests, provenance = {}, {}
    for group, path in paths.items():
        manifest_hash = _digest(path)
        manifests[group] = json.loads(path.read_text())
        source_dir = path.parent / 'source'
        for filename, expected in FILES.items():
            if _digest(source_dir / filename) != expected:
                raise ValueError('Untrusted original source or license')
        provenance[group] = {'manifest': str(path), 'manifest_sha256': manifest_hash,
                             'source': str(source_dir / '2048.c'),
                             'source_sha256': FILES['2048.c'], 'license_sha256': FILES['LICENSE']}
    rows = []
    for group, variant, target in EXPANDED if profile == 'expanded' else TARGETED:
        manifest = manifests[group]
        builds = [item for item in manifest['builds'] if item['variant'] == variant]
        if len(builds) != 1:
            raise ValueError('Required build missing or duplicated')
        build = builds[0]
        binary = Path(build['binary']).resolve()
        if _digest(binary) != build['binary_sha256']:
            raise ValueError('Binary changed')
        report_path = Path(build['runs'][0]['report']).resolve()
        report_hash = _digest(report_path)
        report = json.loads(report_path.read_text())
        symbols = binary.parent / 'symbols-ground-truth.txt'
        symbols_hash = _digest(symbols)
        addresses, _ = mapped_symbol_addresses(binary, report, symbols.read_text(), set(manifest['authored_functions']))
        address = addresses.get(target)
        records = [item for item in report['functions'] if address is not None and item['address'] == address]
        if len(records) > 1:
            raise ValueError('Ambiguous observed target entry')
        record = records[0] if records else None
        rows.append({'group': group, 'variant': variant, 'function': target,
                     'binary': str(binary), 'binary_sha256': build['binary_sha256'],
                     'baseline_report': str(report_path), 'baseline_report_sha256': report_hash,
                     'symbols': str(symbols), 'symbols_sha256': symbols_hash,
                     'compiler': build.get('compiler_path') or 'gcc',
                     'cache': str(paths[group].parent / 'cache' / (variant + '.sqlite')),
                     'address': address, 'observed_name': record['name'] if record else None,
                     'entry_status': 'AVAILABLE' if record else 'NOT_DISCOVERED',
                     'baseline_compilation_status': record.get('compilation', {}).get('status') if record else None})
    return {'schema_version': 1, 'program_version': __version__, 'profile': profile,
            'selection': 'Fixed pairs selected before inference; no filtering by success or failure',
            'oracle_isolation': 'Source, original names, expected outputs and evaluator signatures are never passed to run_analysis',
            'provenance': provenance, 'targets': rows,
            'limits': {'attempts_per_target': 3, 'analysis_timeout_seconds': 600,
                       'phase_timeout_seconds': 150, 'max_output_tokens': 16384,
                       'random_cases': random_cases, 'random_seed': 2048}}


def summarize(results, planned):
    """Failures and unavailable targets remain in the denominator."""
    usage = Counter()
    usage_rows = 0
    for row in results:
        if isinstance(row.get('candidate_usage'), dict):
            usage_rows += 1
            for key, value in row['candidate_usage'].items():
                if type(value) is int and value >= 0:
                    usage[key] += value
    return {'planned_targets': planned, 'completed_targets': len(results),
            'status_counts': dict(Counter(row['status'] for row in results)),
            'llm_generated': sum(bool(row.get('llm_generated')) for row in results),
            'candidate_compiled': sum(row.get('candidate_compilation', {}).get('status') == 'COMPILED' for row in results),
            'llm_target_selected': sum(row.get('target_source_selection') == 'llm_reconstruction' for row in results),
            'llm_target_used': sum(bool(row.get('llm_target_used')) for row in results),
            'llm_targets_matched': sum(bool(row.get('llm_target_used')) and row['status'] == 'MATCHED_FINITE_CASES' for row in results),
            'tested_cases': sum(row.get('tested_cases', 0) for row in results),
            'mismatches': sum(row.get('mismatches', 0) for row in results),
            'analysis_seconds': sum(row.get('analysis_seconds', 0) for row in results),
            'wall_seconds': sum(row.get('wall_seconds', 0) for row in results),
            'candidate_usage': dict(usage), 'candidate_usage_available_targets': usage_rows,
            'usage_complete': False,
            'usage_scope': 'Selected candidate only; rejected attempts and discovery may incur additional unrecorded usage'}


def _verify_target_inputs(target, provenance):
    checks = ((provenance['manifest'], provenance['manifest_sha256']),
              (provenance['source'], provenance['source_sha256']),
              (Path(provenance['source']).parent / 'LICENSE', provenance['license_sha256']),
              (target['binary'], target['binary_sha256']),
              (target['baseline_report'], target['baseline_report_sha256']),
              (target['symbols'], target['symbols_sha256']))
    for path, expected in checks:
        if _digest(path) != expected:
            raise ValueError('Benchmark provenance changed after planning')


def _attribution(row, target):
    artifacts = row.get('artifacts', [])
    target_artifacts = [item for item in artifacts if item.get('original_function') == target]
    selection = target_artifacts[0].get('source_selection') if len(target_artifacts) == 1 else None
    dependencies = sorted({item['original_function'] for item in artifacts
                           if item.get('original_function') and item['original_function'] != target
                           and item.get('source_selection') == 'llm_reconstruction'})
    executed = (selection == 'llm_reconstruction' and row.get('tested_cases', 0) > 0
                and row.get('status') in ('MATCHED_FINITE_CASES', 'MISMATCH'))
    return {'target_source_selection': selection, 'llm_target_used': executed,
            'llm_dependency_functions': dependencies, 'llm_used': executed}


def run(normal, stress, output, ghidra_home, *, model='auto', key=None, profile='targeted', plan_only=False, random_cases=1024):
    output = Path(output)
    if output.exists():
        raise ValueError('Output must be new')
    plan = build_plan(normal, stress, profile=profile, random_cases=random_cases)
    output.mkdir(parents=True)
    plan_path = output / 'plan.json'
    plan_path.write_text(json.dumps(plan, indent=2) + '\n')
    plan_hash = _digest(plan_path)
    if plan_only:
        return plan
    if key is None:
        key = getpass.getpass('Chiave DeepSeek (solo memoria, nessuna eco): ')
    if not isinstance(key, str) or not key.strip():
        raise ValueError('API key required')
    request = urllib.request.Request('https://api.deepseek.com/models', headers={'Authorization': 'Bearer ' + key})
    try:
        with urllib.request.build_opener(_NoRedirect()).open(request, timeout=30) as response:
            models = json.loads(response.read(1048576))['data']
    except urllib.error.HTTPError as error:
        status = error.code
        error.close()
        raise RuntimeError(f'DeepSeek model discovery HTTP {status}') from None
    available = [item['id'] for item in models if isinstance(item, dict) and isinstance(item.get('id'), str)]
    if model == 'auto':
        model = next((name for name in ('deepseek-flash', 'deepseek-chat', 'deepseek-v4-pro', 'deepseek-reasoner') if name in available), None)
    if model not in available:
        raise ValueError('Requested supported model unavailable')
    print('Modello disponibile e selezionato: ' + model, flush=True)
    results = []
    for target in plan['targets']:
        started = time.monotonic()
        label = target['variant'] + '-' + target['function']
        result = {'variant': target['variant'], 'function': target['function'], 'model': model,
                  'status': 'UNKNOWN', 'tested_cases': 0, 'mismatches': 0, 'llm_used': False,
                  'llm_target_used': False, 'target_source_selection': None, 'llm_dependency_functions': []}
        try:
            if _digest(plan_path) != plan_hash:
                raise ValueError('Benchmark plan changed')
            provenance = plan['provenance'][target['group']]
            _verify_target_inputs(target, provenance)
            if target['entry_status'] != 'AVAILABLE':
                result['reason'] = 'Target entry not discovered; retained in sample'
            else:
                print(label + ': ricostruzione LLM da disassembly/Pcode e feedback compilatore', flush=True)
                analysis_started = time.monotonic()
                report = run_analysis(Path(target['binary']), output / label / 'analysis', AnalysisConfig(
                    backend='ghidra', ghidra_home=ghidra_home, cache_path=Path(target['cache']),
                    function_pattern=exact_function_pattern(target['observed_name']),
                    llm_endpoint='https://api.deepseek.com', llm_model=model, llm_api_key=key,
                    llm_attempts=3, llm_max_output_tokens=16384, llm_reasoning_effort='low',
                    llm_context_bytes=131072, timeout=600, phase_timeout=150))
                result['analysis_seconds'] = time.monotonic() - analysis_started
                if len(report['functions']) != 1:
                    raise ValueError('Exact target selection returned unexpected entries')
                replacement = _exact_record(report, target['address'], target['observed_name'])
                candidate = replacement.get('candidate') or {}
                result.update(llm_generated=bool(candidate.get('source')),
                              candidate_compilation=candidate.get('compilation', {}),
                              candidate_source_sha256=candidate.get('source_sha256'),
                              baseline_source_sha256=candidate.get('baseline_sha256'),
                              candidate_usage=candidate.get('usage'), attempts=replacement.get('ai_attempts', []),
                              context=replacement.get('ai_context'), analysis_report=str(output / label / 'analysis/report.json'))
                _verify_target_inputs(target, provenance)
                original_report = json.loads(Path(target['baseline_report']).read_text())
                # Only this newly inferred target may use AI; dependencies retain baseline/compatibility.
                original_report['functions'] = [replacement if item['address'] == target['address']
                                               else dict(item, candidate=None) for item in original_report['functions']]
                merged = output / label / 'evaluation-report.json'
                merged.write_text(json.dumps(original_report, indent=2) + '\n')
                manifest = json.loads(Path(provenance['manifest']).read_text())
                addresses, _ = mapped_symbol_addresses(Path(target['binary']), original_report,
                    Path(target['symbols']).read_text(), set(manifest['authored_functions']))
                verification = evaluate_report(Path(provenance['source']), merged, addresses,
                    output / label / 'differential', compiler=target['compiler'], random_cases=plan['limits']['random_cases'],
                    compatibility=True, use_ai=True)
                row = next(item for item in verification['functions'] if item['function'] == target['function'])
                result.update(_attribution(row, target['function']))
                result.update(status=row['status'], tested_cases=row.get('tested_cases', 0),
                              mismatches=row.get('mismatches', 0), reason=row.get('reason'),
                              cases_sha256=row.get('cases_sha256'),
                              verification=str(output / label / 'differential/verification.json'))
        except Exception as error:
            # Keep the denominator, avoid reflecting credential-bearing exception messages.
            result.update(status='ERROR', error_type=type(error).__name__)
        result['wall_seconds'] = time.monotonic() - started
        results.append(result)
        partial = {'model': model, 'profile': profile, 'plan_sha256': plan_hash,
                   'results': results, 'summary': summarize(results, len(plan['targets']))}
        encoded = json.dumps(partial, indent=2)
        if key in encoded:
            raise RuntimeError('Credential redaction failed')
        (output / 'verification.partial.json').write_text(encoded + '\n')
        print(label + ': ' + result['status'] + ', AI target valutata: ' + str(result['llm_target_used']), flush=True)
    result = dict(partial, program_version=__version__, api_key_persisted=False,
                  limitations=['Single pinned game; 22 fixed function/build pairs are not 22 independent games.',
                               'Target entries selected by evaluator-only ground truth; not a discovery benchmark.',
                               'Original source and expected outputs are never supplied to the LLM.',
                               'Finite comparisons only; mixed closure: target AI body with baseline/compatibility dependencies; a closure mismatch may originate in a dependency.',
                               'Usage records cover selected candidates only, not every paid request.'])
    encoded = json.dumps(result, indent=2)
    if key in encoded or any(key.encode() in file.read_bytes() for file in output.rglob('*') if file.is_file()):
        raise RuntimeError('Credential found in artifacts; do not distribute this output')
    (output / 'verification.json').write_text(encoded + '\n')
    (output / 'verification.partial.json').unlink()
    key = None
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--trusted', action='store_true')
    parser.add_argument('--normal', type=Path, required=True)
    parser.add_argument('--stress', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--ghidra-home', type=Path)
    parser.add_argument('--model', default='auto')
    parser.add_argument('--profile', choices=('targeted', 'expanded'), default='targeted')
    parser.add_argument('--random-cases', type=int, default=1024, help='Random inputs per function, 0..4096, in addition to fixed exhaustive/boundary cases')
    parser.add_argument('--plan-only', action='store_true', help='Seal sample inputs without credentials, inference or execution')
    args = parser.parse_args()
    if not args.plan_only and (not args.trusted or not args.ghidra_home):
        parser.error('--trusted and --ghidra-home required for inference and trusted code execution')
    try:
        run(args.normal, args.stress, args.output, args.ghidra_home, model=args.model,
            profile=args.profile, plan_only=args.plan_only, random_cases=args.random_cases)
    except Exception as error:
        print('Collaudo interrotto: ' + (str(error) if isinstance(error, (ValueError, RuntimeError)) else type(error).__name__), file=sys.stderr)
        raise SystemExit(2)
