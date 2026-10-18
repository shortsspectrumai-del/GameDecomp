"""Freeze real Ghidra static imports of synthetic console CPU fixtures.

No input is executed and no provider is contacted. This measures loader wiring,
not whole-game recovery, semantic equivalence, or LLM reconstruction accuracy.
"""
import argparse
import hashlib
import json
from pathlib import Path
import time

from gamedecomp.pipeline import AnalysisConfig, run_analysis
from tests.test_console_ghidra import console_fixtures


def verify(output, ghidra_home):
    output = Path(output).resolve()
    output.mkdir(parents=True, exist_ok=False)
    rows = []
    for name, data, profile in console_fixtures():
        source = output / (name + '.input')
        source.write_bytes(data)
        started = time.monotonic()
        report = run_analysis(source, output / name, AnalysisConfig(
            console_profile=profile, ghidra_home=Path(ghidra_home),
            phase_timeout=90, timeout=120, max_functions=100,
            cache_path=output / 'analysis.sqlite'))
        functions = report['functions']
        provenance = report['metadata']['console_import']
        passed = (report['input']['sha256'] == hashlib.sha256(data).hexdigest()
                  and report['input']['format'] == name
                  and provenance['source_sha256'] == report['input']['sha256']
                  and not provenance['executable_run']
                  and bool(functions)
                  and any(f['instructions'] for f in functions)
                  and any(f.get('source') for f in functions)
                  and all(f['compilation']['status'] == 'UNKNOWN' for f in functions))
        rows.append({'format': name, 'profile': profile, 'static_import': 'PASS' if passed else 'FAIL',
                     'functions': len(functions), 'seconds': round(time.monotonic() - started, 3),
                     'source_sha256': report['input']['sha256'],
                     'normalized_sha256': provenance['normalized_sha256'],
                     'frontend_architecture': provenance.get('frontend_architecture'),
                     'semantic_status': 'UNKNOWN', 'target_abi_compilation': 'UNKNOWN'})
        print(name + ': ' + rows[-1]['static_import'], flush=True)
    root = Path(__file__).resolve().parents[1]
    sources = [p for folder in ('gamedecomp', 'tests') for p in (root / folder).rglob('*')
               if p.is_file() and p.suffix in ('.py', '.java') and '__pycache__' not in p.parts]
    sources.append(Path(__file__).resolve())
    summary = {'status': 'PASS' if all(r['static_import'] == 'PASS' for r in rows) else 'FAIL',
               'scope': 'Synthetic CPU static imports only; no commercial game, execution or semantic proof.',
               'provider_calls': 0, 'rows': rows,
               'source_sha256': {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(sources)}}
    (output / 'verification.json').write_text(json.dumps(summary, indent=2) + '\n')
    return summary


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--ghidra-home', type=Path, required=True)
    args = parser.parse_args()
    raise SystemExit(0 if verify(args.output, args.ghidra_home)['status'] == 'PASS' else 1)
