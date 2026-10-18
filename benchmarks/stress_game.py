#!/usr/bin/env python3
"""Harder offline builds of the pinned MIT game: O3/PIE/stack protection/LTO.

Only use --trusted for the pinned local source and recovered bodies. Missing
functions after LTO are counted as missing, never recreated from ground truth.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import shutil
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from benchmarks.real_game import (FILES, _run, _text_digest, function_names,
                                  source_files, mapped_symbol_addresses, measure)
from benchmarks.real_game_differential import evaluate_benchmark
from gamedecomp import __version__
from gamedecomp.pipeline import AnalysisConfig, run_analysis

PROFILES = [
    ('gcc-O3-pie', 'gcc', ['-O3', '-fPIE', '-pie', '-fstack-protector-strong', '-D_FORTIFY_SOURCE=2']),
    ('clang-O3-pie', 'clang', ['-O3', '-fPIE', '-pie', '-fstack-protector-strong', '-D_FORTIFY_SOURCE=2']),
    ('gcc-O3-lto-pie', 'gcc', ['-O3', '-flto', '-fPIE', '-pie', '-fstack-protector-all', '-D_FORTIFY_SOURCE=2']),
    ('gcc-Os-lto-pie', 'gcc', ['-Os', '-flto', '-fPIE', '-pie', '-fstack-protector-all', '-D_FORTIFY_SOURCE=2']),
]


def run_stress(source_directory, output, ghidra_home, *, random_cases=1024):
    source_directory, output = source_directory.resolve(), output.resolve()
    # Verify both original files before any build or execution. No download.
    for name, expected in FILES.items():
        file = source_directory/name
        if file.is_symlink() or hashlib.sha256(file.read_bytes()).hexdigest() != expected:
            raise ValueError('Unexpected pinned source/license: '+name)
    if output.exists():
        raise ValueError('Output must be a new directory')
    output.mkdir(parents=True)
    (output/'source').mkdir()
    for name in FILES:
        shutil.copyfile(source_directory/name, output/'source'/name)
    source, provenance = source_files(output)
    authored = function_names(source.read_text())
    manifest = {'schema_version': 1, 'created_at': datetime.now(timezone.utc).isoformat(),
                'program_version': __version__, 'backend': 'ghidra', 'provenance': provenance,
                'authored_functions': authored, 'builds': [],
                'limitations': ['One C game; finite comparisons, no SOTA claim.',
                                'LTO may eliminate or inline original functions; absent entries remain missing.',
                                'Evaluation-only symbols and image mapping are never provided to the analyzer.']}
    for label, compiler, flags in PROFILES:
        directory = output/'builds'/label
        directory.mkdir(parents=True)
        unstripped, binary = directory/'2048-symbols', directory/'2048-stripped'
        _, compilation = _run([compiler, '-std=c11', *flags, source, '-o', unstripped])
        symbols, _ = _run(['nm', '--defined-only', '--format=posix', '-S', unstripped])
        (directory/'symbols-ground-truth.txt').write_text(symbols)
        _run(['strip', '--strip-all', '-o', binary, unstripped])
        if _text_digest(unstripped) != _text_digest(binary):
            raise AssertionError('Strip changed text')
        test_output, original_test = _run([binary, 'test'])
        if 'All 13 tests executed successfully' not in test_output:
            raise AssertionError('Original game self-tests failed')
        report_file = output/'analysis'/label/'report.json'
        print(label+': Ghidra analysis', flush=True)
        report = run_analysis(binary, report_file.parent, AnalysisConfig(backend='ghidra',
            ghidra_home=ghidra_home, workers=4, timeout=300, phase_timeout=180,
            cache_path=output/'cache'/(label+'.sqlite')))
        addresses, adjustment = mapped_symbol_addresses(binary, report, symbols, set(authored))
        coverage = measure(report, authored, addresses)
        manifest['builds'].append({'variant': label, 'compiler_path': shutil.which(compiler),
            'binary': str(binary), 'binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(),
            'flags': flags, 'compile': compilation, 'original_tests': {'cases': 13, **original_test},
            'evaluation_address_adjustment': adjustment, 'coverage': coverage,
            'runs': [{'report': str(report_file), 'cache_hit': report['cache_hit']} ]})
        (output/'benchmark.partial.json').write_text(json.dumps(manifest, indent=2)+'\n')
        print(label+': '+str(coverage['game_entries_detected'])+'/19 original entries', flush=True)
    path = output/'benchmark.json'
    path.write_text(json.dumps(manifest, indent=2)+'\n')
    verification = evaluate_benchmark(path, output/'differential', random_cases=random_cases, compatibility=True)
    (output/'benchmark.partial.json').unlink()
    print(json.dumps(verification['summary']), flush=True)
    return manifest, verification


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--trusted', action='store_true')
    parser.add_argument('--source-directory', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--ghidra-home', type=Path, required=True)
    parser.add_argument('--random-cases', type=int, default=1024)
    args = parser.parse_args()
    if not args.trusted or not 0 <= args.random_cases <= 4096:
        parser.error('--trusted required; random-cases must be 0..4096')
    run_stress(args.source_directory, args.output, args.ghidra_home, random_cases=args.random_cases)
