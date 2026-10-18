#!/usr/bin/env python3
"""Reproducible benchmark of the MIT game 2048.c at a pinned commit.

Checks the approved source SHA256, runs its original test mode and, with Ghidra,
compares recovered deterministic functions in child workers. Symbol ground truth
is used only for evaluation, never for reconstruction or repairing recovered code."""
from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import platform
import re
import shutil
import statistics
import struct
import subprocess
import sys
import time
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

REPOSITORY = 'https://github.com/mevdschee/2048.c'
COMMIT = '90343eb209e84fa9687d596f5d5eecfdf7d4df51'
FILES = {
    '2048.c': '90f794c675a696aa10980dd120d1f0503ee4ed33a61fef92c7df8f443f5b18a8',
    'LICENSE': '593783abd95546a2817d104b2656dd985a979a9e90da895729f211fc844b6402',
}
# This is the only game function with a pure scalar ABI that this harness
# can compare automatically; the others require memory, I/O or void returns.
SCALAR_FUNCTIONS = {'getDigitCount'}


def _run(command, *, timeout=30):
    started = time.monotonic()
    result = subprocess.run([str(item) for item in command], stdin=subprocess.DEVNULL,
                            capture_output=True, timeout=timeout, check=False)
    output = result.stdout.decode('utf-8', 'replace')
    error = result.stderr.decode('utf-8', 'replace')
    if result.returncode:
        raise RuntimeError(f'Comando {command[0]} fallito ({result.returncode}): {error[:4096]}')
    return output, {'command': [str(item) for item in command], 'returncode': result.returncode,
                    'seconds': time.monotonic() - started, 'stdout': output[:8192], 'stderr': error[:8192]}


def source_files(output):
    directory = output / 'source'
    directory.mkdir(parents=True, exist_ok=True)
    provenance = {'repository': REPOSITORY, 'branch_at_resolution': 'main', 'commit': COMMIT,
                  'commit_resolution': 'GitHub REST API /repos/mevdschee/2048.c/commits/main', 'files': {}}
    for filename, expected in FILES.items():
        path = directory / filename
        url = f'https://raw.githubusercontent.com/mevdschee/2048.c/{COMMIT}/{filename}'
        if not path.exists():
            request = urllib.request.Request(url, headers={'User-Agent': 'GameDecomp-real-game-benchmark'})
            with urllib.request.urlopen(request, timeout=30) as response:
                raw = response.read(1024 * 1024 + 1)
            if len(raw) > 1024 * 1024:
                raise ValueError('Sorgente remoto oltre il limite di 1 MiB')
            if hashlib.sha256(raw).hexdigest() != expected:
                raise ValueError(f'SHA256 inatteso: {filename}; nessuna compilazione/esecuzione')
            path.write_bytes(raw)
        if path.is_symlink() or not path.is_file():
            raise ValueError('Sono richiesti file di sorgente regolari, senza symlink')
        raw = path.read_bytes()
        if hashlib.sha256(raw).hexdigest() != expected:
            raise ValueError(f'SHA256 inatteso: {filename}; nessuna compilazione/esecuzione')
        provenance['files'][filename] = {'url': url, 'sha256': expected, 'bytes': len(raw)}
    (directory / 'provenance.json').write_text(json.dumps(provenance, indent=2) + '\n', encoding='utf-8')
    return directory / '2048.c', provenance


def function_names(source):
    """List declarations for this pinned source; this is not a general C parser."""
    return re.findall(r'^(?:void|bool|int|uint8_t)\s+(\w+)\([^;]*?\)\s*\{', source, re.M)


def symbol_addresses(text, authored):
    """Accept only text definitions of source names; exclude PLT and runtime symbols."""
    result = {}
    for line in text.splitlines():
        fields = line.split()
        if len(fields) >= 3 and fields[0] in authored and fields[1] in ('T', 't', 'W', 'w'):
            result[fields[0]] = int(fields[2], 16)
    return result


def mapped_symbol_addresses(binary, report, text, authored):
    """Map evaluator-only ELF symbols to the frontend's observed image base."""
    addresses = symbol_addresses(text, authored)
    image_base = report.get('metadata', {}).get('image_base')
    if image_base is None:
        return addresses, 0
    data = Path(binary).read_bytes()
    if len(data) < 64 or data[:6] != b'\x7fELF\x02\x01' or type(image_base) is not int:
        raise ValueError('Image mapping requires a valid ELF64 little-endian target')
    offset = struct.unpack_from('<Q', data, 32)[0]
    size, count = struct.unpack_from('<HH', data, 54)
    if not 56 <= size or not 1 <= count <= 4096 or offset+size*count > len(data):
        raise ValueError('Invalid program header table')
    loads = [struct.unpack_from('<Q', data, offset+index*size+16)[0] for index in range(count)
             if struct.unpack_from('<I', data, offset+index*size)[0] == 1]
    if not loads:
        raise ValueError('No ELF load segment')
    adjustment = image_base - min(loads)
    return {name: address+adjustment for name, address in addresses.items()}, adjustment


def _text_digest(binary):
    dump, _ = _run(['objdump', '-s', '-j', '.text', binary])
    data = bytearray()
    for line in dump.splitlines():
        fields = line.split()
        if not fields or not re.fullmatch(r'[a-fA-F0-9]+', fields[0]):
            continue
        for field in fields[1:5]:
            if not re.fullmatch(r'(?:[a-fA-F0-9]{2}){1,4}', field):
                break
            data.extend(bytes.fromhex(field))
    if not data:
        raise ValueError('Sezione .text vuota o non leggibile')
    return hashlib.sha256(data).hexdigest()


def measure(report, authored, addresses):
    """Measure exact entry-address coverage without counting arbitrary .text regions."""
    # A stripped section blob can happen to start exactly at main. Coinciding
    # addresses are insufficient: objdump's section/PLT labels are not function
    # boundaries and must never inflate function-discovery coverage.
    def is_function(record):
        name = record['name']
        return not name.startswith('.') and '@plt' not in name
    discovered = {record['address']: record for record in report['functions'] if is_function(record)}
    structural = report.get('type_recovery', {})
    signatures = structural.get('functions', {})
    rows = []
    for name in authored:
        address = addresses.get(name)
        record = discovered.get(address)
        signature = signatures.get(record['id'], {}) if record else {}
        metadata_signature = signature.get('status') == 'METADATA'
        rows.append({
            'original_name': name, 'entry_address': address,
            'detected_entry': record is not None,
            'reported_name': record['name'] if record else None,
            'original_name_preserved': bool(record and record['name'] == name),
            'source_recovered': bool(record and record.get('source')),
            'compilation_status': record['compilation']['status'] if record else 'NOT_DISCOVERED',
            'compatibility_compilation_status': (record.get('compatibility') or {}).get('compilation', {}).get('status', 'NOT_AVAILABLE') if record else 'NOT_DISCOVERED',
            'signature_from_metadata': metadata_signature,
            'parameters_named_from_metadata': sum(bool(item.get('name')) for item in signature.get('parameters', [])) if metadata_signature else 0,
            'diagnostics': record.get('diagnostics', []) if record else ['Nessuna entry di funzione individuata a questo indirizzo'],
        })
    addresses_set = set(addresses.values())
    return {
        'authored_functions': len(authored), 'linked_authored_functions': len(addresses),
        'game_entries_detected': sum(row['detected_entry'] for row in rows),
        'game_sources_recovered': sum(row['source_recovered'] for row in rows),
        'game_sources_compiled': sum(row['source_recovered'] and row['compilation_status'] == 'COMPILED' for row in rows),
        'game_compatibility_compiled': sum(row['compatibility_compilation_status'] == 'COMPILED' for row in rows),
        'game_names_preserved': sum(row['original_name_preserved'] for row in rows),
        'game_metadata_signatures': sum(row['signature_from_metadata'] for row in rows),
        'metadata_type_nodes_including_libc': len(structural.get('types', [])),
        'non_game_records': sum(not is_function(record) or record['address'] not in addresses_set for record in report['functions']),
        'all_records': len(report['functions']), 'functions': rows,
        'type_diagnostics': structural.get('diagnostics', []),
        'diagnostics': report.get('diagnostics', []),
    }


def differential_if_supported(source, builds, output, workers):
    recovered = [build for build in builds if not build['stripped'] and
                 any(row['original_name'] in SCALAR_FUNCTIONS and row['source_recovered'] for row in build['coverage']['functions'])]
    if not recovered:
        return {'status': 'NOT_APPLICABLE', 'tested_functions': 0, 'tested_cases': 0, 'mismatches': 0,
                'reason': 'Nessuna funzione scalare pura del gioco effettivamente recuperata; confronto differenziale non eseguito.'}
    from gamedecomp.pipeline import AnalysisConfig, run_analysis
    from gamedecomp.verify import verify_report
    results = []
    for build in recovered:
        directory = output / 'differential' / build['variant']
        directory.mkdir(parents=True)
        binary = directory / '2048.so'
        _run([build['compiler_path'], '-std=c11', '-g', build['optimization'], '-shared', '-fPIC', source, '-o', binary])
        # Shared-library code generation differs from the executable. Analyze
        # it again and only test conservative sources actually recovered here.
        report = run_analysis(binary, directory / 'analysis', AnalysisConfig(backend='native', workers=workers,
                              function_pattern='getDigitCount', cache_path=directory / 'cache.sqlite'))
        if not any(record.get('source') for record in report['functions']):
            results.append({'variant': build['variant'], 'status': 'UNKNOWN', 'reason': 'Variante shared non recuperata'})
            continue
        result = verify_report(binary, directory / 'analysis' / 'report.json', trusted=True, workers=workers, cases=256)
        (directory / 'verification.json').write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding='utf-8')
        results.append({'variant': build['variant'], 'verification': result})
    return {'status': 'EXECUTED', 'results': results,
            'limitations': 'Valori di ritorno finiti sotto ABI inferita; nessuna equivalenza generale o verifica del gioco completo.'}


def run_benchmark(output, *, repeats=3, workers=4, backend='native', ghidra_home=None):
    if backend not in ('native', 'ghidra'):
        raise ValueError('backend deve essere native o ghidra')
    from gamedecomp import __version__
    from gamedecomp.pipeline import AnalysisConfig, run_analysis
    output = Path(output).resolve()
    if (output / 'benchmark.json').exists():
        raise ValueError('Benchmark già presente: scegliere una nuova directory')
    if type(repeats) is not int or not 1 <= repeats <= 20:
        raise ValueError('repeats deve essere tra 1 e 20')
    if type(workers) is not int or not 1 <= workers <= 64:
        raise ValueError('workers deve essere tra 1 e 64')
    for name in ('gcc', 'clang', 'nm', 'strip', 'objdump'):
        if not shutil.which(name):
            raise RuntimeError(f'Strumento richiesto assente: {name}')
    source, provenance = source_files(output)
    authored = function_names(source.read_text(encoding='utf-8'))
    if len(authored) != 19 or len(set(authored)) != len(authored):
        raise ValueError('Elenco di funzioni inatteso per il sorgente fissato')
    benchmark = {'schema_version': 1, 'created_at': datetime.now(timezone.utc).isoformat(), 'backend': backend,
                 'program_version': __version__, 'provenance': provenance,
                 'host': {'system': platform.system(), 'machine': platform.machine(), 'python': platform.python_version()},
                 'repeats': repeats, 'workers': workers, 'llm_enabled': False, 'gnn_enabled': False,
                 'cache': 'database nuovo per ogni replica; cache fredda di baseline, cache OS non azzerata',
                 'authored_functions': authored, 'builds': []}
    for compiler in ('gcc', 'clang'):
        compiler_path = shutil.which(compiler)
        version, _ = _run([compiler_path, '--version'])
        for optimization in ('-O0', '-O2'):
            variant = compiler + '-' + optimization[1:]
            directory = output / 'builds' / variant
            directory.mkdir(parents=True, exist_ok=False)
            debug = directory / '2048-debug'
            _, compile_info = _run([compiler_path, '-std=c11', '-g', optimization, '-fno-pie', '-no-pie', source, '-o', debug])
            symbols, _ = _run(['nm', '--defined-only', '--format=posix', '-S', debug])
            (directory / 'symbols-ground-truth.txt').write_text(symbols, encoding='utf-8')
            addresses = symbol_addresses(symbols, set(authored))
            if len(addresses) != len(authored):
                raise ValueError('Funzioni sorgente mancanti nel ground truth del linker')
            stripped = directory / '2048-stripped'
            _run(['strip', '--strip-all', '-o', stripped, debug])
            if _text_digest(debug) != _text_digest(stripped):
                raise ValueError('La sezione .text è cambiata durante strip; mapping indirizzi non valido')
            for is_stripped, binary in ((False, debug), (True, stripped)):
                label = variant + ('-stripped' if is_stripped else '-debug')
                print(f'{label}: test originale e analisi ({repeats} repliche)', flush=True)
                test_output, original_test = _run([binary, 'test'], timeout=10)
                if 'All 13 tests executed successfully' not in test_output:
                    raise RuntimeError('La modalità test originale non ha riportato i 13 casi attesi')
                runs, measured = [], None
                for repeat in range(repeats):
                    analysis_directory = output / 'analysis' / label / f'run-{repeat+1}'
                    config = AnalysisConfig(backend=backend, ghidra_home=ghidra_home, workers=workers,
                                            timeout=300 if backend == 'ghidra' else 120,
                                            phase_timeout=180 if backend == 'ghidra' else 30,
                                            cache_path=output / 'cache' / f'{label}-{repeat+1}.sqlite', recover_types=True)
                    started = time.monotonic()
                    report = run_analysis(binary, analysis_directory, config)
                    runs.append({'wall_seconds': time.monotonic() - started, 'pipeline_seconds': report['timings']['total_seconds'],
                                 'report': str(analysis_directory / 'report.json'), 'cache_hit': report['cache_hit']})
                    current = measure(report, authored, addresses)
                    if measured is not None and current != measured:
                        raise RuntimeError('Copertura non deterministica tra repliche identiche')
                    measured = current
                benchmark['builds'].append({
                    'variant': label, 'compiler': compiler, 'compiler_path': compiler_path,
                    'compiler_version': version.splitlines()[0], 'optimization': optimization, 'stripped': is_stripped,
                    'binary': str(binary), 'binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(),
                    'binary_bytes': binary.stat().st_size, 'compile': compile_info,
                    'original_tests': {'cases': 13, **original_test}, 'runs': runs,
                    'median_wall_seconds': statistics.median(run['wall_seconds'] for run in runs),
                    'coverage': measured,
                })
                (output / 'benchmark.partial.json').write_text(json.dumps(benchmark, indent=2, ensure_ascii=False), encoding='utf-8')
    if backend == 'ghidra':
        from benchmarks.real_game_differential import evaluate_report
        comparisons = []
        for build in benchmark['builds']:
            symbols = (Path(build['binary']).parent / 'symbols-ground-truth.txt').read_text()
            comparisons.append({'variant': build['variant'], 'verification': evaluate_report(
                source, build['runs'][0]['report'], symbol_addresses(symbols, set(authored)),
                output / 'differential' / build['variant'], compiler=build['compiler_path'])})
        benchmark['differential'] = {'status': 'EXECUTED', 'results': comparisons}
    else:
        benchmark['differential'] = differential_if_supported(source, benchmark['builds'], output, workers)
    reasons = Counter()
    for build in benchmark['builds']:
        for row in build['coverage']['functions']:
            if not row['source_recovered']:
                for reason in row['diagnostics'][:1]:
                    reasons[re.sub(r'^0x[0-9a-f]+: ', '', reason)] += 1
    benchmark['unsupported_diagnostics'] = dict(reasons)
    benchmark['limitations'] = [
        'Un solo piccolo gioco C; nessuna misura SOTA o rappresentatività dei giochi moderni.',
        'Le 13 prove sono il test originale del gioco, non prove di equivalenza della decompilazione.',
        'I nomi dei simboli debug e i tipi DWARF sono metadati conservati dal compilatore, non inferenze AI.',
        'C non contiene classi originali: i tipi libc/termios non sono recupero di classi del gioco.',
        'Gli indirizzi del gemello con simboli sono ground truth riservato al valutatore; la pipeline stripped non li riceve.',
        'Le etichette PLT, startup/runtime e sezione .text non contano come funzioni originali del gioco.',
        'Ai fini dei tempi sono incluse scrittura report e cache locale; esclusi download, compilazione e test originale.',
        'Le repliche usano cache applicativa fredda, ma non azzerano cache filesystem/CPU e non sono un confronto con altri decompilatori.',
    ]
    target = output / 'benchmark.json'
    target.write_text(json.dumps(benchmark, indent=2, ensure_ascii=False, allow_nan=False) + '\n', encoding='utf-8')
    (output / 'benchmark.partial.json').unlink(missing_ok=True)
    print(f'Risultati: {target}', flush=True)
    return benchmark


def run_existing_benchmark(baseline, output, *, workers=4, ghidra_home=None, reuse_reports=None):
    """Measure Ghidra on identical binaries from an already checked baseline.

Reused reports are explicit and produce no synthetic repetitions or timings.
Ground truth enters measure() only after Ghidra analysis."""
    from gamedecomp.pipeline import AnalysisConfig, run_analysis
    from gamedecomp import __version__
    baseline, output = Path(baseline).resolve(), Path(output).resolve()
    if output.exists():
        raise ValueError('Output già presente: scegliere una nuova directory')
    previous = json.loads(baseline.read_text())
    source = baseline.parent / 'source' / '2048.c'
    if hashlib.sha256(source.read_bytes()).hexdigest() != FILES['2048.c']:
        raise ValueError('SHA256 inatteso per il sorgente originale')
    reuse_reports = reuse_reports or {}
    labels = {build['variant'] for build in previous['builds']}
    if set(reuse_reports) - labels:
        raise ValueError('Variante riusata non presente nella baseline')
    output.mkdir(parents=True)
    (output / 'source').mkdir()
    for name in FILES:
        shutil.copyfile(baseline.parent / 'source' / name, output / 'source' / name)
    source_files(output)
    result = {key: value for key, value in previous.items()
              if key not in ('builds', 'differential', 'unsupported_diagnostics')}
    result.update(backend='ghidra', program_version=__version__, baseline=str(baseline), repeats=1, workers=workers,
                  created_at=datetime.now(timezone.utc).isoformat(), builds=[],
                  cache='Cache nuova per analisi; report esterni riusati esplicitamente senza duplicare analisi')
    for old in previous['builds']:
        label, binary = old['variant'], Path(old['binary'])
        if hashlib.sha256(binary.read_bytes()).hexdigest() != old['binary_sha256']:
            raise ValueError('Binario baseline modificato: ' + label)
        reused = label in reuse_reports
        if reused:
            report_path = Path(reuse_reports[label]).resolve()
            report = json.loads(report_path.read_text())
            if report.get('input', {}).get('sha256', report.get('binary_hash')) != old['binary_sha256']:
                raise ValueError('Report riusato riferito a un binario diverso: ' + label)
            wall_seconds = None
        else:
            report_path = output / 'analysis' / label / 'report.json'
            started = time.monotonic()
            report = run_analysis(binary, report_path.parent, AnalysisConfig(
                backend='ghidra', ghidra_home=ghidra_home, workers=workers, timeout=300,
                phase_timeout=180, cache_path=output / 'cache' / (label + '.sqlite')))
            wall_seconds = time.monotonic() - started
        if report.get('backend') != 'ghidra':
            raise ValueError('Richiesto un report Ghidra reale: ' + label)
        # Raw Analysis exports may be reused too. Compile their observed units
        # without changing bodies, and record this separately from pipeline time.
        if any('compilation' not in function for function in report['functions']):
            from gamedecomp.pipeline import _compilation_source
            from gamedecomp.validation import compile_source
            for function in report['functions']:
                if not function.get('source'):
                    function['compilation'] = {'status': 'UNKNOWN'}
                    continue
                try:
                    unit, _ = _compilation_source(function['source'], function.get('metadata', {}), 'ghidra')
                    function['compilation'] = compile_source(unit)
                except ValueError as error:
                    function['compilation'] = {'status': 'UNKNOWN', 'diagnostics': [str(error)]}
            enriched = output / 'reused' / label / 'report.json'
            enriched.parent.mkdir(parents=True)
            enriched.write_text(json.dumps(report, indent=2, ensure_ascii=False) + '\n')
            report_path = enriched
        symbols = (binary.parent / 'symbols-ground-truth.txt').read_text()
        build = dict(old)
        build.update(coverage=measure(report, previous['authored_functions'],
                                      symbol_addresses(symbols, set(previous['authored_functions']))),
                     runs=[{'report': str(report_path), 'reused_report': reused,
                            'wall_seconds': wall_seconds, 'pipeline_seconds': report.get('timings', {}).get('total_seconds')}],
                     median_wall_seconds=wall_seconds)
        result['builds'].append(build)
        (output / 'benchmark.partial.json').write_text(json.dumps(result, indent=2, ensure_ascii=False) + '\n')
        print(f"{label}: {build['coverage']['game_sources_recovered']}/19 recuperate, "
              f"{build['coverage']['game_sources_compiled']}/19 compilate", flush=True)
    (output / 'benchmark.json').write_text(json.dumps(result, indent=2, ensure_ascii=False) + '\n')
    (output / 'benchmark.partial.json').unlink(missing_ok=True)
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=ROOT / 'demo-output' / 'real-game')
    parser.add_argument('--repeats', type=int, default=3)
    parser.add_argument('--workers', type=int, default=4)
    parser.add_argument('--backend', choices=('native', 'ghidra'), default='native')
    parser.add_argument('--ghidra-home', type=Path)
    parser.add_argument('--baseline', type=Path, help='Riusa gli identici binari di un benchmark nativo; richiede --backend ghidra')
    parser.add_argument('--reuse-report', action='append', default=[], metavar='VARIANTE=REPORT',
                        help='Riusa un report Ghidra già misurato con --baseline, senza duplicare analisi')
    parser.add_argument('--trusted', action='store_true', help='Autorizza compilazione/esecuzione di 2048.c MIT fissato/hashato e, con Ghidra, corpi recuperati')
    args = parser.parse_args(argv)
    if not args.trusted:
        parser.error('Richiesto --trusted: la modalità test esegue il sorgente MIT fissato dopo verifica SHA256')
    if args.baseline:
        if args.backend != 'ghidra':
            parser.error('--baseline richiede --backend ghidra')
        reused = {}
        for item in args.reuse_report:
            if '=' not in item:
                parser.error('--reuse-report richiede VARIANTE=REPORT')
            label, path = item.split('=', 1)
            if label in reused:
                parser.error('Variante --reuse-report duplicata')
            reused[label] = Path(path)
        run_existing_benchmark(args.baseline, args.output, workers=args.workers,
                               ghidra_home=args.ghidra_home, reuse_reports=reused)
    else:
        if args.reuse_report:
            parser.error('--reuse-report richiede --baseline')
        run_benchmark(args.output, repeats=args.repeats, workers=args.workers,
                      backend=args.backend, ghidra_home=args.ghidra_home)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
