#!/usr/bin/env python3
"""Finite comparisons of recovered 2048.c bodies; execution requires --trusted.

Original source is used only as the evaluator oracle and ABI contract. Each
recovered library contains backend-exported bodies and context, with identity
renamings recorded explicitly."""
from __future__ import annotations

import argparse
from functools import lru_cache
import hashlib
import itertools
import json
import os
from pathlib import Path
import random
import re
import shutil
import signal
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from benchmarks.real_game import FILES, symbol_addresses, mapped_symbol_addresses

SEED = 2048
SCORES = (0, 17, 4294967287)
SPECS = {
    'getDigitCount': ('uint8_t getDigitCount(uint32_t number)', ()),
    'findTarget': ('uint8_t findTarget(uint8_t array[SIZE], uint8_t x, uint8_t stop)', ()),
    'slideArray': ('bool slideArray(uint8_t array[SIZE], uint32_t *score)', ('findTarget',)),
    'rotateBoard': ('void rotateBoard(uint8_t board[SIZE][SIZE])', ()),
    'moveUp': ('bool moveUp(uint8_t board[SIZE][SIZE], uint32_t *score)', ('slideArray',)),
    'moveLeft': ('bool moveLeft(uint8_t board[SIZE][SIZE], uint32_t *score)', ('rotateBoard', 'moveUp')),
    'moveDown': ('bool moveDown(uint8_t board[SIZE][SIZE], uint32_t *score)', ('rotateBoard', 'moveUp')),
    'moveRight': ('bool moveRight(uint8_t board[SIZE][SIZE], uint32_t *score)', ('rotateBoard', 'moveUp')),
    'findPairDown': ('bool findPairDown(uint8_t board[SIZE][SIZE])', ()),
    'countEmpty': ('uint8_t countEmpty(uint8_t board[SIZE][SIZE])', ()),
    'gameEnded': ('bool gameEnded(uint8_t board[SIZE][SIZE])', ('countEmpty', 'findPairDown', 'rotateBoard')),
}


def check_original_signatures(source):
    """Check the oracle contract without using it to generate bodies or signatures."""
    declarations = re.findall(r'^(?:void|bool|uint8_t)\s+\w+\([^;]*?\)\s*(?=\{)', source, re.M)
    normalized = {re.sub(r'\s+', '', item) for item in declarations}
    for name, (signature, _) in SPECS.items():
        if re.sub(r'\s+', '', signature) not in normalized:
            raise ValueError(f'Firma originale inattesa o assente: {name}')


def function_cases(name, *, random_cases=256, seed=SEED):
    if name not in SPECS:
        raise ValueError('Funzione fuori dal contratto del valutatore')
    if type(random_cases) is not int or not 0 <= random_cases <= 4096:
        raise ValueError('random_cases deve essere tra 0 e 4096')
    if type(seed) is not int or not 0 <= seed < 2**64:
        raise ValueError('seed must be an unsigned 64-bit integer')
    rng = random.Random(seed)
    if name == 'getDigitCount':
        values = set(range(21)) | {2147483647, 2147483648, 4294967294, 4294967295}
        for power in range(1, 10):
            values.update((10 ** power - 1, 10 ** power, 10 ** power + 1))
        values.update(rng.randrange(2 ** 32) for _ in range(random_cases))
        return [{'number': value} for value in sorted(values)]
    if name in ('findTarget', 'slideArray'):
        arrays = list(itertools.product(range(5), repeat=4))
        arrays.extend(tuple(rng.randrange(13) for _ in range(4)) for _ in range(random_cases))
        if name == 'findTarget':
            return [{'array': list(array), 'x': x, 'stop': stop} for array in arrays
                    for x in range(4) for stop in range(max(1, x))]
        return [{'array': list(array), 'score': score} for array in arrays for score in SCORES]
    boards = [[0] * 16, [1] * 16, list(range(1, 17)),
              [1, 2, 1, 2, 2, 1, 2, 1, 1, 2, 1, 2, 2, 1, 2, 1],
              [1, 1, 0, 0, 2, 2, 1, 1, 0, 0, 3, 3, 4, 0, 4, 0],
              [1, 2, 3, 4, 1, 2, 3, 4, 5, 6, 7, 8, 5, 6, 7, 8]]
    boards.extend([rng.randrange(13) for _ in range(16)] for _ in range(random_cases))
    if name == 'rotateBoard':
        boards.append(list(range(240, 256)))
    if name.startswith('move'):
        return [{'board': board, 'score': score} for board in boards for score in SCORES]
    return [{'board': board} for board in boards]


def compare_observations(cases, original, recovered):
    if not cases:
        raise ValueError('Zero casi non attestano una funzione confrontata')
    if len(cases) != len(original) or len(cases) != len(recovered):
        raise ValueError('Risultati incompleti: nessun confronto parziale dichiarato completo')
    mismatches = [{'index': index, 'input': case, 'original': expected, 'recovered': actual}
                  for index, (case, expected, actual) in enumerate(zip(cases, original, recovered))
                  if expected != actual]
    return {'status': 'MISMATCH' if mismatches else 'MATCHED_FINITE_CASES',
            'tested_cases': len(cases), 'matched_cases': len(cases) - len(mismatches),
            'mismatches': len(mismatches), 'mismatch_examples': mismatches[:20]}


def recovered_closure(report, addresses, name):
    needed = set()
    def visit(current):
        if current in needed:
            return
        needed.add(current)
        for dependency in SPECS[current][1]:
            visit(dependency)
    visit(name)
    records = {item['address']: item for item in report['functions']
               if not item['name'].startswith('.') and '@plt' not in item['name']}
    selected, missing = {}, []
    for function in sorted(needed):
        record = records.get(addresses.get(function))
        if record is None or not record.get('source'):
            missing.append(function)
        else:
            selected[function] = record
    if missing:
        return {'status': 'UNKNOWN', 'reason': 'Closure di corpi recuperati incompleta',
                'missing_functions': missing, 'tested_cases': 0}
    names = [record['name'] for record in selected.values()]
    if len(set(names)) != len(names) or any(not re.fullmatch(r'[A-Za-z_]\w*', item, re.ASCII) for item in names):
        return {'status': 'UNKNOWN', 'reason': 'Identità dei simboli C ambigua o non supportata', 'tested_cases': 0}
    return {'status': 'AVAILABLE', 'records': selected,
            'identity_mapping': {record['name']: original for original, record in selected.items()}}


def write_recovered_unit(record, mapping, output, *, compatibility=False, use_ai=False, validation_probe=False):
    if validation_probe and not use_ai:
        raise ValueError('A validation probe requires explicit AI selection')
    metadata = record.get('metadata', {})
    preamble = metadata.get('compile_preamble')
    if (metadata.get('compile_preamble_status') != 'AVAILABLE' or not isinstance(preamble, str)
            or len(preamble.encode()) > 262144 or '\0' in preamble):
        raise ValueError('Preamble Ghidra assente, non disponibile o non valido')
    body = record['source']
    baseline = body
    selection = 'conservative_baseline'
    lowered = record.get('compatibility') or {}
    if (compatibility and record.get('compilation', {}).get('status') != 'COMPILED'
            and lowered.get('status') == 'AVAILABLE'
            and lowered.get('compilation', {}).get('status') == 'COMPILED'):
        candidate, runtime = lowered.get('source'), lowered.get('preamble')
        if (not isinstance(candidate, str) or not isinstance(runtime, str)
                or '\0' in candidate + runtime or len((candidate+runtime+preamble).encode()) > 1_000_000
                or lowered.get('source_sha256') != hashlib.sha256(body.encode()).hexdigest()
                or lowered.get('lowered_sha256') != hashlib.sha256(candidate.encode()).hexdigest()):
            raise ValueError('Traduzione di compatibilità non valida o hash discordante')
        body, preamble = candidate, runtime + '\n' + preamble
        selection = 'explicit_compatibility_lowering'
    candidate = record.get('candidate') or {}
    from gamedecomp.semantic import candidate_is_usable
    if use_ai and (candidate_is_usable(candidate) or
                   validation_probe and candidate.get('compilation', {}).get('status') == 'COMPILED'):
        if (candidate.get('baseline_sha256') != hashlib.sha256(baseline.encode()).hexdigest()
                or candidate.get('source_sha256') != hashlib.sha256(candidate.get('source', '').encode()).hexdigest()
                or candidate['compilation'].get('abi_check') not in ('COMPILER_TYPE_IDENTITY', 'COMPILER_ABI_SHAPE')):
            raise ValueError('Candidata AI non vincolata alla baseline o ABI non verificato')
        body = candidate['source']
        preamble = candidate.get('compile_support', '')+'\n'+metadata['compile_preamble']
        selection = 'llm_validation_probe' if validation_probe else 'llm_reconstruction'
    output.mkdir(parents=True, exist_ok=True)
    stem = f"{record['address']:x}_{record['name']}"
    source_file = output / (stem + '.recovered.c')
    unit_file = output / (stem + '.unit.c')
    source_file.write_text(body, encoding='utf-8')
    if selection != 'conservative_baseline':
        (output / (stem + '.baseline.c')).write_text(baseline, encoding='utf-8')
    unit = preamble+'\n\n'+body
    if selection in ('llm_reconstruction', 'llm_validation_probe'):
        from gamedecomp.ai_engine import abi_assertion
        unit += abi_assertion(baseline, record['name'], candidate=body) or ''
    unit_file.write_text(unit, encoding='utf-8')
    return {'source_file': str(source_file), 'unit_file': str(unit_file),
            'source_sha256': hashlib.sha256(body.encode()).hexdigest(),
            'preamble_sha256': hashlib.sha256(preamble.encode()).hexdigest(),
            'baseline_sha256': hashlib.sha256(baseline.encode()).hexdigest(), 'source_selection': selection,
            'identity_mapping': mapping,
            'identity_compile_flags': [f'-D{old}={new}' for old, new in sorted(mapping.items()) if old != new]}


def _command(command, *, timeout=30):
    process = subprocess.Popen([str(item) for item in command], stdin=subprocess.DEVNULL,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
    timed_out = False
    try:
        output, error = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        output, error = process.communicate()
    return {'command': [str(item) for item in command], 'returncode': process.returncode,
            'timed_out': timed_out, 'stdout': output.decode('utf-8', 'replace')[:16384],
            'stderr': error.decode('utf-8', 'replace')[:16384]}


def _compile_closure(closure, compiler, directory, *, compatibility=False, use_ai=False, validation_probe=False):
    artifacts, commands, objects = [], [], []
    for original, record in closure['records'].items():
        try:
            unit = write_recovered_unit(record, closure['identity_mapping'], directory, compatibility=compatibility,
                                        use_ai=use_ai, validation_probe=validation_probe)
        except ValueError as error:
            return {'status': 'UNKNOWN', 'reason': str(error), 'failed_function': original,
                    'artifacts': artifacts, 'compile_commands': commands, 'tested_cases': 0}
        unit['original_function'] = original
        artifacts.append(unit)
        object_file = directory / (original + '.o')
        command = _command([compiler, '-std=gnu11', '-O0', '-fPIC', '-Werror=implicit-function-declaration',
                            *unit['identity_compile_flags'], '-c', unit['unit_file'], '-o', object_file])
        commands.append(command)
        if command['returncode'] or command['timed_out']:
            return {'status': 'UNKNOWN', 'reason': 'Corpo recuperato non compilabile senza correzioni',
                    'failed_function': original, 'artifacts': artifacts, 'compile_commands': commands, 'tested_cases': 0}
        objects.append(object_file)
    library = directory / 'recovered.so'
    command = _command([compiler, '-shared', '-Wl,-z,defs', '-Wl,-Bsymbolic', *objects, '-o', library])
    commands.append(command)
    return {'status': 'UNKNOWN' if command['returncode'] or command['timed_out'] else 'AVAILABLE',
            'reason': 'Link della closure recuperata' if command['returncode'] else None,
            'library': str(library), 'artifacts': artifacts, 'compile_commands': commands, 'tested_cases': 0}


@lru_cache(maxsize=4)
def _guarded_types(length):
    """Place guards beside buffers without changing alignment or ABI."""
    import ctypes
    guard = ctypes.c_uint8 * 32

    class GuardedMemory(ctypes.Structure):
        _fields_ = [('before', guard), ('value', ctypes.c_uint8 * length), ('after', guard)]

    class GuardedScore(ctypes.Structure):
        _fields_ = [('before', guard), ('value', ctypes.c_uint32), ('after', guard)]

    return GuardedMemory, GuardedScore


def _guards_intact(guarded):
    return bytes(guarded.before) == b'\xa5' * 32 and bytes(guarded.after) == b'\x5a' * 32


def _observe(library, name, case):
    # Import and load ctypes only in the child worker. The parent Python
    # process never loads the native oracle or decompiled code.
    import ctypes
    function = getattr(library, name)
    u8, u32 = ctypes.c_uint8, ctypes.c_uint32
    pointer = ctypes.POINTER(u8)
    function.restype = None if name == 'rotateBoard' else u8
    if name == 'getDigitCount':
        function.argtypes = [u32]
        return {'return': int(function(case['number']))}
    values = case.get('array', case.get('board'))
    memory_type, score_type = _guarded_types(len(values))
    guarded_memory, guarded_score = memory_type(), score_type()
    for guarded in (guarded_memory, guarded_score):
        guarded.before[:] = b'\xa5' * 32
        guarded.after[:] = b'\x5a' * 32
    guarded_memory.value[:] = values
    guarded_score.value = case.get('score', 0)
    memory = guarded_memory.value
    arguments = [memory]
    function.argtypes = [pointer]
    if name == 'findTarget':
        function.argtypes.extend([u8, u8])
        arguments.extend((case['x'], case['stop']))
    elif name == 'slideArray' or name.startswith('move'):
        function.argtypes.append(ctypes.POINTER(u32))
        arguments.append(ctypes.cast(ctypes.byref(guarded_score, score_type.value.offset), ctypes.POINTER(u32)))
    returned = function(*arguments)
    result = {'return': None if returned is None else int(returned), 'memory': list(memory),
              'guards': {'memory_intact': _guards_intact(guarded_memory)}}
    if 'score' in case:
        result['score'] = guarded_score.value
        result['guards']['score_intact'] = _guards_intact(guarded_score)
    return result


def worker(job_path):
    import ctypes
    import resource
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_AS, (512 * 1024 * 1024, 512 * 1024 * 1024))
    resource.setrlimit(resource.RLIMIT_CPU, (10, 10))
    job = json.loads(Path(job_path).read_text())
    if job['function'] not in SPECS:
        raise ValueError('Funzione worker non supportata')
    original = ctypes.CDLL(job['original_library'], mode=os.RTLD_LOCAL)
    recovered = ctypes.CDLL(job['recovered_library'], mode=os.RTLD_LOCAL)
    expected, actual = [], []
    for case in job['cases']:
        expected.append(_observe(original, job['function'], case))
        actual.append(_observe(recovered, job['function'], case))
    print(json.dumps(compare_observations(job['cases'], expected, actual), allow_nan=False))


def summarize(rows):
    return {'target_functions': len(rows),
            'tested_functions': sum(row['status'] in ('MATCHED_FINITE_CASES', 'MISMATCH') for row in rows),
            'matched_functions': sum(row['status'] == 'MATCHED_FINITE_CASES' for row in rows),
            'mismatched_functions': sum(row['status'] == 'MISMATCH' for row in rows),
            'unknown_functions': sum(row['status'] == 'UNKNOWN' for row in rows),
            'tested_cases': sum(row.get('tested_cases', 0) for row in rows),
            'matched_cases': sum(row.get('matched_cases', 0) for row in rows),
            'mismatches': sum(row.get('mismatches', 0) for row in rows)}


def evaluate_report(source, report_path, addresses, output, *, compiler='gcc', random_cases=256, timeout=15, compatibility=False, use_ai=False):
    """Evaluate an existing report without passing ground truth to the pipeline."""
    source, report_path, output = Path(source).resolve(), Path(report_path).resolve(), Path(output).resolve()
    if hashlib.sha256(source.read_bytes()).hexdigest() != FILES['2048.c']:
        raise ValueError('SHA256 originale inatteso: nessuna esecuzione')
    check_original_signatures(source.read_text())
    if output.exists():
        raise ValueError('Directory differenziale già presente: scegliere una nuova directory')
    output.mkdir(parents=True)
    report_bytes = report_path.read_bytes()
    report = json.loads(report_bytes)
    report_snapshot = output / 'input-report.json'
    report_snapshot.write_bytes(report_bytes)
    original_library = output / 'original.so'
    original_compile = _command([compiler, '-std=c11', '-O0', '-fPIC', '-shared', '-Wl,-Bsymbolic', source, '-o', original_library])
    if original_compile['returncode'] or original_compile['timed_out']:
        raise RuntimeError('Compilazione oracolo originale fallita: ' + original_compile['stderr'])
    results = []
    for name, (signature, _) in SPECS.items():
        directory = output / name
        closure = recovered_closure(report, addresses, name)
        row = {'function': name, 'original_abi': signature, 'planned_cases': len(function_cases(name, random_cases=random_cases))}
        if closure['status'] != 'AVAILABLE':
            row.update(closure)
        else:
            row.update(_compile_closure(closure, compiler, directory, compatibility=compatibility, use_ai=use_ai))
            if row['status'] == 'AVAILABLE':
                cases = function_cases(name, random_cases=random_cases)
                job = {'function': name, 'original_library': str(original_library),
                       'recovered_library': row['library'], 'cases': cases}
                job_path = directory / 'worker-input.json'
                job_path.write_text(json.dumps(job, indent=2) + '\n')
                process = _command([sys.executable, Path(__file__).resolve(), '--trusted', '--worker', job_path], timeout=timeout)
                row['worker'] = process
                row['cases_sha256'] = hashlib.sha256(json.dumps(cases, sort_keys=True).encode()).hexdigest()
                if process['returncode'] or process['timed_out']:
                    row.update(status='UNKNOWN', reason='Worker terminato, errore o timeout', tested_cases=0)
                else:
                    try:
                        row.update(json.loads(process['stdout']))
                    except (json.JSONDecodeError, TypeError):
                        row.update(status='UNKNOWN', reason='Risultato worker non valido', tested_cases=0)
        results.append(row)
        print(f"{name}: {row['status']} ({row.get('tested_cases', 0)}/{row['planned_cases']} casi)", flush=True)
    result = {'schema_version': 1, 'report': str(report_path), 'report_snapshot': str(report_snapshot),
              'report_sha256': hashlib.sha256(report_bytes).hexdigest(),
              'backend': report.get('backend'), 'original_source_sha256': FILES['2048.c'],
              'compatibility_enabled': compatibility,
              'llm_candidates_enabled': use_ai,
              'original_compile': original_compile, 'random_seed': SEED, 'random_cases': random_cases,
              'execution': 'Librerie caricate esclusivamente in worker figlio, nuova sessione, timeout e limiti risorse; non sandbox generale',
              'limitations': ['Casi finiti sotto il contratto ABI originale, nessuna equivalenza universale.',
                              'Solo 11 funzioni deterministiche delle 19 originali; I/O, tempo, random e gioco interattivo esclusi.',
                              'Baseline conservate; traduzioni di compatibilità solo se abilitate, compilate e con hash verificati. Selezione e rinominazioni identità registrate; nessun helper originale collegato alla closure recuperata.',
                              'Sentinelle di 32 byte prima/dopo array e score rilevano corruzioni adiacenti; non provano assenza di letture/scritture fuori limite in generale.',
                              'Array contengono esponenti 0..12 nei casi casuali; nessuno shift signed fuori dominio definito.'],
              'summary': summarize(results), 'functions': results}
    (output / 'verification.json').write_text(json.dumps(result, indent=2, ensure_ascii=False, allow_nan=False) + '\n')
    return result


def evaluate_benchmark(manifest_path, output, *, random_cases=256, timeout=15, compatibility=False):
    manifest_path, output = Path(manifest_path).resolve(), Path(output).resolve()
    manifest = json.loads(manifest_path.read_text())
    source = manifest_path.parent / 'source' / '2048.c'
    results = []
    for build in manifest['builds']:
        report = json.loads(Path(build['runs'][0]['report']).read_text())
        if report.get('input', {}).get('sha256', report.get('binary_hash')) != build['binary_sha256']:
            raise ValueError('Il report non corrisponde al binario della variante: ' + build['variant'])
        symbols = Path(build['binary']).parent / 'symbols-ground-truth.txt'
        addresses, adjustment = mapped_symbol_addresses(build['binary'], report, symbols.read_text(), set(manifest['authored_functions']))
        result = evaluate_report(source, build['runs'][0]['report'], addresses, output / build['variant'],
                                 compiler=build.get('compiler_path') or shutil.which('gcc'),
                                 random_cases=random_cases, timeout=timeout, compatibility=compatibility)
        result['evaluation_address_adjustment'] = adjustment
        (output / build['variant'] / 'verification.json').write_text(json.dumps(result, indent=2, ensure_ascii=False)+'\n')
        results.append({'variant': build['variant'], 'verification': result})
    combined = {'status': 'EXECUTED', 'builds': results,
                'summary': summarize([row for result in results for row in result['verification']['functions']]),
                'limitations': 'Le stesse suite finite sono ripetute sulle varianti; il numero totale non conta input unici.'}
    (output / 'verification.json').write_text(json.dumps(combined, indent=2, ensure_ascii=False) + '\n')
    return combined


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--trusted', action='store_true', help='Autorizza compilazione ed esecuzione di oracolo MIT fissato e corpi recuperati')
    parser.add_argument('--benchmark', type=Path)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--random-cases', type=int, default=256)
    parser.add_argument('--timeout', type=float, default=15)
    parser.add_argument('--compatibility', action='store_true', help='Valuta anche le traduzioni SIMD esplicite già compilate')
    parser.add_argument('--worker', type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    if not args.trusted:
        parser.error('Richiesto --trusted per compilare ed eseguire codice nativo')
    if args.worker:
        worker(args.worker)
        return 0
    if not args.benchmark or not args.output:
        parser.error('Specificare --benchmark e --output')
    if not 0 <= args.random_cases <= 4096 or not 0 < args.timeout <= 60:
        parser.error('random-cases tra 0 e 4096 e timeout tra 0 e 60 secondi')
    evaluate_benchmark(args.benchmark, args.output, random_cases=args.random_cases, timeout=args.timeout, compatibility=args.compatibility)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
