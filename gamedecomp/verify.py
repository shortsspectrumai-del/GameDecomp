"""Opt-in return-value testing of trusted shared ELF files and recovered C.

TESTED is finite differential evidence under an inferred ABI, never a proof.
Native code is loaded only in disposable child processes, not in this module.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import re
import selectors
import shutil
import signal
import subprocess
import sys
import tempfile
import time

from gamedecomp.csyntax import function_header


_CAPTURE_BYTES = 64 * 1024
_MAX_REPORT_BYTES = 32 * 1024 * 1024
_SCOPE = 'return-values under inferred scalar ABI'


def _limits(cases: int, timeout: float, workers: int) -> None:
    for name, value, maximum in [('cases', cases, 100_000), ('workers', workers, 64)]:
        if type(value) is not int or not 1 <= value <= maximum:
            raise ValueError(f'{name} deve essere un intero tra 1 e {maximum}')
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not math.isfinite(timeout) or timeout <= 0:
        raise ValueError('timeout deve essere finito e positivo')


def _run_bounded(arguments: list[str], timeout: float, *, cwd: Path) -> tuple[int | None, str, str, str | None]:
    """Bound capture in memory and kill the process group, including on success."""
    if timeout <= 0:
        return None, '', '', 'Budget totale di verifica esaurito'
    try:
        process = subprocess.Popen(arguments, stdin=subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   cwd=cwd, start_new_session=True)
    except OSError as error:
        return None, '', '', f'Avvio processo fallito: {error}'
    captured = {'stdout': bytearray(), 'stderr': bytearray()}
    problem = None
    deadline = time.monotonic() + timeout
    try:
        with selectors.DefaultSelector() as selector:
            for name, stream in [('stdout', process.stdout), ('stderr', process.stderr)]:
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ, name)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    problem = f'Timeout processo dopo {timeout:g} secondi'
                    break
                events = selector.select(min(remaining, 0.05))
                for key, _ in events:
                    chunk = os.read(key.fileobj.fileno(), 8192)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    buffer = captured[key.data]
                    available = _CAPTURE_BYTES - len(buffer)
                    buffer.extend(chunk[:available])
                    if len(chunk) > available:
                        problem = f'Output processo oltre il limite di {_CAPTURE_BYTES} byte'
                        break
                if problem:
                    break
            if not problem:
                try:
                    process.wait(timeout=max(0.001, deadline - time.monotonic()))
                except subprocess.TimeoutExpired:
                    problem = f'Timeout processo dopo {timeout:g} secondi'
    finally:
        # A child may exit while a spawned descendant still owns its pipes.
        # Killing the session group handles ordinary descendants in either case.
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()
        process.stdout.close()
        process.stderr.close()
    return (process.returncode, captured['stdout'].decode('utf-8', errors='replace'),
            captured['stderr'].decode('utf-8', errors='replace'), problem)


def _shared_elf_problem(path: Path) -> str | None:
    if sys.platform != 'linux' or platform.machine().lower() not in ('x86_64', 'amd64'):
        return 'Verifica disponibile solo su host Linux x86-64 SysV'
    if not re.search(r'\.so(?:\.[0-9]+)*$', path.name):
        return 'Verifica eseguibile solo per librerie ELF condivise .so fidate'
    with path.open('rb') as stream:
        header = stream.read(64)
    if (len(header) != 64 or header[:7] != b'\x7fELF\x02\x01\x01'
            or int.from_bytes(header[16:18], 'little') != 3
            or int.from_bytes(header[18:20], 'little') != 62):
        return 'Richiesta una libreria ELF64 condivisa little-endian x86-64 (ET_DYN)'
    return None


def _function_problem(function: dict, selection: str | None = None) -> str | None:
    source = function.get('source')
    if not isinstance(source, str) or not source.strip():
        return 'Nessuna sorgente conservativa scalare disponibile'
    if len(source.encode('utf-8')) > 1024 * 1024:
        return 'Sorgente oltre il limite di 1 MiB per funzione'
    metadata = function.get('metadata', {})
    if not isinstance(metadata, dict) or metadata.get('language', 'c') != 'c':
        return 'Solo sorgenti C scalari supportate'
    allowed = (None, 'conservative_baseline') if selection is None else (selection,)
    if selection not in (None, 'conservative_baseline', 'llm_candidate') or function.get('selected_source') not in allowed:
        return 'Solo la sorgente conservativa del report viene verificata'
    widths = metadata.get('parameter_bits')
    if (not isinstance(widths, list) or len(widths) > 6
            or any(type(width) is not int or width not in (32, 64) for width in widths)
            or type(metadata.get('return_bits')) is not int or metadata['return_bits'] not in (32, 64)):
        return 'ABI scalare incompleta: richiesti argomenti e ritorno unsigned 32/64 bit'
    export = metadata.get('export_name')
    if not isinstance(export, str) or not re.fullmatch(r'[A-Za-z][A-Za-z0-9_]*', export):
        return 'Nome export C assente o non valido'
    original = metadata.get('original_symbol')
    if not isinstance(original, str) or not original or '\x00' in original or len(original) > 1024:
        return 'Simbolo originale assente o non valido'
    if selection == 'llm_candidate':
        header = function_header(source, export)
        if not header or header[0] != f"uint{metadata['return_bits']}_t":
            return 'Firma C non corrispondente ai metadati ABI scalari'
        arguments = header[1].strip()
    else:
        clean = re.sub(r'/\*.*?\*/|//[^\n]*', '', source, flags=re.S)
        signature = re.search(r'\buint' + str(metadata['return_bits']) + r'_t\s+' + re.escape(export)
                              + r'\s*\(([^)]*)\)\s*\{', clean)
        if not signature:
            return 'Firma C non corrispondente ai metadati ABI scalari'
        arguments = signature.group(1).strip()
    parameters = [] if arguments in ('', 'void') else arguments.split(',')
    if len(parameters) != len(widths) or any(
            not re.fullmatch(r'\s*uint' + str(width) + r'_t\s+[A-Za-z_][A-Za-z0-9_]*\s*', parameter)
            for width, parameter in zip(widths, parameters)):
        return 'Parametri C non corrispondenti ai metadati ABI scalari'
    return None


def _candidate_function(function: dict) -> tuple[dict, str | None]:
    """Select the exact compiled candidate for explicit finite verification.

    Pending selection_eligible=False is intentionally allowed here: this check
    supplies the evidence needed to decide eligibility. Known DISPROVED bodies
    remain excluded. Invalid candidates never silently fall back to a baseline.
    """
    candidate = function.get('candidate')
    if not isinstance(candidate, dict):
        return function, 'Nessuna candidata AI disponibile per la verifica esplicita'
    source, baseline = candidate.get('source'), function.get('source')
    compilation = candidate.get('compilation')
    if (not isinstance(source, str) or not source.strip() or '\x00' in source
            or baseline is not None and not isinstance(baseline, str)
            or not isinstance(compilation, dict) or compilation.get('status') != 'COMPILED'
            or compilation.get('abi_check') not in ('COMPILER_ABI_SHAPE', 'COMPILER_TYPE_IDENTITY')
            or candidate.get('semantic_status') == 'DISPROVED'):
        return function, 'Candidata AI non compilata, ABI indisponibile o già DISPROVED'
    try:
        if (candidate.get('source_sha256') != hashlib.sha256(source.encode('utf-8')).hexdigest()
                or candidate.get('baseline_sha256') != hashlib.sha256((baseline or '').encode('utf-8')).hexdigest()):
            return function, 'Hash della candidata AI o della baseline discordante'
        support = candidate.get('compile_support', '')
        if not isinstance(support, str) or '\x00' in support or len((source+support).encode('utf-8')) > 1024*1024:
            return function, 'Supporto di compilazione della candidata AI non valido'
    except UnicodeError:
        return function, 'Sorgente candidata AI Unicode non valida'
    return dict(function, source=source, selected_source='llm_candidate',
                _verification_support=support), None


def _unknown(record: dict, reason: str) -> None:
    record.update(status='UNKNOWN', semantic_status='UNKNOWN', diagnostics=[reason], mismatches=0)


def _finish(result: dict) -> dict:
    records = result['functions']
    result['summary'] = {
        'total': len(records), 'recovered': sum(bool(item['has_source']) for item in records),
        'eligible': sum(not item['skipped'] for item in records),
        'tested': sum(item['semantic_status'] == 'TESTED' for item in records),
        'mismatches': sum(item['semantic_status'] == 'DISPROVED' for item in records),
        'unknown': sum(item['semantic_status'] == 'UNKNOWN' for item in records),
        'skipped': sum(item['skipped'] for item in records), 'proved': 0,
        'cases_checked': sum(item['cases_checked'] for item in records),
    }
    result['status'] = ('DISPROVED' if result['summary']['mismatches'] else
                        'TESTED' if result['summary']['tested'] else 'UNKNOWN')
    return result


def verify_report(binary: Path, report_path: Path, *, trusted: bool = False,
                  cases: int = 128, timeout: float = 30, workers: int = 4,
                  use_candidates: bool = False) -> dict:
    """Test trusted originals against conservative sources in a JSON report.

    Both artifacts must be trusted: ELF constructors and recovered C can run
    arbitrary native code. No library is loaded into the calling Python process.
    """
    if trusted is not True:
        raise PermissionError('Verifica dinamica rifiutata: usare trusted=True solo per binario e sorgente fidati')
    if type(use_candidates) is not bool:
        raise TypeError('use_candidates deve essere booleano')
    _limits(cases, timeout, workers)
    started = time.monotonic()
    deadline = started + timeout
    binary, report_path = Path(binary).resolve(strict=True), Path(report_path).resolve(strict=True)
    if not binary.is_file() or not report_path.is_file():
        raise ValueError('Binario e report devono essere file regolari')
    if binary.stat().st_size > 256 * 1024 * 1024:
        raise ValueError('Binario oltre il limite di 256 MiB')
    if report_path.stat().st_size > _MAX_REPORT_BYTES:
        raise ValueError('Report oltre il limite di 32 MiB')
    report = json.loads(report_path.read_text(encoding='utf-8'))
    if not isinstance(report, dict) or not isinstance(report.get('input'), dict):
        raise ValueError('Report privo di metadati input validi')
    digest = hashlib.sha256()
    with binary.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
    actual_hash = digest.hexdigest()
    if report['input'].get('sha256') != actual_hash:
        raise ValueError('SHA256 del binario diverso da input.sha256 nel report')
    functions = report.get('functions')
    if not isinstance(functions, list) or len(functions) > 4096 or any(not isinstance(item, dict) for item in functions):
        raise ValueError('Elenco funzioni del report non valido o oltre il limite di 4096')
    result = {
        'schema_version': 1, 'input': {'path': str(binary), 'sha256': actual_hash},
        'analysis_report': str(report_path), 'scope': _SCOPE, 'cases_requested': cases,
        'execution': {'workers': workers, 'timeout_seconds': timeout, 'trusted': True,
                      'native_loading': 'child processes only'},
        'use_candidates': use_candidates,
        'functions': [],
        'limitations': [
            'TESTED confronta valori di ritorno su un insieme finito; non prova equivalenza generale.',
            'Firma, signedness e tipi originali sono inferiti; memoria, effetti collaterali e ABI reali non sono verificati.',
            'Binario originale e C recuperato devono essere fidati: anche i costruttori ELF vengono eseguiti.',
            'Processi figli con timeout, limiti risorse e gruppi di processi non costituiscono una sandbox di sicurezza.',
            ('Selezionate soltanto candidate AI compilate, vincolate agli hash e con controllo ABI; nessun ripiego baseline.'
             if use_candidates else
             'Le sorgenti conservative nel report JSON sono autorevoli; candidate AI ed export recovered.c separati non vengono selezionati.'),
        ],
    }
    global_problem = _shared_elf_problem(binary)
    if report.get('backend') not in ('native', 'native-objdump'):
        global_problem = 'Verifica dinamica disponibile solo per il backend native scalare'
    report_metadata = report.get('metadata', {})
    if isinstance(report_metadata, dict) and report_metadata.get('abi', 'sysv-amd64') != 'sysv-amd64':
        global_problem = 'ABI del report diversa da SysV AMD64'
    eligible = []
    used_exports = set()
    for index, function in enumerate(functions):
        selection = 'llm_candidate' if use_candidates else 'conservative_baseline'
        selection_problem = None
        if use_candidates:
            function, selection_problem = _candidate_function(function)
        source = function.get('source')
        if use_candidates and selection_problem:
            candidate = function.get('candidate')
            source = candidate.get('source') if isinstance(candidate, dict) else None
        source_hash = hashlib.sha256(source.encode('utf-8')).hexdigest() if isinstance(source, str) else None
        record = {'id': function.get('id', str(index)), 'name': function.get('name', str(index)),
                  'status': 'UNKNOWN', 'semantic_status': 'UNKNOWN', 'scope': _SCOPE,
                  'cases_requested': cases, 'cases_checked': 0, 'diagnostics': [],
                  'has_source': bool(source), 'skipped': True,
                  'source_selection': selection, 'source_sha256': source_hash,
                  'source_origin': 'llm_reconstruction_engine' if use_candidates else 'conservative_frontend',
                  'candidate_source_sha256': source_hash if use_candidates and not selection_problem else None,
                  'mismatches': 0}
        result['functions'].append(record)
        problem = global_problem or selection_problem or _function_problem(function, selection='llm_candidate' if use_candidates else None)
        export = function.get('metadata', {}).get('export_name') if isinstance(function.get('metadata'), dict) else None
        if not problem and export in used_exports:
            problem = 'Export duplicato nel report'
        if problem:
            _unknown(record, problem)
            continue
        used_exports.add(export)
        record['skipped'] = False
        eligible.append((index, function, record))
    if not eligible:
        return _finish(result)
    compiler = shutil.which('gcc')
    if not compiler:
        for _, _, record in eligible:
            _unknown(record, 'GCC non disponibile: sorgente recuperata non compilata')
        return _finish(result)
    with tempfile.TemporaryDirectory(prefix='gamedecomp-verify-') as directory:
        work = Path(directory)
        recovered_c, recovered_so = work / 'recovered.c', work / 'recovered.so'
        recovered_c.write_text('#include <stdint.h>\n\n' + '\n\n'.join(
            f.get('_verification_support', '')+'\n'+f['source'] if use_candidates else f['source']
            for _, f, _ in eligible), encoding='utf-8')
        code, _, errors, problem = _run_bounded(
            [compiler, '-std=c11', '-O2', '-fPIC', '-shared', '-Wl,-Bsymbolic',
             str(recovered_c), '-o', str(recovered_so)], deadline - time.monotonic(), cwd=work)
        if problem or code != 0:
            diagnostic = problem or f'Compilazione recuperata fallita (exit {code}): {errors[:8192]}'
            for _, _, record in eligible:
                _unknown(record, diagnostic)
            return _finish(result)

        def compare(item):
            index, function, record = item
            metadata = function['metadata']
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                _unknown(record, 'Budget totale di verifica esaurito')
                return
            seed = int(hashlib.sha256((actual_hash + '\0' + metadata['export_name']).encode()).hexdigest(), 16)
            specification = {
                'original': str(binary), 'recovered': str(recovered_so), 'sha256': actual_hash,
                'original_symbol': metadata['original_symbol'], 'export_name': metadata['export_name'],
                'parameter_bits': metadata['parameter_bits'], 'return_bits': metadata['return_bits'],
                'cases': cases, 'seed': seed, 'timeout': remaining,
            }
            record['seed'] = seed
            record['parameter_bits'], record['return_bits'] = metadata['parameter_bits'], metadata['return_bits']
            payload = work / f'function-{index}.json'
            payload.write_text(json.dumps(specification), encoding='utf-8')
            code, output, errors, problem = _run_bounded(
                [sys.executable, '-I', '-B', str(Path(__file__).with_name('verify_worker.py')), str(payload)],
                deadline - time.monotonic(), cwd=work)
            if problem:
                _unknown(record, problem)
                return
            if code != 0:
                _unknown(record, f'Worker terminato con exit {code}; crash/caricamento fallito. {errors[:2048]}')
                return
            try:
                observed = json.loads(output)
                status = observed['status']
                checked = observed['cases_checked']
                if (status not in ('TESTED', 'DISPROVED') or type(checked) is not int
                        or not 1 <= checked <= cases or (status == 'TESTED' and checked != cases)):
                    raise ValueError('Risultato worker incompleto/non valido')
                record.update(status=status, semantic_status=status, cases_checked=checked,
                              mismatches=1 if status == 'DISPROVED' else 0)
                if status == 'DISPROVED':
                    counterexample = observed['counterexample']
                    if (not isinstance(counterexample, dict)
                            or counterexample.get('original') == counterexample.get('recovered')):
                        raise ValueError('Controesempio worker non valido')
                    record['counterexample'] = counterexample
            except (ValueError, KeyError, TypeError) as error:
                record['cases_checked'] = 0
                _unknown(record, f'Output worker non valido: {error}; {output[:1024]}')

        with ThreadPoolExecutor(max_workers=workers, thread_name_prefix='gd-verify') as executor:
            list(executor.map(compare, eligible))
    result['elapsed_seconds'] = time.monotonic() - started
    return _finish(result)


def run_demo(output: Path, *, workers: int = 4, cases: int = 128) -> dict:
    """Compile and verify only the small fixture shipped with this project."""
    _limits(cases, 30, workers)
    from gamedecomp.pipeline import AnalysisConfig, run_analysis
    output = Path(output).resolve()
    # A demo owns one new directory and never overwrites an earlier run.
    output.mkdir(parents=True, exist_ok=False)
    compiler = shutil.which('gcc')
    if not compiler:
        raise RuntimeError('GCC richiesto per compilare la fixture demo fidata')
    fixture = Path(__file__).parent / 'data' / 'demo_game.c'
    source, binary = output / 'demo_game.c', output / 'demo_game.so'
    shutil.copyfile(fixture, source)
    code, _, errors, problem = _run_bounded(
        [compiler, '-shared', '-fPIC', '-O2', str(source), '-o', str(binary)], 30, cwd=output)
    if problem or code != 0:
        raise RuntimeError(problem or f'Compilazione demo fallita: {errors[:8192]}')
    analysis = run_analysis(binary, output / 'analysis', AnalysisConfig(
        backend='native', workers=workers, cache_path=output / 'cache.sqlite', function_pattern='game_*'))
    report_path = output / 'analysis' / 'report.json'
    verification = verify_report(binary, report_path, trusted=True, workers=workers, cases=cases)
    verification_path = output / 'verification.json'
    verification_path.write_text(json.dumps(verification, indent=2, ensure_ascii=False, allow_nan=False), encoding='utf-8')
    return {'output': str(output), 'binary': str(binary), 'report': str(report_path),
            'report_path': str(report_path), 'verification': str(verification_path),
            'verification_path': str(verification_path), 'recovered': analysis['summary']['recovered'],
            'tested': verification['summary']['tested'], 'mismatches': verification['summary']['mismatches'],
            'total': verification['summary']['total'], 'summary': verification['summary']}
