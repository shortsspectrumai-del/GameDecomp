"""Optional real Ghidra headless frontend; never downloads dependencies."""
import hashlib
import json
import math
import os
import tempfile
from pathlib import Path

from gamedecomp.models import Analysis
from gamedecomp.validation import _capture_compiler

MAX_PREAMBLE_BYTES = 262_144
_CONSOLE_PROCESSOR_IDS = frozenset({
    'AARCH64:LE:64:v8A', 'MIPS:LE:32:default', 'ARM:LE:32:v4t',
    'PowerPC:BE:32:default', '6502:LE:16:default', '68000:BE:32:default',
})


def analyze(path: Path, *, ghidra_home: Path | None = None, timeout: float = 60,
            raw_processor=None, raw_base=None, entry_point=None, processor_id=None) -> Analysis:
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not math.isfinite(timeout) or timeout <= 0:
        raise ValueError('Timeout non valido')
    if processor_id is not None and (not isinstance(processor_id, str) or
            processor_id not in _CONSOLE_PROCESSOR_IDS or raw_processor is not None):
        raise ValueError('Invalid or conflicting console processor override')
    if raw_processor is not None and (raw_processor != '6502:LE:16:default' or raw_base != 0x8000 or
                                     type(entry_point) is not int or not 0x8000 <= entry_point <= 0xffff):
        raise ValueError('Invalid NES static loader mapping')
    if entry_point is not None and (type(entry_point) is not int or not 0 <= entry_point <= 0xffffffff):
        raise ValueError('Invalid console static entry address')
    home = Path(ghidra_home or os.environ.get('GHIDRA_HOME', ''))
    executable = home / 'support' / ('analyzeHeadless.bat' if os.name == 'nt' else 'analyzeHeadless')
    if not executable.is_file():
        raise RuntimeError('Ghidra non disponibile: impostare --ghidra-home o GHIDRA_HOME')
    executable = executable.resolve()
    scripts = Path(__file__).resolve().parents[1] / 'ghidra_scripts'
    with tempfile.TemporaryDirectory(prefix='gamedecomp-ghidra-') as directory:
        export = Path(directory) / 'analysis.json'
        command = [str(executable), directory, 'analysis', '-import', str(Path(path).resolve()),
                   '-max-cpu', '1', '-analysisTimeoutPerFile', str(max(1, int(timeout))),
                   '-scriptPath', str(scripts), '-postScript', 'ExportGameDecomp.java', str(export), '-deleteProject']
        if raw_processor is not None:
            command += ['-loader', 'BinaryLoader', '-loader-baseAddr', '0x8000',
                        '-processor', raw_processor]
        elif processor_id is not None:
            # Keep the structured ELF loader while pinning the console instruction set.
            command += ['-processor', processor_id]
        if entry_point is not None:
            command += ['-preScript', 'PrepareConsoleEntry.java', hex(entry_point)]
        code, output, timed_out, limited = _capture_compiler(command, directory, timeout)
        if timed_out:
            raise TimeoutError('Ghidra oltre il timeout; nessun risultato completo pubblicato')
        if limited:
            raise RuntimeError('Ghidra diagnostic output oltre il limite di 256 KiB')
        if code or not export.is_file():
            diagnostics = output[:16384].decode('utf-8', errors='replace')
            raise RuntimeError('Esportazione Ghidra fallita: ' + diagnostics)
        if entry_point is not None and b'REPORT SCRIPT ERROR' in output:
            raise RuntimeError('Console entry initialization failed; no complete analysis exported')
        if export.stat().st_size > 128 * 1024 * 1024:
            raise ValueError('Output Ghidra oltre il limite')
        result = Analysis.from_dict(json.loads(export.read_text(encoding='utf-8')))
        if entry_point is not None and not any(function.address == entry_point for function in result.functions):
            raise RuntimeError('Console entry function missing; static import is incomplete')
        for function in result.functions:
            preamble = function.metadata.get('compile_preamble')
            if preamble is not None and (not isinstance(preamble, str) or
                    len(preamble.encode('utf-8')) > MAX_PREAMBLE_BYTES or '\x00' in preamble):
                raise ValueError('Ghidra compile_preamble non valido o oltre il limite di 256 KiB')
            if preamble is None or function.metadata.get('compile_preamble_status') != 'AVAILABLE':
                function.metadata['compile_preamble'] = ''
                function.metadata['compile_preamble_status'] = 'UNAVAILABLE'
            function.metadata['semantic_status'] = 'UNKNOWN'
        result.binary_hash = hashlib.sha256(Path(path).read_bytes()).hexdigest()
        result.backend = 'ghidra'
        result.metadata['dependency_status'] = 'Ghidra headless invoked successfully; version recorded when available'
        result.metadata['semantic_status'] = 'UNKNOWN'
        result.metadata.setdefault('frontend_version', 'UNKNOWN')
        return result
