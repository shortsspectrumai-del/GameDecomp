"""Optional ILSpy CLI adapter for managed assemblies."""
import hashlib
import math
import shutil
import tempfile
from pathlib import Path

from gamedecomp.models import Analysis, Function
from gamedecomp.validation import _capture_compiler


def analyze(path: Path, timeout: float = 60) -> Analysis:
    if (isinstance(timeout, bool) or not isinstance(timeout, (int, float))
            or not math.isfinite(timeout) or timeout <= 0):
        raise ValueError('timeout must be a finite positive number')
    executable = shutil.which('ilspycmd')
    if executable is None:
        raise RuntimeError('Backend .NET non disponibile: installare ilspycmd e un runtime .NET compatibile')
    with tempfile.TemporaryDirectory(prefix='gamedecomp-ilspy-') as directory:
        code, output, timed_out, output_limited = _capture_compiler(
            [str(Path(executable).resolve()), '-p', '-o', directory, str(Path(path).resolve())],
            directory, float(timeout))
        if timed_out:
            raise TimeoutError('ILSpy ha superato il tempo limite')
        if output_limited:
            raise RuntimeError('ILSpy ha superato il limite di output diagnostico')
        if code:
            raise RuntimeError('ILSpy non ha recuperato il progetto: ' + output[:8192].decode(errors='replace'))
        analysis = Analysis(hashlib.sha256(Path(path).read_bytes()).hexdigest(), 'PE', 'dotnet-il', 'ilspy')
        for index, source in enumerate(sorted(Path(directory).rglob('*.cs'))):
            if source.stat().st_size > 4 * 1024 * 1024:
                analysis.diagnostics.append(f'Unità C# troppo grande: {source.name}')
                continue
            analysis.functions.append(Function(f'dotnet:{index}', str(source.relative_to(directory)), index,
                                               source=source.read_text(encoding='utf-8-sig'),
                                               metadata={'language': 'csharp', 'unit': 'compilation_unit',
                                                         'recovery_scope': 'ILSpy managed compilation unit'}))
        analysis.metadata['unit_count_label'] = 'C# compilation units, not individual native functions'
        return analysis
