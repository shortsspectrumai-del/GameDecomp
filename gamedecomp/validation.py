"""Compile recovered source without executing it.

The selected compiler is a trusted local tool. It runs as a normal subprocess,
NOT in a security sandbox: preprocessing can access files and compiler bugs can
have effects. Temporary files, deadlines and diagnostic limits provide resource
bounds, not isolation. COMPILED says nothing about behavioral equivalence.
"""
from __future__ import annotations

import math
import os
import selectors
import shutil
import signal
import subprocess
import tempfile
import time
from pathlib import Path

MAX_SOURCE_BYTES = 1_000_000
MAX_OUTPUT_BYTES = 262_144


def _stop_compiler(process: subprocess.Popen) -> None:
    if os.name == 'posix':
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    elif process.poll() is None:
        process.kill()
    process.wait()


def _capture_compiler(command: list[str], directory: str, timeout: float) -> tuple:
    output = bytearray()
    timed_out = False
    output_limited = False
    deadline = time.monotonic() + timeout
    process = subprocess.Popen(command, cwd=directory, stdin=subprocess.DEVNULL,
                               stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                               start_new_session=(os.name == 'posix'))
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    timed_out = True
                    _stop_compiler(process)
                    break
                for key, _ in selector.select(min(remaining, 0.1)):
                    chunk = os.read(key.fd, min(65_536, MAX_OUTPUT_BYTES + 1 - len(output)))
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    output.extend(chunk)
                    if len(output) > MAX_OUTPUT_BYTES:
                        output_limited = True
                        _stop_compiler(process)
                        break
                if output_limited:
                    break
        if not timed_out and not output_limited:
            try:
                process.wait(timeout=max(0.001, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                timed_out = True
                _stop_compiler(process)
    finally:
        if process.poll() is None:
            _stop_compiler(process)
        if process.stdout is not None:
            process.stdout.close()
    return process.returncode, bytes(output[:MAX_OUTPUT_BYTES]), timed_out, output_limited


def compile_source(source: str, *, compiler: str | None = None,
                   timeout: float = 30, language: str = 'c', strict: bool = False) -> dict:
    """Compile a bounded C translation unit to an object, or report UNKNOWN.

    ``language='c++'`` optionally selects C++17 and a C++ compiler. No linking,
    loading, dynamic tests or binary execution occurs. Invalid configuration
    raises TypeError/ValueError; missing tools and interrupted checks are UNKNOWN.

    ``strict=True`` rejects compiler-detected missing returns and uninitialized
    reads. Modest optimization enables flow diagnostics; it is not a general
    proof that the source is free of undefined behavior. Unused parameters and
    helpers are intentionally outside this diagnostic policy.
    In particular, GCC may optimize away a conditionally uninitialized read
    before diagnosing it; Clang detects some such paths that GCC misses.
    """
    if not isinstance(source, str):
        raise TypeError('source must be a string')
    try:
        if len(source) > MAX_SOURCE_BYTES or len(source.encode('utf-8')) > MAX_SOURCE_BYTES:
            raise ValueError('source exceeds the size limit')
    except UnicodeEncodeError:
        raise ValueError('source must contain valid Unicode') from None
    if '\x00' in source:
        raise ValueError('source must not contain NUL characters')
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)):
        raise ValueError('timeout must be a finite positive number')
    if not math.isfinite(timeout) or timeout <= 0:
        raise ValueError('timeout must be a finite positive number')
    if language not in ('c', 'c++'):
        raise ValueError('language must be c or c++')
    if type(strict) is not bool:
        raise TypeError('strict must be a boolean')
    if compiler is not None and (not isinstance(compiler, str) or not compiler or '\x00' in compiler):
        raise ValueError('compiler must name a trusted executable')
    candidates = ('gcc', 'clang') if language == 'c' else ('g++', 'clang++')
    executable = shutil.which(compiler) if compiler is not None else next(
        (found for name in candidates if (found := shutil.which(name))), None)
    if executable is not None:
        executable = os.path.abspath(executable)
    flags = ['-x', language, '-std=c11' if language == 'c' else '-std=c++17']
    if language == 'c':
        flags.append('-Werror=implicit-function-declaration')
    if strict:
        flags.extend(['-O1', '-Werror=return-type', '-Werror=uninitialized'])
    for header in ('stdint.h', 'stddef.h', 'stdbool.h'):
        flags.extend(['-include', header])
    flags.append('-c')
    result = {
        'status': 'UNKNOWN', 'diagnostics': [], 'returncode': None,
        'timed_out': False, 'output_limited': False,
        'toolchain': {'compiler': executable, 'requested_compiler': compiler,
                      'language': language, 'flags': flags, 'sandboxed': False, 'strict': strict},
    }
    if executable is None:
        result['diagnostics'].append('No compatible compiler executable was found')
        return result
    try:
        with tempfile.TemporaryDirectory(prefix='gamedecomp-compile-') as directory:
            src = Path(directory) / ('source.c' if language == 'c' else 'source.cpp')
            obj = Path(directory) / 'source.o'
            src.write_text(source, encoding='utf-8')
            command = [executable, *flags, str(src), '-o', str(obj)]
            code, output, timed_out, output_limited = _capture_compiler(command, directory, float(timeout))
            result['returncode'] = code
            result['timed_out'] = timed_out
            result['output_limited'] = output_limited
            text = output.decode('utf-8', errors='replace').replace(directory, '<temporary>')
            result['diagnostics'] = text.splitlines()
            if timed_out:
                result['diagnostics'].append('Compiler timeout: compilation result is unknown')
            elif output_limited:
                result['diagnostics'].append('Compiler diagnostic output limit exceeded: result is unknown')
            elif code == 0 and obj.is_file():
                result['status'] = 'COMPILED'
            elif code == 0:
                result['diagnostics'].append('Compiler produced no object file: result is unknown')
            elif code < 0:
                result['diagnostics'].append('Compiler was terminated: result is unknown')
            else:
                result['status'] = 'COMPILE_FAILED'
    except OSError:
        result['diagnostics'].append('Compiler could not run or temporary compilation files were inaccessible')
    return result
