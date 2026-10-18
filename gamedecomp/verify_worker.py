"""Child-only loader for explicitly trusted differential verification.

Run as a standalone script under Python -I. Process separation and resource
limits contain common crashes and hangs; they are not a security sandbox.
"""
from __future__ import annotations

import hashlib
import json
import math
from pathlib import Path
import random
import sys


def _inputs(widths: list[int], count: int, seed: int):
    boundaries = []
    for width in widths:
        mask = (1 << width) - 1
        boundaries.append([0, 1, 2, mask, mask - 1, 1 << (width - 1),
                           (1 << (width - 1)) - 1, mask // 3, (mask // 3) * 2])
    emitted = 0
    for position in range(9):
        if emitted >= count:
            return
        yield tuple(values[position] for values in boundaries)
        emitted += 1
    for index, values in enumerate(boundaries):
        for value in values[1:]:
            if emitted >= count:
                return
            args = [0] * len(widths)
            args[index] = value
            yield tuple(args)
            emitted += 1
    generator = random.Random(seed)
    while emitted < count:
        yield tuple(generator.getrandbits(width) for width in widths)
        emitted += 1


def main() -> int:
    specification = json.loads(Path(sys.argv[1]).read_text(encoding='utf-8'))
    # Do this before dlopen: ELF constructors also execute native code.
    try:
        import resource
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        resource.setrlimit(resource.RLIMIT_FSIZE, (64 * 1024 * 1024, 64 * 1024 * 1024))
        cpu = max(1, math.ceil(specification['timeout']))
        resource.setrlimit(resource.RLIMIT_CPU, (cpu, cpu + 1))
        resource.setrlimit(resource.RLIMIT_AS, (512 * 1024 * 1024, 512 * 1024 * 1024))
    except (ImportError, OSError, ValueError):
        pass
    original_path = Path(specification['original'])
    digest = hashlib.sha256()
    with original_path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
    if digest.hexdigest() != specification['sha256']:
        raise ValueError('Original binary SHA256 changed before loading')
    import ctypes  # Native loading is deliberately confined to this child.
    original_library = ctypes.CDLL(str(original_path))
    recovered_library = ctypes.CDLL(specification['recovered'])
    original = getattr(original_library, specification['original_symbol'])
    recovered = getattr(recovered_library, specification['export_name'])
    types = {32: ctypes.c_uint32, 64: ctypes.c_uint64}
    original.argtypes = recovered.argtypes = [types[width] for width in specification['parameter_bits']]
    original.restype = recovered.restype = types[specification['return_bits']]
    result = {'status': 'TESTED', 'cases_checked': 0}
    for args in _inputs(specification['parameter_bits'], specification['cases'], specification['seed']):
        expected = int(original(*args))
        actual = int(recovered(*args))
        result['cases_checked'] += 1
        if expected != actual:
            result.update(status='DISPROVED', counterexample={
                'arguments': list(args), 'original': expected, 'recovered': actual,
                'case_index': result['cases_checked'] - 1,
            })
            break
    print(json.dumps(result, allow_nan=False), flush=True)
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception as error:
        print(json.dumps({'status': 'UNKNOWN', 'cases_checked': 0,
                          'diagnostics': [f'{type(error).__name__}: {str(error)[:2048]}']}), flush=True)
        raise SystemExit(1)
