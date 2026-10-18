"""Reproducible synthetic graph corpus from compiled, authored C fixtures.

The corpus is a small training/evaluation demonstration, not a game benchmark.
All optimization/compiler variants of a body-template group stay in one split.
The six labels describe authored behavior; no input or generated binary runs.
"""
from __future__ import annotations

import hashlib
import json
import math
import os
from pathlib import Path
import random
import shutil
import tempfile
import time

from gamedecomp.backends.native import analyze
from gamedecomp.validation import _capture_compiler


FAMILIES = ('arithmetic', 'bitwise', 'comparison', 'memory_read',
            'memory_write', 'float_math')
_OPTIMIZATIONS = ('O0', 'O1', 'O2')
_MAX_SAMPLES = 256

# Index ranges 0..2 / 3..5 / 6..8 are reserved to train / validation / test.
# Each held-out index changes the expression structure, not only constants.
_BODIES = {
    'arithmetic': (
        'return a + b * {k}u;',
        'return (a - b) * {k}u;',
        'return a * a + b;',
        'return (a + b) * (a + {k}u);',
        'return a * {k}u + b * ({k}u + 2u);',
        'return a * ({k}u + 4u) - b * {k}u;',
        'return a + b * {k}u - {k}u;',
        'return (a + {k}u) * (b + {k}u);',
        'return a * b + a + b;',
    ),
    'bitwise': (
        'return (a ^ b) & 0x{mask:x}u;',
        'return (a << 5) | (b >> 3);',
        'return (a & b) ^ ~a;',
        'return (a | b) ^ 0x{mask:x}u;',
        'return ~((a >> 7) | b);',
        'return (a << 9) ^ b;',
        'return ~(a ^ b) | ((a & b) << 3);',
        'return a ^ ((b << 5) | (b >> 27));',
        'return (a & ~b) | (b >> 4);',
    ),
    'comparison': (
        'return a > b;',
        'return a == b;',
        'return a <= b;',
        'return (a & 0xffffu) == b;',
        'return a != b;',
        'return a >= b;',
        'return a < b ? {k}u : 3u;',
        'return (a > b) + (a == b);',
        'return a < b ? a : b;',
    ),
    'memory_read': (
        'return p[b & 7u];',
        'return p[0] + p[2];',
        'return p[b & 3u] ^ p[(b + 1u) & 3u];',
        'return p[1] * {k}u + p[5];',
        'return p[b & 7u] + p[7u - (b & 7u)];',
        'return (p[2] >> 3) | p[4];',
        'return p[0] + p[3] + p[7];',
        'return p[b & 3u] * p[4u + (b & 3u)];',
        'return (p[1] ^ p[6]) + b;',
    ),
    'memory_write': (
        'p[0] = b; return b;',
        'p[b & 7u] = b + {k}u; return b;',
        'p[1] = b; p[3] = b * {k}u; return b;',
        'p[2] = b ^ 0x{mask:x}u; return b;',
        'p[4] = b + 1u; p[5] = b - 1u; return b;',
        'p[b & 3u] = b << 4; return b;',
        'p[0] = b * {k}u; p[7] = b; return b;',
        'p[1] = ~b; p[2] = b >> 5; p[3] = b << 3; return b;',
        'p[4u + (b & 3u)] = b ^ (b >> 7); return b;',
    ),
    'float_math': (
        'return a + b * {k}.0;',
        'return (a - b) * {k}.0;',
        'return a * a + b;',
        'return (a + b) * (a + {k}.0);',
        'return a / (b * b + 1.0);',
        'return (a * 0.25) - (b * {k}.0);',
        'return a * b + a + b;',
        'return (a + {k}.0) / (b * b + 2.0);',
        'return (a * a - b * b) * 0.5;',
    ),
}


def _remaining(deadline: float, cap: float) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError('GNN corpus generation exceeded its shared time budget')
    return min(cap, remaining)


def _run_tool(command: list[str], directory: Path, deadline: float,
              compiler_timeout: float) -> str:
    code, output, timed_out, limited = _capture_compiler(
        command, str(directory), _remaining(deadline, compiler_timeout))
    if timed_out:
        raise TimeoutError('GNN corpus compiler exceeded its time budget')
    if limited:
        raise RuntimeError('GNN corpus compiler exceeded its diagnostic output budget')
    text = output.decode('utf-8', errors='replace')
    if code:
        raise RuntimeError(f'GNN corpus compiler failed ({code}): {text[:8192]}')
    return text


def _fixture(sample: int, template: int, generator: random.Random) -> tuple[str, dict]:
    pieces = ['#include <stdint.h>\n#define NOINLINE __attribute__((noinline))\n']
    labels: dict[str, str] = {}
    for index, family in enumerate(FAMILIES):
        k = generator.randrange(3, 32, 2)
        mask = generator.getrandbits(32) | 0x01010101
        helper = f'f_{sample:04d}_{index:02d}_h'
        caller = f'f_{sample:04d}_{index:02d}_w'
        split_index = template // 3
        if family == 'float_math':
            return_type, arguments = 'double', 'double a, double b'
            wrapper = (
                f'return {helper}(a, b) + a * 0.5;',
                f'return ({helper}(a, b) + b) * 0.25;',
                f'return {helper}(a, b) - (a + b) * 0.125;',
            )[split_index]
        elif family == 'memory_read':
            return_type, arguments = 'uint32_t', 'const uint32_t *p, uint32_t b'
            wrapper = (
                f'return {helper}(p, b) + p[6];',
                f'return {helper}(p, b) * p[5];',
                f'return {helper}(p, b) ^ p[b & 7u];',
            )[split_index]
        elif family == 'memory_write':
            return_type, arguments = 'uint32_t', 'uint32_t *p, uint32_t b'
            wrapper = (
                f'uint32_t v = {helper}(p, b); p[6] = v + 1u; return v;',
                f'uint32_t v = {helper}(p, b); p[5] = v * {k}u; p[7] = b; return v;',
                f'uint32_t v = {helper}(p, b); p[b & 3u] = v ^ b; p[4] = ~v; return v;',
            )[split_index]
        else:
            return_type, arguments = 'uint32_t', 'uint32_t a, uint32_t b'
            if family == 'arithmetic':
                wrapper = (
                    f'return {helper}(a, b) + a * {k}u;',
                    f'return {helper}(a, b) - b * {k}u;',
                    f'return {helper}(a, b) * 3u + a;',
                )[split_index]
            elif family == 'bitwise':
                wrapper = (
                    f'return {helper}(a, b) ^ a;',
                    f'return {helper}(a, b) | ~b;',
                    f'return ({helper}(a, b) << 3) ^ (a >> 7);',
                )[split_index]
            else:
                wrapper = (
                    f'return {helper}(a, b) | (a != b);',
                    f'return {helper}(a, b) + (a < b);',
                    f'return ({helper}(a, b) == b) + (a <= b);',
                )[split_index]
        body = _BODIES[family][template].format(k=k, mask=mask)
        pieces.append(f'NOINLINE {return_type} {helper}({arguments}) {{ {body} }}\n')
        pieces.append(f'NOINLINE {return_type} {caller}({arguments}) {{ {wrapper} }}\n')
        labels[helper] = labels[caller] = family
    return ''.join(pieces), labels


def _assignment(sample: int, samples: int) -> tuple[str, int]:
    # All three splits are non-empty even for the smallest smoke corpus.
    validation_count = max(1, samples // 5)
    test_count = max(1, samples // 5)
    train_count = samples - validation_count - test_count
    if sample < train_count:
        return 'train', sample % 3
    if sample < train_count + validation_count:
        return 'validation', 3 + (sample - train_count) % 3
    return 'test', 6 + (sample - train_count - validation_count) % 3


def build_corpus(output: Path, *, samples: int = 48, seed: int = 17,
                 timeout: float = 600, compiler_timeout: float = 30) -> Path:
    """Create a new corpus directory and return its ``dataset.json`` path.

    ``samples`` counts authored translation units, each with 12 labeled
    functions. Each compiler available among GCC/Clang produces O0/O1/O2
    variants; max 256 units. A shared deadline bounds the entire operation.
    Only trusted local compiler/objdump tools run; the resulting ELF files do
    not run. Failed builds are removed without publishing a partial dataset.
    """
    if isinstance(samples, bool) or not isinstance(samples, int) or not 3 <= samples <= _MAX_SAMPLES:
        raise ValueError(f'samples must be an integer between 3 and {_MAX_SAMPLES}')
    if isinstance(seed, bool) or not isinstance(seed, int) or not 0 <= seed < 2**32:
        raise ValueError('seed must be an unsigned 32-bit integer')
    for name, value in (('timeout', timeout), ('compiler_timeout', compiler_timeout)):
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value <= 0:
            raise ValueError(f'{name} must be a finite positive number')
    output = Path(output).absolute()
    if output.is_symlink() or (output.exists() and (not output.is_dir() or any(output.iterdir()))):
        raise ValueError('GNN corpus output must be a new or empty directory')
    if not shutil.which('objdump'):
        raise RuntimeError('GNN corpus requires objdump/binutils')
    compilers = [(name, str(Path(found).absolute())) for name in ('gcc', 'clang')
                 if (found := shutil.which(name))]
    if not compilers:
        raise RuntimeError('GNN corpus requires a trusted local GCC or Clang compiler')
    deadline = time.monotonic() + timeout
    _remaining(deadline, compiler_timeout)
    from gamedecomp.gnn import FEATURE_VERSION, build_graph

    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=f'.{output.name}-', dir=output.parent) as directory:
        staging = Path(directory)
        (staging / 'sources').mkdir()
        (staging / 'binaries').mkdir()
        manifest = {
            'schema_version': 1, 'samples': samples, 'seed': seed,
            'trusted_generated_sources': True, 'binaries_executed': False,
            'families': list(FAMILIES), 'optimization_levels': list(_OPTIMIZATIONS),
            'split_policy': 'body-template groups: train 0..2, validation 3..5, test 6..8; all compiler/optimization/source-constant variants remain in their template split',
            'limitations': 'Small synthetic scalar C corpus for demonstrating training. It does not measure recovery of arbitrary classes, types, names, or real game behavior. Compiler families can appear in every split; body-template groups cannot.',
            'toolchains': [], 'sources': [], 'binaries': [],
        }
        for name, executable in compilers:
            version = _run_tool([executable, '--version'], staging, deadline, compiler_timeout)
            manifest['toolchains'].append({'name': name, 'path': executable,
                                           'version': version[:8192].strip()})
        dataset = {'schema_version': 1, 'feature_version': FEATURE_VERSION, 'graphs': []}
        generator = random.Random(seed)
        for sample in range(samples):
            _remaining(deadline, compiler_timeout)
            split, template = _assignment(sample, samples)
            group = f'body-template-{template:02d}'
            source_id = f'source-{sample:04d}'
            source_relative = f'sources/{source_id}.c'
            source_text, truth = _fixture(sample, template, generator)
            source_path = staging / source_relative
            source_path.write_text(source_text, encoding='utf-8')
            manifest['sources'].append({
                'id': source_id, 'path': source_relative,
                'sha256': hashlib.sha256(source_text.encode('utf-8')).hexdigest(),
                'group': group, 'template_id': template, 'split': split,
                'ground_truth': truth,
            })
            for compiler_name, executable in compilers:
                for optimization in _OPTIMIZATIONS:
                    binary_relative = f'binaries/{source_id}-{compiler_name}-{optimization}.so'
                    binary_path = staging / binary_relative
                    # No startup object/functions, debug symbols or execution.
                    # Bsymbolic and no tail-call optimization preserve real
                    # helper-to-caller graph links for every compiler variant.
                    flags = [f'-{optimization}', '-std=c11', '-fPIC', '-shared',
                             '-nostdlib', '-fno-optimize-sibling-calls', '-Wl,-Bsymbolic']
                    _run_tool([executable, *flags, source_relative, '-o', binary_relative],
                              staging, deadline, compiler_timeout)
                    artifact = analyze(binary_path, timeout=_remaining(deadline, compiler_timeout))
                    by_name = {function.name: function for function in artifact.functions
                               if function.name in truth}
                    if set(by_name) != set(truth) or any(not item.instructions for item in by_name.values()):
                        raise RuntimeError('GNN corpus failed to extract all authored function instructions')
                    if any('timeout' in message.lower() for message in artifact.diagnostics):
                        raise TimeoutError('GNN corpus disassembly exceeded its time budget')
                    artifact.functions = [by_name[name] for name in truth]
                    labels = {function.id: truth[function.name] for function in artifact.functions}
                    graph = build_graph(artifact, labels=labels, group=group)
                    if len(graph['edges']) < 6:
                        raise RuntimeError('GNN corpus call graph is missing authored helper edges')
                    binary_hash = hashlib.sha256(binary_path.read_bytes()).hexdigest()
                    graph.update(split=split, source_id=source_id, binary_sha256=binary_hash,
                                 compiler=compiler_name, optimization=optimization)
                    manifest['binaries'].append({
                        'source_id': source_id, 'path': binary_relative, 'sha256': binary_hash,
                        'compiler': compiler_name, 'optimization': optimization,
                        'flags': flags, 'group': group, 'split': split,
                        'functions': len(artifact.functions), 'edges': len(graph['edges']),
                        'graph_index': len(dataset['graphs']),
                    })
                    dataset['graphs'].append(graph)
        _remaining(deadline, compiler_timeout)
        (staging / 'dataset.json').write_text(json.dumps(dataset, indent=2, allow_nan=False) + '\n', encoding='utf-8')
        (staging / 'manifest.json').write_text(json.dumps(manifest, indent=2, allow_nan=False) + '\n', encoding='utf-8')
        _remaining(deadline, compiler_timeout)
        os.replace(staging, output)
    return output / 'dataset.json'
