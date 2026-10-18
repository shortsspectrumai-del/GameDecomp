"""Profile-bound console normalization followed by real Ghidra static analysis."""
import hashlib
from pathlib import Path
import tempfile
import time

from gamedecomp.console_support import FORMAT_PROFILES
from gamedecomp.ingest import inspect_binary


# Language IDs are bound to Ghidra's installed processor .ldefs. Generic ARM
# v7/v8 decoders cover the ARM/Thumb v4T instruction subset; Thumb-default and
# M-profile variants are excluded. Compatibility here is not hardware equivalence.
_PROFILE_LANGUAGES = {
    'switch-aarch64': ('AARCH64', 'LE', '64', frozenset({'v8A'})),
    'psx-mipsel': ('MIPS', 'LE', '32', frozenset({'default'})),
    'gba-arm': ('ARM', 'LE', '32', frozenset({'v4t', 'v7', 'v8'})),
    'dol-ppc': ('PowerPC', 'BE', '32', frozenset({'default'})),
    'nes-nrom-6502': ('6502', 'LE', '16', frozenset({'default'})),
    'megadrive-m68k': ('68000', 'BE', '32', frozenset({'default'})),
}


def _validate_frontend_language(language, profile):
    expected = _PROFILE_LANGUAGES.get(profile)
    parts = language.split(':') if isinstance(language, str) else []
    if (expected is None or len(parts) != 4 or tuple(parts[:3]) != expected[:3]
            or parts[3] not in expected[3]):
        observed = repr(language)[:100]
        raise ValueError(f'Ghidra frontend language {observed} does not match the explicit console profile {profile}')


def analyze(path, *, profile, ghidra_home=None, timeout=60):
    from gamedecomp.backends.ghidra import analyze as ghidra_analyze
    path = Path(path).resolve()
    started = time.monotonic()
    info = inspect_binary(path, console_profile=profile)
    if FORMAT_PROFILES.get(info['format']) != profile:
        raise ValueError('Console profile and module format differ')
    with tempfile.TemporaryDirectory(prefix='gamedecomp-console-') as directory:
        target = Path(directory) / 'normalized.elf'
        extra = {}
        if info['format'] in ('NSO', 'NRO'):
            from gamedecomp.console_formats import convert_console_module
            provenance = convert_console_module(path, target)
        elif info['format'] == 'MEGADRIVE':
            from gamedecomp.megadrive_format import convert_megadrive_module
            provenance = convert_megadrive_module(path, target)
        elif info['format'] == 'NES':
            from gamedecomp.nes_format import prepare_nes_module
            target = Path(directory) / 'program.bin'
            provenance = prepare_nes_module(path, target)
            provenance['source_sha256'] = provenance['sha256']
            provenance['derived_sha256'] = provenance['prepared_sha256']
            extra = {'raw_processor': provenance['processor_id'],
                     'raw_base': provenance['load_address'], 'entry_point': provenance['entry_point']}
        else:
            from gamedecomp.retro_formats import convert_retro_module
            provenance = convert_retro_module(path, target, info['format'])
        # Synthetic ELF headers do not identify console-specific processor variants.
        # Pin every normalized image instead of relying on loader-selected defaults.
        normalized_processors = {
            'switch-aarch64': 'AARCH64:LE:64:v8A',
            'psx-mipsel': 'MIPS:LE:32:default',
            'gba-arm': 'ARM:LE:32:v4t',
            'dol-ppc': 'PowerPC:BE:32:default',
            'megadrive-m68k': '68000:BE:32:default',
        }
        if profile in normalized_processors:
            extra['processor_id'] = normalized_processors[profile]
        derived_hash = hashlib.sha256(target.read_bytes()).hexdigest()
        if 'entry_point' not in extra:
            extra['entry_point'] = provenance.get('entry_point', provenance.get('entry'))
        expected = provenance.get('derived_sha256', provenance.get('sha256'))
        if derived_hash != expected or provenance['source_sha256'] != info['sha256']:
            raise ValueError('Console normalization provenance changed')
        remaining = timeout - (time.monotonic() - started)
        if remaining <= 0:
            raise TimeoutError('Console normalization exceeded analysis budget')
        analysis = ghidra_analyze(target, ghidra_home=ghidra_home, timeout=remaining, **extra)
        if (analysis.binary_hash != derived_hash or
                hashlib.sha256(path.read_bytes()).hexdigest() != info['sha256']):
            raise ValueError('Console source or normalized module changed during analysis')
        frontend_architecture, frontend_format = analysis.architecture, analysis.format
        _validate_frontend_language(frontend_architecture, profile)
        analysis.metadata['frontend_architecture'] = frontend_architecture
        analysis.metadata['frontend_format'] = frontend_format
        analysis.binary_hash = info['sha256']
        analysis.format = info['format']
        analysis.architecture = info['architecture']
        provenance = {k: v for k, v in provenance.items() if k not in ('path', 'source_path', 'derived_path')}
        analysis.metadata['console_import'] = dict(provenance, profile=profile,
            frontend_architecture=frontend_architecture, frontend_format=frontend_format,
            frontend_language_status='PROFILE_COMPATIBLE',
            processor_override=extra.get('processor_id', extra.get('raw_processor')),
            architecture_source='explicit_console_profile', normalized_sha256=derived_hash,
            executable_run=False, semantic_status='UNKNOWN',
            compilation_scope='No target console ABI compiler configured; host compilation cannot establish console ABI fidelity.')
        for function in analysis.functions:
            function.metadata['console_target'] = {'profile': profile, 'architecture': info['architecture'],
                'bits': info['bits'], 'endianness': info['endianness'],
                'scope': 'Static CPU reconstruction only; console SDK, hardware and runtime behavior remain unverified.'}
        return analysis
