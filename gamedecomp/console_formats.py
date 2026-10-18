"""Bounded Switch module parsing and deterministic, analysis-only ELF conversion.

Layout references: switchbrew/libnx nx/include/switch/nro.h and
switchbrew/switch-tools src/elf2nso.c. No code from these projects is copied.
These module headers do not encode the CPU: callers must require the explicit
switch-aarch64 profile before selecting an AArch64 analysis backend.
"""
import hashlib
import os
import struct
import tempfile
from pathlib import Path

MAX_MODULE_BYTES = 256 * 1024 * 1024
_PAGE = 0x1000
_NAMES = ('text', 'rodata', 'data')
_LIMITATIONS = (
    'The module header does not encode its CPU; AArch64 requires the explicit switch-aarch64 profile.',
    'The derived ET_EXEC ELF uses a synthetic zero-based analysis mapping; it is not the original ELF or a runtime load address.',
    'The derived ELF is an analysis container, not a runnable or relinked game.',
    'Relocations, imports, exports, SDK types and runtime load addresses are not reconstructed.',
    'Game assets and appended NRO assets are not included in the derived ELF.',
)


def detect_console_format(head: bytes) -> str | None:
    """Recognize module magic independently of filename extensions."""
    if head[:4] == b'NSO0':
        return 'NSO'
    if head[0x10:0x14] == b'NRO0':
        return 'NRO'
    return None


def _load_lz4():
    from lz4.block import decompress
    return decompress


def _u32(data, offset):
    return struct.unpack_from('<I', data, offset)[0]


def _bounded_range(offset, size, limit, label):
    if offset < 0 or size < 0 or offset > limit or size > limit - offset:
        raise ValueError(f'{label} range exceeds its bounds')
    return (offset, offset + size)


def _no_overlaps(ranges, label):
    nonempty = sorted((start, end) for start, end in ranges if end > start)
    for previous, current in zip(nonempty, nonempty[1:]):
        if current[0] < previous[1]:
            raise ValueError(f'Overlapping {label} segments')


def _read_module(path):
    path = Path(path).resolve(strict=True)
    if not path.is_file():
        raise ValueError('Console module must be a regular file')
    if path.stat().st_size > MAX_MODULE_BYTES:
        raise ValueError('Console module exceeds the 256 MiB limit')
    with path.open('rb') as stream:
        data = stream.read(MAX_MODULE_BYTES + 1)
    if len(data) > MAX_MODULE_BYTES:
        raise ValueError('Console module exceeds the 256 MiB limit')
    return path, data


def _parse(path, data, format_name):
    if format_name not in ('NRO', 'NSO') or detect_console_format(data) != format_name:
        raise ValueError('Console module format does not match its magic')
    header_size = 0x80 if format_name == 'NRO' else 0x100
    if len(data) < header_size:
        raise ValueError('Truncated console module header')
    version = _u32(data, 0x14 if format_name == 'NRO' else 4)
    if version != 0:
        raise ValueError('Unsupported console module version')
    flags = _u32(data, 0x1C if format_name == 'NRO' else 0xC)
    allowed = 0 if format_name == 'NRO' else 0x7F
    if flags & ~allowed:
        raise ValueError('Unsupported console module flags or compression scheme')
    limit = _u32(data, 0x18) if format_name == 'NRO' else len(data)
    if limit < header_size or limit > len(data):
        raise ValueError('Invalid NRO declared module size')
    bss = _u32(data, 0x38 if format_name == 'NRO' else 0x3C)
    file_ranges, memory_ranges, segments = [], [], []
    for index, name in enumerate(_NAMES):
        if format_name == 'NRO':
            file_offset, size = struct.unpack_from('<II', data, 0x20 + index * 8)
            memory_offset = file_offset
            stored_size, compressed = size, False
        else:
            file_offset, memory_offset, size = struct.unpack_from('<III', data, 0x10 + index * 0x10)
            compressed = bool(flags & (1 << index))
            stored_size = _u32(data, 0x60 + index * 4) if compressed else size
            declared_stored = _u32(data, 0x60 + index * 4)
            if not compressed and declared_stored not in (0, size):
                raise ValueError('Inconsistent uncompressed NSO file size')
            if stored_size and file_offset < header_size:
                raise ValueError('NSO segment overlaps its header')
        if memory_offset % _PAGE:
            raise ValueError('Console segment memory offset is not page aligned')
        memory_size = size + (bss if index == 2 else 0)
        file_ranges.append(_bounded_range(file_offset, stored_size, limit, 'File segment'))
        memory_ranges.append(_bounded_range(memory_offset, memory_size, MAX_MODULE_BYTES, 'Memory segment'))
        if format_name == 'NRO' and stored_size and file_offset < header_size and index != 0:
            raise ValueError('NRO non-text segment overlaps its header')
        segments.append({
            'name': name, 'file_offset': file_offset, 'stored_size': stored_size,
            'memory_offset': memory_offset, 'size': size, 'memory_size': memory_size,
            'compressed': compressed, 'hash_checked': False,
            'elf_flags': (1 if flags & 0x40 else 5) if index == 0 else (4 if index == 1 else 6),
        })
    if format_name == 'NRO' and (segments[0]['file_offset'] != 0 or segments[0]['size'] < header_size):
        raise ValueError('NRO text segment must contain its complete header')
    if segments[0]['size'] == 0:
        raise ValueError('Console text segment is empty')
    if sum(segment['memory_size'] for segment in segments) > MAX_MODULE_BYTES:
        raise ValueError('Expanded console module exceeds the 256 MiB limit')
    _no_overlaps(file_ranges, 'file')
    _no_overlaps(memory_ranges, 'memory')
    payloads = []
    decompressor = None
    for index, segment in enumerate(segments):
        offset, stored_size = segment['file_offset'], segment['stored_size']
        payload = data[offset:offset + stored_size]
        if segment['compressed']:
            if segment['size'] == 0 or stored_size == 0:
                raise ValueError('Compressed console segment has an empty size')
            if decompressor is None:
                try:
                    decompressor = _load_lz4()
                except ImportError as error:
                    raise ValueError('Compressed NSO requires the optional LZ4 dependency') from error
            try:
                payload = decompressor(payload, uncompressed_size=segment['size'])
            except Exception as error:
                raise ValueError('Invalid LZ4 console segment') from error
        if len(payload) != segment['size']:
            raise ValueError('Expanded console segment size mismatch')
        if format_name == 'NSO' and flags & (1 << (index + 3)):
            expected = data[0xA0 + index * 32:0xC0 + index * 32]
            if hashlib.sha256(payload).digest() != expected:
                raise ValueError(f'NSO {segment["name"]} hash mismatch')
            segment['hash_checked'] = True
        payloads.append(payload)
    info = {
        'path': str(path), 'format': format_name, 'size': len(data),
        'sha256': hashlib.sha256(data).hexdigest(), 'source_sha256': hashlib.sha256(data).hexdigest(),
        'architecture': 'aarch64', 'bits': 64, 'endianness': 'little',
        'required_profile': 'switch-aarch64', 'architecture_source': 'switch_aarch64_profile_assumption',
        'entry': segments[0]['memory_offset'], 'segments': segments,
        'analysis_image_base': 0, 'analysis_mapping': 'synthetic_zero_based_module_relative',
        'appended_bytes': len(data) - limit if format_name == 'NRO' else 0,
        'limitations': list(_LIMITATIONS),
    }
    return info, payloads


def inspect_console_module(path, format_name) -> dict:
    """Validate ranges, expansion bounds and required hashes without execution."""
    source, data = _read_module(path)
    info, _ = _parse(source, data, format_name)
    return info


def convert_console_module(path, destination) -> dict:
    """Write a deterministic ELF64 ET_EXEC analysis container with three PT_LOAD entries."""
    source, data = _read_module(path)
    destination = Path(destination)
    if destination.is_symlink() or destination.exists():
        raise ValueError('Console destination already exists or is a symlink')
    # Resolve only the parent: never follow a destination symlink, including dangling links.
    destination = destination.parent.resolve() / destination.name
    if source == destination:
        raise ValueError('Source console module cannot be replaced')
    info, payloads = _parse(source, data, detect_console_format(data))
    ident = b'\x7fELF\x02\x01\x01' + bytes(9)
    header = struct.pack('<16sHHIQQQIHHHHHH', ident, 2, 183, 1, info['entry'], 64, 0, 0, 64, 56, 3, 0, 0, 0)
    output = bytearray(header + bytes(3 * 56))
    for index, (segment, payload) in enumerate(zip(info['segments'], payloads)):
        file_offset = (len(output) + _PAGE - 1) & ~(_PAGE - 1)
        if file_offset + len(payload) > MAX_MODULE_BYTES:
            raise ValueError('Derived ELF exceeds the 256 MiB limit')
        output.extend(bytes(file_offset - len(output)))
        output.extend(payload)
        struct.pack_into('<IIQQQQQQ', output, 64 + index * 56,
                         1, segment['elf_flags'], file_offset, segment['memory_offset'],
                         segment['memory_offset'], len(payload), segment['memory_size'], _PAGE)
        segment['derived_file_offset'] = file_offset
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(dir=destination.parent, prefix='.console-', delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(output)
        # Atomic publication refuses a destination created after the initial check.
        try:
            os.link(temporary, destination)
        except FileExistsError as error:
            raise ValueError('Console destination already exists or is a symlink') from error
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
    info.update(derived_path=str(destination), derived_sha256=hashlib.sha256(output).hexdigest(), derived_size=len(output))
    return info
