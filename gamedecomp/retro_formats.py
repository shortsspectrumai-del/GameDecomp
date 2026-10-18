"""Bounded static mapping of plaintext retro executable modules to ELF32.

This module independently implements documented container layouts. It does not
execute inputs, recover symbols, decrypt containers, or infer code/data splits.
Format references (no source code is incorporated):
- https://github.com/devkitPro/gba-tools/blob/master/src/gbafix.c
- https://github.com/dolphin-emu/dolphin/blob/master/Source/Core/Core/Boot/DolReader.h
- https://github.com/simias/psxsdk/blob/master/tools/elf2exe.c
- https://psx-spx.consoledev.net/ps1/cdr/cdromfileformats/executables/
"""
from __future__ import annotations

import hashlib
import struct
from pathlib import Path

MAX_BYTES = 256 * 1024 * 1024
_FORMATS = {'PSX_EXE', 'GBA', 'DOL'}


def _gba_header_valid(head: bytes) -> bool:
    if len(head) < 0xC0 or head[0xB2] != 0x96:
        return False
    if head[0xB3] != 0 or any(head[0xB5:0xBC]) or any(head[0xBE:0xC0]):
        return False
    instruction = int.from_bytes(head[:4], 'little')
    return (instruction >> 24 == 0xEA and
            (sum(head[0xA0:0xBE]) + 0x19) & 255 == 0)


def detect_retro_format(head: bytes) -> str | None:
    """Recognize header evidence; DOL requires an explicit format selection."""
    if head[:8] == b'PS-X EXE':
        return 'PSX_EXE'
    if _gba_header_valid(head):
        return 'GBA'
    return None


def _bounded_range(start: int, size: int, limit: int, label: str) -> None:
    if start < 0 or size <= 0 or size > MAX_BYTES or start + size > limit:
        raise ValueError(f'Invalid {label} bounds')


def _segment(name: str, offset: int, size: int, address: int,
             flags: int, memory_size: int | None = None) -> dict:
    return {'name': name, 'file_offset': offset, 'file_size': size, 'size': size,
            'address': address, 'memory_offset': address,
            'memory_size': size if memory_size is None else memory_size,
            'flags': flags}


def _nonoverlapping(segments: list[dict], *, file: bool = False) -> None:
    key, size_key = ('file_offset', 'file_size') if file else ('address', 'memory_size')
    ranges = sorted((s[key], s[key] + s[size_key]) for s in segments if s[size_key])
    if any(left[1] > right[0] for left, right in zip(ranges, ranges[1:])):
        raise ValueError('Overlapping file sections' if file else 'Overlapping memory sections')


def _read(path: Path) -> bytes:
    # Bound the read itself, not just a preceding size check (files may change).
    with path.open('rb') as stream:
        if not 0 < path.stat().st_size <= MAX_BYTES:
            raise ValueError('Retro module size must be between 1 byte and 256 MiB')
        data = stream.read(MAX_BYTES + 1)
    if not 0 < len(data) <= MAX_BYTES:
        raise ValueError('Retro module exceeds size limit')
    return data


def _parse(data: bytes, format_name: str) -> dict:
    if format_name not in _FORMATS:
        raise ValueError('Unsupported retro module format')
    segments = []
    notes = ['Static module mapping only; complete game projects, assets, symbols, and semantic equivalence are not recovered.']
    if format_name == 'PSX_EXE':
        if len(data) < 0x800 or data[:8] != b'PS-X EXE':
            raise ValueError('Invalid PS-X EXE header')
        entry, gp, address, size = struct.unpack_from('<IIII', data, 0x10)
        _bounded_range(0x800, size, len(data), 'PS-X EXE payload')
        _bounded_range(address, size, 1 << 32, 'PS-X EXE memory')
        segments.append(_segment('payload', 0x800, size, address, 7))
        bss_address, bss_size = struct.unpack_from('<II', data, 0x28)
        if bss_size:
            _bounded_range(bss_address, bss_size, 1 << 32, 'PS-X EXE BSS')
            segments.append(_segment('bss', 0, 0, bss_address, 6, bss_size))
        arch, endian, machine, profile = 'mipsel', 'little', 8, 'psx-mipsel'
        notes.append('The combined PS-X EXE payload has unknown code/data boundaries; initial GP is recorded, not reconstructed.')
        extras = {'initial_gp': gp, 'appended_bytes': len(data) - 0x800 - size}
    elif format_name == 'GBA':
        if not _gba_header_valid(data):
            raise ValueError('Invalid GBA fixed header, checksum, or ARM branch')
        if len(data) > 32 * 1024 * 1024:
            raise ValueError('GBA ROM exceeds the 32 MiB cartridge mapping')
        immediate = int.from_bytes(data[:4], 'little') & 0xFFFFFF
        if immediate & 0x800000:
            immediate -= 1 << 24
        target = 8 + immediate * 4
        if not 0xC0 <= target <= len(data) - 4:
            raise ValueError('GBA branch target is outside executable payload')
        entry = 0x08000000 + target
        segments.append(_segment('rom', 0, len(data), 0x08000000, 5))
        arch, endian, machine, profile = 'arm', 'little', 40, 'gba-arm'
        notes.append('ROM data is mapped read/execute; embedded assets and ARM/Thumb transitions require further analysis. The header branch target is used as the analysis entry.')
        extras = {'header_branch_target': entry, 'cartridge_base': 0x08000000}
    else:
        if len(data) < 0x100:
            raise ValueError('Truncated DOL header')
        offsets = struct.unpack_from('>18I', data, 0)
        addresses = struct.unpack_from('>18I', data, 0x48)
        sizes = struct.unpack_from('>18I', data, 0x90)
        bss_address, bss_size, entry = struct.unpack_from('>III', data, 0xD8)
        for index, (offset, address, size) in enumerate(zip(offsets, addresses, sizes)):
            if not size:
                continue
            if offset < 0x100:
                raise ValueError('DOL section overlaps header')
            _bounded_range(offset, size, len(data), 'DOL file section')
            _bounded_range(address, size, 1 << 32, 'DOL memory section')
            if index < 7 and (address % 4 or size % 4):
                raise ValueError('Unaligned DOL text section')
            name = f'text{index}' if index < 7 else f'data{index - 7}'
            segments.append(_segment(name, offset, size, address, 5 if index < 7 else 6))
        _nonoverlapping(segments)
        _nonoverlapping(segments, file=True)
        if bss_size:
            _bounded_range(bss_address, bss_size, 1 << 32, 'DOL BSS')
            # Some DOL BSS declarations span loaded sections: preserve those bytes.
            gaps = [(bss_address, bss_address + bss_size)]
            for segment in segments:
                low, high = segment['address'], segment['address'] + segment['memory_size']
                remaining = []
                for begin, end in gaps:
                    if high <= begin or low >= end:
                        remaining.append((begin, end))
                    else:
                        if begin < low:
                            remaining.append((begin, low))
                        if high < end:
                            remaining.append((high, end))
                gaps = remaining
            segments.extend(_segment(f'bss{index}', 0, 0, begin, 6, end - begin)
                            for index, (begin, end) in enumerate(gaps))
        arch, endian, machine, profile = 'powerpc', 'big', 20, 'dol-ppc'
        extras = {'declared_bss_address': bss_address, 'declared_bss_size': bss_size}
        notes.append('DOL has no magic signature; the selected profile is a user assertion. BSS excludes existing loaded sections. Platform-specific paired-single instructions require a compatible backend.')
    _nonoverlapping(segments)
    if not segments or entry % 4 or not any(
        s['flags'] & 1 and s['address'] <= entry and entry + 4 <= s['address'] + s['file_size']
        for s in segments
    ):
        raise ValueError('Entry point is not an aligned instruction in a loaded executable section')
    if sum(s['memory_size'] for s in segments) > MAX_BYTES:
        raise ValueError('Total mapped memory exceeds 256 MiB')
    return {'format': format_name, 'architecture': arch, 'bits': 32,
            'endianness': endian, 'endian': endian, 'machine': machine,
            'entry_point': entry, 'profile': profile, 'segments': segments,
            'source_sha256': hashlib.sha256(data).hexdigest(),
            'source_size': len(data), 'limitations': notes, **extras}


def inspect_retro_module(path: str | Path, format_name: str) -> dict:
    """Validate a complete plaintext module without changing it."""
    return _parse(_read(Path(path)), format_name)


def _elf(data: bytes, info: dict) -> bytes:
    order = '<' if info['endianness'] == 'little' else '>'
    segments = info['segments']
    cursor = 52 + 32 * len(segments)
    if cursor + sum(s['file_size'] for s in segments) > MAX_BYTES:
        raise ValueError('Derived ELF size exceeds 256 MiB')
    payload = bytearray(cursor)
    headers = []
    for segment in segments:
        # Unit alignment avoids padding driven by attacker-controlled addresses.
        offset = cursor
        size = segment['file_size']
        payload.extend(data[segment['file_offset']:segment['file_offset'] + size])
        cursor += size
        headers.append(struct.pack(order + 'IIIIIIII', 1, offset,
                                   segment['address'], segment['address'], size,
                                   segment['memory_size'], segment['flags'], 1))
    ident = b'\x7fELF' + bytes([1, 1 if order == '<' else 2, 1]) + bytes(9)
    payload[:52] = struct.pack(order + '16sHHIIIIIHHHHHH', ident, 2,
                               info['machine'], 1, info['entry_point'], 52, 0, 0,
                               52, 32, len(segments), 0, 0, 0)
    payload[52:52 + 32 * len(segments)] = b''.join(headers)
    return bytes(payload)


def convert_retro_module(path: str | Path, destination: str | Path,
                         format_name: str) -> dict:
    """Create a deterministic analysis ELF, preserving source provenance."""
    path, destination = Path(path), Path(destination)
    if path.resolve() == destination.resolve() or (
        destination.exists() and path.samefile(destination)
    ):
        raise ValueError('Source module cannot be replaced')
    data = _read(path)
    info = _parse(data, format_name)
    derived = _elf(data, info)
    # Exclusive creation prevents overwriting an unrelated file or following a symlink.
    with destination.open('xb') as stream:
        stream.write(derived)
    return {**info, 'derived_path': str(destination),
            'derived_sha256': hashlib.sha256(derived).hexdigest()}
