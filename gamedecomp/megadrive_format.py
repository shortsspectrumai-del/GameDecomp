"""Strict static mapping of linear Mega Drive/Genesis 68000 ROMs to ELF32.

Format facts were checked against primary tool sources; no code was copied:
https://github.com/Stephane-D/SGDK/blob/master/inc/sys.h
https://github.com/Stephane-D/SGDK/blob/master/src/boot/sega.s
https://github.com/Stephane-D/SGDK/blob/master/md.ld
https://github.com/ekeeke/Genesis-Plus-GX/blob/master/core/loadrom.c

Only an unbanked, big-endian, zero-based ROM view is represented. Inputs are
never executed and no hardware or whole-game behavioral equivalence is claimed.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import struct
import tempfile

MAX_ROM_BYTES = 4 * 1024 * 1024
FORMAT = 'MEGADRIVE'
PROFILE = 'megadrive-m68k'


def detect_megadrive_format(head: bytes) -> str | None:
    """Recognize the standard cartridge header; never guess a swapped image."""
    if len(head) < 0x110 or head[0x100:0x104] != b'SEGA':
        return None
    console = head[0x100:0x110]
    if any(marker in console.upper() for marker in (b'32X', b'SATURN', b'PICO', b'CD')):
        return None
    if any(value < 0x20 or value > 0x7E for value in console):
        return None
    return FORMAT


def _read(path: str | Path) -> tuple[Path, bytes]:
    source = Path(path).resolve(strict=True)
    if not source.is_file() or not 0 < source.stat().st_size <= MAX_ROM_BYTES:
        raise ValueError('Mega Drive input must be a regular ROM with size at most 4 MiB')
    with source.open('rb') as stream:
        data = stream.read(MAX_ROM_BYTES + 1)
    if not 0x202 <= len(data) <= MAX_ROM_BYTES or len(data) % 2:
        raise ValueError('Invalid Mega Drive ROM size; an even linear image with executable bytes is required')
    return source, data


def _parse(source: Path, data: bytes) -> dict:
    if detect_megadrive_format(data) is None:
        raise ValueError('Unsupported Mega Drive header; interleaved, byte-swapped, copier-header and add-on images are not accepted')
    initial_sp, reset = struct.unpack_from('>II', data)
    rom_start, rom_end = struct.unpack_from('>II', data, 0x1A0)
    if rom_start != 0 or rom_end != len(data) - 1:
        raise ValueError('Mega Drive ROM bounds must describe the complete zero-based linear image exactly')
    if reset % 2 or not 0x200 <= reset <= len(data) - 2:
        raise ValueError('Mega Drive reset vector must point to an aligned instruction in the ROM payload')
    # The 68000 drives only 24 address lines; SGDK uses high-bit RAM aliases.
    first_stack_write = (initial_sp - 2) & 0xFFFFFF
    if initial_sp % 2 or not 0xFF0000 <= first_stack_write <= 0xFFFFFE:
        raise ValueError('Mega Drive stack must be aligned and its first predecrement write must fall in canonical work RAM')
    declared = struct.unpack_from('>H', data, 0x18E)[0]
    computed = sum(word[0] for word in struct.iter_unpack('>H', data[0x200:])) & 0xFFFF
    if declared != 0 and declared != computed:
        raise ValueError('Mega Drive ROM checksum mismatch')
    checksum_verified = declared == computed
    notes = [
        'Only linear big-endian ROMs up to 4 MiB with exact zero-based header bounds are supported; bank switching, SMD interleaving, copier headers, Sega CD and 32X are unavailable.',
        'The ROM has unknown code/data boundaries; assets and secondary Z80 code are retained as bytes, not decompiled as 68000 code with established correctness.',
        'The initial SP is recorded with its 24-bit bus mapping; RAM initialization, VDP, audio, I/O, interrupts and runtime behavior are not modeled.',
        'This ELF is an analysis container, not a runnable game or a recovered project. No input is executed and no semantic equivalence is established.',
    ]
    if not checksum_verified:
        notes.append('A zero header checksum differs from the computed checksum and is treated as an unprovided checksum, not verified integrity.')
    segment = {'name': 'rom', 'file_offset': 0, 'file_size': len(data),
               'size': len(data), 'address': 0, 'memory_offset': 0,
               'memory_size': len(data), 'flags': 5}
    digest = hashlib.sha256(data).hexdigest()
    return {'path': str(source), 'format': FORMAT, 'profile': PROFILE,
            'required_profile': PROFILE, 'architecture': 'm68k', 'bits': 32,
            'endianness': 'big', 'entry_point': reset, 'initial_sp': initial_sp,
            'initial_sp_bus_address': initial_sp & 0xFFFFFF,
            'first_stack_write_bus_address': first_stack_write,
            'rom_start': rom_start, 'rom_end': rom_end,
            'checksum_declared': declared, 'checksum_computed': computed,
            'checksum_verified': checksum_verified,
            'checksum_status': 'VERIFIED' if checksum_verified else 'NOT_PROVIDED',
            'source_sha256': digest, 'sha256': digest,
            'source_size': len(data), 'size': len(data), 'segments': [segment],
            'limitations': notes}


def inspect_megadrive_module(path: str | Path) -> dict:
    """Validate header, vectors, exact ROM range and a supplied checksum."""
    source, data = _read(path)
    return _parse(source, data)


def convert_megadrive_module(path: str | Path, destination: str | Path) -> dict:
    """Publish an analysis-only EM_68K ELF32 without overwriting any file."""
    source, data = _read(path)
    requested = Path(destination)
    if requested.is_symlink() or requested.exists():
        raise ValueError('Mega Drive destination must be new and cannot be a symlink')
    output = requested.parent.resolve() / requested.name
    if output == source:
        raise ValueError('Mega Drive source cannot be replaced')
    info = _parse(source, data)
    ident = b'\x7fELF\x01\x02\x01' + bytes(9)
    header = struct.pack('>16sHHIIIIIHHHHHH', ident, 2, 4, 1,
                         info['entry_point'], 52, 0, 0, 52, 32, 1, 0, 0, 0)
    program = struct.pack('>IIIIIIII', 1, 84, 0, 0, len(data), len(data), 5, 2)
    derived = header + program + data
    temporary = None
    try:
        # Publish atomically and exclusively, including against final-name races.
        with tempfile.NamedTemporaryFile(dir=output.parent, prefix='.megadrive-', delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(derived)
        try:
            os.link(temporary, output)
        except FileExistsError as error:
            raise ValueError('Mega Drive destination already exists or is a symlink') from error
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
    return {**info, 'derived_path': str(output), 'derived_size': len(derived),
            'derived_sha256': hashlib.sha256(derived).hexdigest()}
