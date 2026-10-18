"""Identify containers without loading or executing their code."""
import hashlib
import struct
from pathlib import Path


MAX_BINARY_BYTES = 256 * 1024 * 1024


def inspect_binary(path: Path, max_bytes: int = MAX_BINARY_BYTES, *, console_profile=None) -> dict:
    path = Path(path).resolve(strict=True)
    if not path.is_file():
        raise ValueError('Il percorso non è un file regolare')
    size = path.stat().st_size
    if size > max_bytes:
        raise ValueError(f'Binario oltre il limite di {max_bytes} byte')
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        head = stream.read(4096)
        digest.update(head)
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
    result = {'path': str(path), 'size': size, 'sha256': digest.hexdigest()}
    if head.startswith(b'\x7fELF'):
        if len(head) < 52 or head[4] not in (1, 2) or head[5] not in (1, 2):
            raise ValueError('Header ELF troncato o non valido')
        bits = 32 if head[4] == 1 else 64
        if size < (52 if bits == 32 else 64):
            raise ValueError('Header ELF troncato')
        endian = '<' if head[5] == 1 else '>'
        machine = struct.unpack_from(endian + 'H', head, 18)[0]
        architecture = {3: 'x86', 4: 'm68k', 8: 'mips', 20: 'powerpc', 21: 'powerpc64',
                        62: 'x86_64', 40: 'arm', 183: 'aarch64', 243: 'riscv'}.get(machine, f'elf-machine-{machine}')
        result.update(format='ELF', architecture=architecture, bits=bits, endianness='little' if endian == '<' else 'big')
    elif head.startswith(b'MZ'):
        if len(head) < 64:
            raise ValueError('Header DOS troncato')
        offset = struct.unpack_from('<I', head, 60)[0]
        if offset > size - 24:
            raise ValueError('Offset PE non valido')
        with path.open('rb') as stream:
            stream.seek(offset)
            pe = stream.read(24)
        if pe[:4] != b'PE\0\0':
            raise ValueError('Firma PE assente')
        machine = struct.unpack_from('<H', pe, 4)[0]
        architecture = {0x14c: 'x86', 0x8664: 'x86_64', 0x1c4: 'arm', 0xaa64: 'aarch64'}.get(machine, f'pe-machine-{machine}')
        result.update(format='PE', architecture=architecture, bits=64 if machine in (0x8664, 0xaa64) else 32, endianness='little')
    elif head.startswith(b'\0asm'):
        if head[:8] != b'\0asm\x01\0\0\0':
            raise ValueError('Versione WebAssembly non supportata o header troncato')
        result.update(format='WASM', architecture='wasm32', bits=32, endianness='little')
    else:
        from gamedecomp.console_support import inspect_console_input, unsupported_input_message
        console = inspect_console_input(path, head, console_profile)
        if console is None:
            raise ValueError(unsupported_input_message(head))
        result.update(console)
    return result
