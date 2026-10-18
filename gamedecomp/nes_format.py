"""Bounded static import of strict iNES mapper-0 PRG modules.

Format references: https://www.nesdev.org/wiki/INES and
https://www.nesdev.org/wiki/NROM. No cartridge code is executed.
"""
import hashlib
from pathlib import Path


NES_PROCESSOR_ID = '6502:LE:16:default'
MAX_NROM_BYTES = 16 + 512 + 32768 + 8192


def detect_nes(head: bytes) -> bool:
    """Identify the iNES/NES 2.0 family; parsing determines support."""
    return head.startswith(b'NES\x1a')


def _read_nrom(path: Path) -> tuple[bytes, dict]:
    source = Path(path).resolve(strict=True)
    if not source.is_file():
        raise ValueError('NES input must be a regular file.')
    with source.open('rb') as stream:
        data = stream.read(MAX_NROM_BYTES + 1)
    if len(data) > MAX_NROM_BYTES:
        raise ValueError('NES input exceeds the supported NROM size limit.')
    if len(data) < 16 or not detect_nes(data):
        raise ValueError('Invalid or truncated iNES header.')
    header = data[:16]
    if header[7] & 0x0C == 0x08:
        raise ValueError('NES 2.0 is not supported; only strict iNES NROM is available.')
    mapper = (header[6] >> 4) | (header[7] & 0xF0)
    if mapper != 0:
        raise ValueError('Unsupported NES mapper; only mapper 0 (NROM) is available.')
    if header[7] & 0x0F:
        raise ValueError('VS, PlayChoice, archaic, or reserved iNES flags are unsupported.')
    if header[6] & 0x08:
        raise ValueError('Four-screen NROM variants are unsupported.')
    if header[8] > 1 or header[9] & 0xFE or any(header[10:16]):
        raise ValueError('Ambiguous or unsupported extended iNES header fields.')
    if header[4] not in (1, 2) or header[5] not in (0, 1):
        raise ValueError('NROM requires 16/32 KiB PRG and 0/8 KiB CHR.')
    trainer_size = 512 if header[6] & 0x04 else 0
    prg_size = header[4] * 16384
    chr_size = header[5] * 8192
    prg_offset = 16 + trainer_size
    expected = prg_offset + prg_size + chr_size
    if len(data) != expected:
        raise ValueError('Truncated iNES sections or unsupported trailing data.')
    prg = data[prg_offset:prg_offset + prg_size]
    reset = int.from_bytes(prg[-4:-2], 'little')
    if not 0x8000 <= reset <= 0xFFFF:
        raise ValueError('NROM reset vector must point into mapped PRG ROM.')
    metadata = {
        'path': str(source), 'size': len(data),
        'sha256': hashlib.sha256(data).hexdigest(),
        'format': 'NES', 'profile': 'nes-nrom-6502',
        'architecture': '6502', 'bits': 16, 'endianness': 'little',
        'mapper': 0, 'processor_id': NES_PROCESSOR_ID,
        'load_address': 0x8000, 'entry_point': reset,
        'prg_file_offset': prg_offset, 'prg_size': prg_size,
        'prg_mirrored': prg_size == 16384, 'mapped_size': 32768,
        'trainer_omitted_bytes': trainer_size, 'chr_omitted_bytes': chr_size,
        'battery_backed_ram': bool(header[6] & 2),
        'limitations': [
            'Only strict iNES mapper 0 NROM is imported; no bank-switching is inferred.',
            'CHR graphics and optional trainer bytes are omitted from CPU analysis.',
            'RAM, PPU, APU, I/O behavior and cartridge execution are not modeled.',
            'The generic 6502 processor does not establish NES 2A03 behavioral equivalence.',
            'Code/data separation and reconstructed source correctness are not guaranteed.',
        ],
    }
    return prg, metadata


def inspect_nes_module(path: Path) -> dict:
    """Validate an NROM input and report its explicitly bounded CPU layout."""
    return _read_nrom(path)[1]


def prepare_nes_module(path: Path, destination: Path) -> dict:
    """Write a 32 KiB CPU PRG view, mirroring a 16 KiB NROM-128 bank."""
    prg, metadata = _read_nrom(path)
    requested_output = Path(destination)
    if requested_output.is_symlink() or requested_output.exists():
        raise ValueError('Prepared NES output must be a new file, not an existing path or symlink.')
    # Resolve only the parent so a newly-created final symlink cannot be followed.
    output = requested_output.parent.resolve() / requested_output.name
    source = Path(metadata['path'])
    if output == source or (output.exists() and output.samefile(source)):
        raise ValueError('Prepared NES output must not overwrite the source image.')
    mapped = prg * 2 if len(prg) == 16384 else prg
    try:
        with output.open('xb') as stream:
            stream.write(mapped)
    except FileExistsError as error:
        raise ValueError('Prepared NES output must be a new file.') from error
    return {**metadata, 'source_path': str(source), 'path': str(output),
            'prepared_sha256': hashlib.sha256(mapped).hexdigest()}
