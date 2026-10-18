"""Evidence-preserving native disassembly and conservative scalar C recovery.

The C is an unsigned bit-vector model for a limited SysV AMD64 leaf subset,
not a reconstruction of original source types. No input binary is executed.
"""
from __future__ import annotations

import hashlib
import io
import math
from pathlib import Path
import re
import struct
import subprocess
import tempfile
import time

from gamedecomp.models import Analysis, Function, Instruction


_MAX_TOOL_OUTPUT = 32 * 1024 * 1024
_MAX_TOOL_ERROR = 64 * 1024
_MAX_PROGRAM_HEADERS = 4096
_ARGUMENTS = ('rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9')
_CALLER_SAVED = set(_ARGUMENTS) | {'rax', 'r10', 'r11'}
_REGISTERS: dict[str, tuple[str, int]] = {}
for _full, _low in [('rax', 'eax'), ('rbx', 'ebx'), ('rcx', 'ecx'),
                    ('rdx', 'edx'), ('rsi', 'esi'), ('rdi', 'edi'),
                    ('rbp', 'ebp'), ('rsp', 'esp')]:
    _REGISTERS[_full] = (_full, 64)
    _REGISTERS[_low] = (_full, 32)
for _number in range(8, 16):
    _REGISTERS[f'r{_number}'] = (f'r{_number}', 64)
    _REGISTERS[f'r{_number}d'] = (f'r{_number}', 32)

_LABEL = re.compile(r'^\s*([0-9a-fA-F]+) <(.+)>:$')
_INSTRUCTION = re.compile(r'^\s*([0-9a-fA-F]+):\s+(\S+)(?:\s+(.*))?$')
_INTEGER = re.compile(r'^[+-]?(?:0x[0-9a-fA-F]+|[0-9]+)$')
_SCOPE = 'straight-line leaf unsigned integer bit-vector recovery'


class _DeadlineExpired(TimeoutError):
    pass


def _expired(deadline: float | None) -> bool:
    return deadline is not None and time.monotonic() >= deadline


def _check_deadline(deadline: float | None) -> None:
    if _expired(deadline):
        raise _DeadlineExpired('Native analysis timeout: shared end-to-end deadline expired.')


def _function_id(address: int) -> str:
    return f'native:{address:x}'


def _export_name(name: str, address: int) -> str:
    # The fixed prefix excludes C keywords, reserved leading underscores, and
    # raw symbol interpolation. The address also distinguishes sanitized names.
    safe = re.sub(r'[^A-Za-z0-9_]', '_', name)[:80] or 'function'
    return f'gd_{safe}_{address:x}'


def _inspect(path: Path, deadline: float | None = None) -> tuple[str, str, dict, list[str], bool]:
    try:
        return _inspect_with_budget(path, deadline)
    except _DeadlineExpired:
        return 'unknown', 'unknown', {}, ['Native analysis timeout during format/relocation inspection; C recovery disabled.'], False


def _inspect_with_budget(path: Path, deadline: float | None) -> tuple[str, str, dict, list[str], bool]:
    """Read format/ABI evidence without asking the input to run anything."""
    _check_deadline(deadline)
    metadata: dict = {}
    diagnostics: list[str] = []
    with path.open('rb') as stream:
        stream.seek(0, 2)
        file_size = stream.tell()
        stream.seek(0)
        header = stream.read(64)
        if header.startswith(b'\x7fELF'):
            if len(header) < 20 or header[5] not in (1, 2):
                return 'ELF', 'unknown', metadata, ['Truncated or invalid ELF header.'], False
            order = 'little' if header[5] == 1 else 'big'
            machine = int.from_bytes(header[18:20], order)
            architecture = {3: 'x86', 62: 'x86_64', 40: 'arm', 183: 'aarch64',
                            243: 'riscv'}.get(machine, f'elf-machine-{machine}')
            bits = {1: 32, 2: 64}.get(header[4])
            elf_type = int.from_bytes(header[16:18], order)
            metadata.update(bits=bits, endianness=order, elf_type=elf_type,
                            elf_osabi=header[7])
            supported = machine == 62 and bits == 64 and order == 'little'
            if not supported:
                diagnostics.append('C recovery requires a little-endian ELF x86-64 SysV ABI input.')
                return 'ELF', architecture, metadata, diagnostics, False
            metadata['abi'] = 'sysv-amd64'
            if len(header) < 64 or header[6] != 1:
                diagnostics.append('Truncated or invalid ELF64 header; C recovery disabled.')
                return 'ELF', architecture, metadata, diagnostics, False
            if elf_type not in (2, 3):
                diagnostics.append('C recovery requires an executable/shared ELF with applied relocations.')
                return 'ELF', architecture, metadata, diagnostics, False
            # Text relocations can change immediate instruction operands at load
            # time. A scalar model of the on-disk immediate would be incorrect.
            phoff = struct.unpack_from('<Q', header, 32)[0]
            phsize, phcount = struct.unpack_from('<HH', header, 54)
            if phcount > _MAX_PROGRAM_HEADERS:
                diagnostics.append('ELF program header count exceeds the inspection budget; C recovery disabled.')
                return 'ELF', architecture, metadata, diagnostics, False
            if phcount and (phsize < 56 or phoff + phsize * phcount > file_size):
                diagnostics.append('Invalid ELF program headers; C recovery disabled.')
                return 'ELF', architecture, metadata, diagnostics, False
            dynamic: tuple[int, int] | None = None
            for index in range(phcount):
                if index % 64 == 0:
                    _check_deadline(deadline)
                stream.seek(phoff + index * phsize)
                program_header = stream.read(56)
                if len(program_header) != 56:
                    diagnostics.append('Truncated ELF program headers; C recovery disabled.')
                    return 'ELF', architecture, metadata, diagnostics, False
                segment_type, segment_flags = struct.unpack_from('<II', program_header)
                # Loader relocations in writable executable segments need not
                # set DT_TEXTREL. On-disk immediates may therefore be replaced
                # before execution even when the dynamic textrel flag is absent.
                if segment_type == 1 and segment_flags & 3 == 3:  # PT_LOAD, PF_W|PF_X
                    diagnostics.append('ELF has a writable executable load segment; instruction relocations/mutations are unmodeled and C recovery is disabled.')
                    return 'ELF', architecture, metadata, diagnostics, False
                if segment_type != 2:  # PT_DYNAMIC
                    continue
                if dynamic is not None:
                    diagnostics.append('Multiple ELF PT_DYNAMIC segments are unsupported; C recovery disabled.')
                    return 'ELF', architecture, metadata, diagnostics, False
                offset = struct.unpack_from('<Q', program_header, 8)[0]
                size = struct.unpack_from('<Q', program_header, 32)[0]
                if size > 8 * 1024 * 1024 or size % 16 or offset + size > file_size:
                    diagnostics.append('Unsupported ELF dynamic table bounds/size; C recovery disabled.')
                    return 'ELF', architecture, metadata, diagnostics, False
                dynamic = (offset, size)
            if dynamic is not None:
                _check_deadline(deadline)
                offset, size = dynamic
                stream.seek(offset)
                table = stream.read(size)
                if len(table) != size:
                    diagnostics.append('Truncated ELF dynamic table; C recovery disabled.')
                    return 'ELF', architecture, metadata, diagnostics, False
                terminated = False
                for position in range(0, size, 16):
                    if position % (16 * 128) == 0:
                        _check_deadline(deadline)
                    tag, value = struct.unpack_from('<QQ', table, position)
                    if tag == 0:
                        terminated = True
                        break
                    if tag == 22 or (tag == 30 and value & 4):  # DT_TEXTREL / DF_TEXTREL
                        diagnostics.append('ELF text relocations change instructions at load time; C recovery disabled.')
                        return 'ELF', architecture, metadata, diagnostics, False
                if not terminated:
                    diagnostics.append('ELF dynamic table has no DT_NULL terminator; C recovery disabled.')
                    return 'ELF', architecture, metadata, diagnostics, False
            _check_deadline(deadline)
            return 'ELF', architecture, metadata, diagnostics, True
        if header.startswith(b'MZ'):
            architecture = 'unknown'
            if len(header) == 64:
                stream.seek(int.from_bytes(header[60:64], 'little'))
                pe = stream.read(6)
                if pe.startswith(b'PE\x00\x00'):
                    architecture = {0x8664: 'x86_64', 0x14c: 'x86',
                                    0xaa64: 'aarch64'}.get(int.from_bytes(pe[4:6], 'little'), 'unknown')
            return 'PE', architecture, {'abi': 'unknown'}, [
                'PE calling conventions are unsupported; disassembly is retained without C recovery.'
            ], False
    return 'unknown', 'unknown', metadata, ['Unknown native format; no ABI assumed and no C recovery.'], False


def _objdump(path: Path, timeout: float) -> tuple[str, list[str], bool]:
    diagnostics: list[str] = []
    arguments = ['objdump', '-d', '-M', 'intel', '--no-show-raw-insn',
                 '--wide', '--disassemble-zeroes', '--', str(path.resolve())]
    # Temporary files bound Python memory even when binutils emits large output.
    # Never use a shell, and never execute the input artifact.
    with tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as error:
        result = None
        try:
            result = subprocess.run(arguments, stdout=output, stderr=error,
                                    timeout=timeout, check=False)
        except FileNotFoundError:
            return '', ['objdump was not found on PATH; install binutils for native disassembly.'], False
        except subprocess.TimeoutExpired:
            diagnostics.append(f'objdump timeout after {timeout:g} seconds; C recovery disabled.')
        except OSError as exc:
            return '', [f'objdump could not start: {exc}'], False
        output.seek(0)
        data = output.read(_MAX_TOOL_OUTPUT + 1)
        error.seek(0)
        errors = error.read(_MAX_TOOL_ERROR + 1)
        complete = result is not None and result.returncode == 0 and len(data) <= _MAX_TOOL_OUTPUT
        if len(data) > _MAX_TOOL_OUTPUT:
            diagnostics.append(f'objdump output exceeds {_MAX_TOOL_OUTPUT} bytes; truncated and C recovery disabled.')
        if result is not None and result.returncode:
            diagnostics.append(f'objdump failed with exit status {result.returncode}; C recovery disabled.')
        if errors:
            diagnostics.append('objdump: ' + errors[:_MAX_TOOL_ERROR].decode('utf-8', errors='replace').strip())
        if len(errors) > _MAX_TOOL_ERROR:
            diagnostics.append('objdump stderr was truncated.')
        return data[:_MAX_TOOL_OUTPUT].decode('utf-8', errors='replace'), diagnostics, complete


def _parse_disassembly(output: str, deadline: float | None = None) -> list[Function]:
    functions: list[Function] = []
    current: Function | None = None
    for index, line in enumerate(io.StringIO(output)):
        # Retain a small first batch of already-produced evidence even after a
        # tool timeout; subsequent batches share the analysis deadline.
        if index and index % 128 == 0 and _expired(deadline):
            if current is not None:
                current.diagnostics.append('Native analysis timeout during disassembly parsing; function may be incomplete.')
            break
        line = line.rstrip('\r\n')
        label = _LABEL.match(line)
        if label:
            address = int(label.group(1), 16)
            name = label.group(2)
            current = Function(id=_function_id(address), name=name, address=address,
                               metadata={'export_name': _export_name(name, address),
                                         'original_symbol': name, 'recovery_scope': _SCOPE})
            functions.append(current)
            continue
        match = _INSTRUCTION.match(line)
        if current is None or match is None:
            continue
        instruction = Instruction(int(match.group(1), 16), match.group(2).lower(),
                                  (match.group(3) or '').strip())
        current.instructions.append(instruction)
        if instruction.mnemonic in ('call', 'callq'):
            target = re.match(r'^(?:0x)?([0-9a-fA-F]+)(?:\s+<.*>)?$', instruction.operands)
            if target:
                target_id = _function_id(int(target.group(1), 16))
                if target_id not in current.calls:
                    current.calls.append(target_id)
            else:
                current.metadata.setdefault('unresolved_calls', []).append(instruction.operands)
    return functions


class _Unsupported(ValueError):
    pass


class _Recovery:
    """Track full registers, 32-bit truncation, and entry-register use."""
    def __init__(self, function: Function, deadline: float | None = None):
        self.function = function
        self.deadline = deadline
        self.lines: list[str] = []
        self.initialized: set[str] = set()
        self.entry_live = set(_ARGUMENTS)
        self.parameter_bits: dict[int, int] = {}
        self.last_width: dict[str, int] = {}
        self.return_bits: int | None = None
        self.returned = False

    def register(self, operand: str) -> tuple[str, int]:
        try:
            return _REGISTERS[operand]
        except KeyError:
            raise _Unsupported(f'Unsupported register/operand {operand!r}; only scalar 32/64-bit registers are modeled.') from None

    def read(self, operand: str, expected_bits: int | None = None, *, observed_bits: int | None = None) -> str:
        if _INTEGER.fullmatch(operand):
            value = int(operand, 16 if '0x' in operand.lower() else 10)
            if not -(1 << 63) <= value < (1 << 64):
                raise _Unsupported('Immediate outside supported 64-bit bit-vector range.')
            return f'UINT64_C(0x{value & ((1 << 64) - 1):x})'
        full, bits = self.register(operand)
        if expected_bits is not None and bits != expected_bits:
            raise _Unsupported('Mixed operand widths are not supported for this instruction.')
        # LEA into a 32-bit destination depends only on the low address bits,
        # even though Intel syntax names full 64-bit address registers.
        bits = observed_bits or bits
        if full not in _CALLER_SAVED:
            raise _Unsupported(f'Stack/callee-saved register {operand} is outside the modeled leaf ABI.')
        if full in self.entry_live:
            position = _ARGUMENTS.index(full)
            self.parameter_bits[position] = max(self.parameter_bits.get(position, 0), bits)
            if full not in self.initialized:
                self.lines.append(f'    uint64_t r_{full} = (uint64_t)p{position};')
                self.initialized.add(full)
        elif full not in self.initialized:
            raise _Unsupported(f'Read of uninitialized register {operand}.')
        return f'((uint64_t)(uint32_t)r_{full})' if bits == 32 else f'r_{full}'

    def write(self, operand: str, expression: str) -> None:
        full, bits = self.register(operand)
        if full not in _CALLER_SAVED:
            raise _Unsupported(f'Write to stack/callee-saved register {operand} is unsupported.')
        prefix = '' if full in self.initialized else 'uint64_t '
        cast = '(uint64_t)(uint32_t)' if bits == 32 else '(uint64_t)'
        self.lines.append(f'    {prefix}r_{full} = {cast}({expression});')
        self.initialized.add(full)
        self.entry_live.discard(full)
        self.last_width[full] = bits

    def lea(self, operand: str, result_bits: int) -> str:
        match = re.fullmatch(r'\[([^\[\]]+)\]', operand)
        if not match:
            raise _Unsupported('LEA requires a scalar address expression without memory access or segment prefixes.')
        expression = match.group(1).replace(' ', '')
        tokens = re.findall(r'[+-]?[^+-]+', expression)
        if not tokens or ''.join(tokens) != expression:
            raise _Unsupported('Unsupported LEA address expression.')
        pieces = []
        for token in tokens:
            sign = '-' if token.startswith('-') else '+'
            term = token.lstrip('+-')
            if _INTEGER.fullmatch(term):
                value = self.read(term)
            elif '*' in term:
                fields = term.split('*')
                if len(fields) != 2 or fields[1] not in ('1', '2', '4', '8'):
                    raise _Unsupported('LEA index must have a scale of 1, 2, 4, or 8.')
                if sign == '-':
                    raise _Unsupported('Negative LEA register terms are not modeled.')
                value = f'({self.read(fields[0], 64, observed_bits=result_bits)} * UINT64_C({fields[1]}))'
            else:
                if sign == '-':
                    raise _Unsupported('Negative LEA register terms are not modeled.')
                value = self.read(term, 64, observed_bits=result_bits)
            pieces.append(f' {sign} {value}')
        return '(UINT64_C(0)' + ''.join(pieces) + ')'

    def instruction(self, item: Instruction) -> None:
        mnemonic = item.mnemonic
        text = item.operands.split('#', 1)[0].strip().lower()
        # GNU renders alignment NOPs with prefixes as "data16 cs nop ...".
        if mnemonic in ('data16', 'cs', 'ds', 'es', 'ss', 'addr32'):
            words = (mnemonic + ' ' + text).split()
            while words and words[0] in ('data16', 'cs', 'ds', 'es', 'ss', 'addr32'):
                words.pop(0)
            if words and words[0] == 'nop':
                return
        if mnemonic in ('nop', 'endbr64'):
            return
        if self.returned:
            raise _Unsupported('Non-padding instructions follow RET; function boundaries/control flow are ambiguous.')
        operands = [part.strip() for part in text.split(',')] if text else []
        if mnemonic in ('ret', 'retq'):
            if operands:
                raise _Unsupported('RET stack adjustment is outside the SysV leaf subset.')
            if 'rax' not in self.initialized:
                raise _Unsupported('Return register RAX is uninitialized; no scalar return inferred.')
            self.return_bits = self.last_width['rax']
            self.lines.append(f'    return (uint{self.return_bits}_t)r_rax;')
            self.returned = True
            return
        if mnemonic in ('mov', 'movabs') and len(operands) == 2:
            _, bits = self.register(operands[0])
            self.write(operands[0], self.read(operands[1], bits))
            return
        if mnemonic == 'lea' and len(operands) == 2:
            _, bits = self.register(operands[0])
            self.write(operands[0], self.lea(operands[1], bits))
            return
        if mnemonic in ('add', 'sub', 'and', 'or', 'xor', 'imul'):
            if mnemonic == 'imul' and len(operands) == 3:
                _, bits = self.register(operands[0])
                if not _INTEGER.fullmatch(operands[2]):
                    raise _Unsupported('Three-operand IMUL requires an immediate multiplier.')
                self.write(operands[0], f'({self.read(operands[1], bits)} * {self.read(operands[2])})')
                return
            if len(operands) != 2:
                raise _Unsupported(f'{mnemonic.upper()} requires two scalar operands; implicit high products are unsupported.')
            _, bits = self.register(operands[0])
            if mnemonic in ('xor', 'sub') and operands[0] == operands[1]:
                self.write(operands[0], 'UINT64_C(0)')
                return
            left = self.read(operands[0], bits)
            right = self.read(operands[1], bits)
            operator = {'add': '+', 'sub': '-', 'and': '&', 'or': '|', 'xor': '^', 'imul': '*'}[mnemonic]
            self.write(operands[0], f'({left} {operator} {right})')
            return
        if mnemonic in ('shl', 'sal', 'shr') and len(operands) in (1, 2):
            _, bits = self.register(operands[0])
            immediate = operands[1] if len(operands) == 2 else '1'
            if not _INTEGER.fullmatch(immediate):
                raise _Unsupported('Only immediate shifts with counts smaller than the operand width are modeled.')
            count = int(immediate, 16 if '0x' in immediate.lower() else 10)
            if not 0 <= count < bits:
                raise _Unsupported('Shift count is out of range; masked x86 counts are not inferred.')
            operator = '>>' if mnemonic == 'shr' else '<<'
            self.write(operands[0], f'({self.read(operands[0], bits)} {operator} {count})')
            return
        if mnemonic in ('neg', 'not', 'inc', 'dec', 'bswap') and len(operands) == 1:
            _, bits = self.register(operands[0])
            value = self.read(operands[0], bits)
            if mnemonic == 'neg':
                expression = f'(UINT64_C(0) - {value})'
            elif mnemonic == 'not':
                expression = f'(~{value})'
            elif mnemonic == 'inc':
                expression = f'({value} + UINT64_C(1))'
            elif mnemonic == 'dec':
                expression = f'({value} - UINT64_C(1))'
            else:
                builtin = '__builtin_bswap32' if bits == 32 else '__builtin_bswap64'
                expression = f'{builtin}((uint{bits}_t){value})'
            self.write(operands[0], expression)
            return
        if mnemonic in ('rol', 'ror') and len(operands) in (1, 2):
            _, bits = self.register(operands[0])
            immediate = operands[1] if len(operands) == 2 else '1'
            if not _INTEGER.fullmatch(immediate):
                raise _Unsupported('Only immediate rotations with counts smaller than the operand width are modeled.')
            count = int(immediate, 16 if '0x' in immediate.lower() else 10)
            if not 0 <= count < bits:
                raise _Unsupported('Rotation count is out of range; masked x86 counts are not inferred.')
            value = self.read(operands[0], bits)
            if count == 0:
                expression = value
            elif mnemonic == 'rol':
                expression = f'(({value} << {count}) | ({value} >> {bits - count}))'
            else:
                expression = f'(({value} >> {count}) | ({value} << {bits - count}))'
            self.write(operands[0], expression)
            return
        if mnemonic in ('movsxd', 'movslq') and len(operands) == 2:
            _, dst_bits = self.register(operands[0])
            _, src_bits = self.register(operands[1])
            if dst_bits != 64 or src_bits != 32:
                raise _Unsupported('MOVSXD requires a 64-bit destination and 32-bit source register.')
            value = self.read(operands[1], 32)
            self.write(operands[0], f'(uint64_t)(int64_t)(int32_t){value}')
            return
        if mnemonic in ('cdqe', 'cltq'):
            if operands:
                raise _Unsupported('CDQE/CLTQ takes no operands.')
            value = self.read('eax', 32)
            self.write('rax', f'(uint64_t)(int64_t)(int32_t){value}')
            return
        if mnemonic == 'xchg' and len(operands) == 2:
            _, dst_bits = self.register(operands[0])
            _, src_bits = self.register(operands[1])
            if dst_bits != src_bits:
                raise _Unsupported('XCHG requires matching register operand widths.')
            left = self.read(operands[0], dst_bits)
            right = self.read(operands[1], src_bits)
            if operands[0] == operands[1]:
                self.write(operands[0], left)
            else:
                self.swap_serial = getattr(self, 'swap_serial', 0) + 1
                tmp = f'__gd_swap_{self.swap_serial}'
                self.lines.append(f'    uint64_t {tmp} = {left};')
                self.write(operands[0], right)
                self.write(operands[1], tmp)
            return
        raise _Unsupported(f'Unsupported instruction {mnemonic!r}: flags, memory, branches, calls, or unmodeled effects require a richer backend.')

    def recover(self) -> None:
        try:
            _check_deadline(self.deadline)
            self._recover()
        except _DeadlineExpired:
            self.function.source = None
            self.function.diagnostics.append('Native analysis timeout during C recovery; generated source discarded.')

    def _recover(self) -> None:
        try:
            if not self.function.instructions:
                raise _Unsupported('No instructions were disassembled for this symbol.')
            for index, instruction in enumerate(self.function.instructions):
                if index % 128 == 0:
                    _check_deadline(self.deadline)
                try:
                    self.instruction(instruction)
                except _Unsupported as exc:
                    raise _Unsupported(f'0x{instruction.address:x}: {exc}') from None
            if not self.returned:
                raise _Unsupported('No supported RET was found; function may be incomplete or have control flow.')
        except _Unsupported as exc:
            self.function.diagnostics.append(str(exc))
            return
        _check_deadline(self.deadline)
        parameter_bits = [self.parameter_bits.get(index, 64)
                          for index in range(max(self.parameter_bits, default=-1) + 1)]
        self.function.metadata.update(
            return_bits=self.return_bits,
            parameter_bits=parameter_bits,
            parameter_registers=list(_ARGUMENTS[:len(parameter_bits)]),
            used_parameters=sorted(self.parameter_bits),
            type_evidence={
                'confidence': 'low',
                'basis': 'Observed machine register widths; unsigned bit-vectors, not original language types.',
                'signedness': 'unknown; modulo arithmetic is modeled with unsigned C types',
            },
            assumptions=[
                'Entry uses SysV AMD64 scalar integer argument registers.',
                'A 32-bit register write zero-extends its full 64-bit register.',
                'Flags are dead at return; no memory, stack, calls, or callee-saved writes are modeled.',
                'Only observed argument low bits are specified; original prototypes and signedness are unknown.',
            ],
        )
        if len(parameter_bits) != len(self.parameter_bits):
            self.function.diagnostics.append('Unused leading/intermediate ABI parameters have unknown width and use uint64_t placeholders.')
        arguments = ', '.join(f'uint{bits}_t p{index}' for index, bits in enumerate(parameter_bits)) or 'void'
        # Silence unused ABI placeholders and register intermediates without
        # suppressing compiler warnings globally or adding observable effects.
        used_variables = sorted(self.initialized)
        body = self.lines[:-1]
        body += [f'    (void)p{index};' for index in range(len(parameter_bits)) if index not in self.parameter_bits]
        body += [f'    (void)r_{register};' for register in used_variables]
        body += self.lines[-1:]
        self.function.source = '\n'.join([
            '#include <stdint.h>',
            '/* Recovered SysV AMD64 leaf bit-vectors; machine widths, not original types.',
            ' * Unsigned arithmetic wraps; 32-bit writes zero-extend; flags are dead.',
            ' * Original prototypes, signedness, and high argument bits are unknown. */',
            f'uint{self.return_bits}_t {self.function.metadata["export_name"]}({arguments}) {{',
            *body, '}',
        ])
        _check_deadline(self.deadline)


def analyze(path: Path, timeout: float = 60) -> Analysis:
    """Disassemble native functions and recover only modeled scalar leaf code."""
    if isinstance(timeout, bool) or not isinstance(timeout, (float, int)) or not math.isfinite(timeout) or timeout <= 0:
        raise ValueError('timeout must be finite and positive')
    deadline = time.monotonic() + timeout
    path = Path(path)
    digest = hashlib.sha256()
    try:
        with path.open('rb') as stream:
            while True:
                _check_deadline(deadline)
                chunk = stream.read(1024 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
        _check_deadline(deadline)
    except _DeadlineExpired:
        return Analysis(binary_hash='', format='unknown', architecture='unknown',
                        backend='native-objdump', diagnostics=[
                            'Native analysis timeout during hashing; SHA256 is incomplete and C recovery disabled.'
                        ], metadata={'hash_complete': False, 'analysis_complete': False,
                                     'input_executed': False, 'source_recovery_supported': False,
                                     'timeout_seconds': timeout})
    format_name, architecture, metadata, diagnostics, supported = _inspect(path, deadline=deadline)
    remaining = deadline - time.monotonic()
    if remaining > 0:
        output, tool_diagnostics, complete = _objdump(path, remaining)
    else:
        output, tool_diagnostics, complete = '', ['Native analysis timeout before objdump; C recovery disabled.'], False
    diagnostics.extend(tool_diagnostics)
    functions = _parse_disassembly(output, deadline=deadline)
    if not functions and complete:
        diagnostics.append('objdump found no named code symbols; stripped function discovery is unsupported.')
    metadata.update(
        recovery_scope=_SCOPE,
        source_recovery_supported=bool(supported and complete),
        disassembly_tool='objdump',
        input_executed=False,
        hash_complete=True,
        timeout_seconds=timeout,
    )
    for function in functions:
        if supported and complete and not _expired(deadline):
            _Recovery(function, deadline=deadline).recover()
        else:
            function.diagnostics.append('C recovery disabled: unsupported/unknown ABI or incomplete disassembly. See analysis diagnostics.')
    expired = _expired(deadline)
    metadata['analysis_complete'] = bool(complete and not expired)
    if expired:
        metadata['source_recovery_supported'] = False
        diagnostics.append('Native analysis timeout: end-to-end deadline expired; C recovery disabled.')
        for function in functions:
            function.source = None
    return Analysis(binary_hash=digest.hexdigest(), format=format_name,
                    architecture=architecture, backend='native-objdump', functions=functions,
                    diagnostics=diagnostics, metadata=metadata)
