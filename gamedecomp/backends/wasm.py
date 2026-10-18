"""A bounded MVP WebAssembly reader with conservative scalar C recovery.

Unsupported bodies retain raw evidence. This is not a full WASM validator.
"""
import hashlib
import math
import re
import time
from pathlib import Path

from gamedecomp.models import Analysis, Function, Instruction


class Reader:
    def __init__(self, data: bytes, base: int = 0, deadline: float | None = None):
        self.data, self.position, self.base, self.deadline = data, 0, base, deadline

    def take(self, count: int) -> bytes:
        if self.deadline is not None and time.monotonic() >= self.deadline:
            raise TimeoutError('Analisi WASM oltre il timeout')
        if count < 0 or count > len(self.data) - self.position:
            raise ValueError('WebAssembly troncato')
        value = self.data[self.position:self.position + count]
        self.position += count
        return value

    def byte(self) -> int:
        return self.take(1)[0]

    def leb(self, bits: int = 32, signed: bool = False) -> int:
        value, shift = 0, 0
        for _ in range((bits + 6) // 7):
            byte = self.byte()
            value |= (byte & 0x7f) << shift
            shift += 7
            if byte < 0x80:
                if signed and byte & 0x40:
                    value -= 1 << shift
                lower = -(1 << (bits - 1)) if signed else 0
                upper = (1 << (bits - 1)) if signed else (1 << bits)
                if not lower <= value < upper:
                    raise ValueError('LEB128 fuori intervallo')
                return value
        raise ValueError('LEB128 troppo lungo')

    def name(self) -> str:
        return self.take(self.leb()).decode('utf-8', errors='strict')

    def done(self):
        if self.position != len(self.data):
            raise ValueError('Dati WebAssembly residui nella sezione')


def _name(value: str, index: int) -> str:
    safe = re.sub(r'[^a-zA-Z0-9_]', '_', value)
    return f'wasm_{index}_{safe[:80]}'


def _limits(reader: Reader):
    flag = reader.leb()
    if flag not in (0, 1):
        raise ValueError('Limiti WASM estesi non supportati')
    reader.leb()
    if flag:
        reader.leb()


def _recover(function: Function, body: bytes, parameters: list[int], returns: list[int], deadline: float | None = None):
    names = {0x7f: ('uint32_t', 32), 0x7e: ('uint64_t', 64)}
    if any(t not in names for t in parameters + returns) or len(returns) != 1:
        raise ValueError('Firma non scalare intera supportata')
    reader = Reader(body, function.address, deadline)
    locals_ = list(parameters)
    declarations = []
    groups = reader.leb()
    if groups > 10000:
        raise ValueError('Troppi gruppi di variabili locali')
    for _ in range(groups):
        count, kind = reader.leb(), reader.byte()
        if kind not in names or len(locals_) + count > 10000:
            raise ValueError('Locali non supportati o eccessivi')
        for _ in range(count):
            if deadline is not None and time.monotonic() >= deadline:
                raise TimeoutError('Recupero locali WASM oltre il timeout')
            declarations.append(f'    {names[kind][0]} l{len(locals_)} = 0;')
            locals_.append(kind)
    stack: list[tuple[str, int]] = []
    statements, serial, terminated = [], 0, False

    def pop(kind=None):
        if not stack:
            raise ValueError('Stack WASM insufficiente')
        value = stack.pop()
        if kind is not None and value[1] != kind:
            raise ValueError('Tipo stack WASM incompatibile')
        return value

    while reader.position < len(body):
        address = reader.base + reader.position
        opcode = reader.byte()
        operands, mnemonic = '', f'op_{opcode:02x}'
        if opcode == 0x01:
            mnemonic = 'nop'
        elif opcode in (0x20, 0x21, 0x22):
            index = reader.leb()
            if index >= len(locals_):
                raise ValueError('Indice locale WASM non valido')
            kind = locals_[index]
            local = f'p{index}' if index < len(parameters) else f'l{index}'
            operands = str(index)
            mnemonic = {0x20: 'local.get', 0x21: 'local.set', 0x22: 'local.tee'}[opcode]
            if opcode == 0x20:
                # Freeze the read: later local.set must not change old stack values.
                serial += 1
                temp = f't{serial}'
                statements.append(f'    {names[kind][0]} {temp} = {local};')
                stack.append((temp, kind))
            else:
                value, _ = pop(kind)
                statements.append(f'    {local} = {value};')
                if opcode == 0x22:
                    stack.append((value, kind))
        elif opcode in (0x41, 0x42):
            kind = 0x7f if opcode == 0x41 else 0x7e
            bits = names[kind][1]
            value = reader.leb(bits, signed=True)
            stack.append((f'UINT{bits}_C({value % (1 << bits)})', kind))
            mnemonic, operands = f'i{bits}.const', str(value)
        elif opcode == 0x1a:
            pop()
            mnemonic = 'drop'
        elif opcode == 0x1b:
            cond, _ = pop(0x7f)
            right, kind = pop()
            left, _ = pop(kind)
            ctype, _ = names[kind]
            serial += 1
            temp = f't{serial}'
            statements.append(f'    {ctype} {temp} = ({cond} != 0u ? {left} : {right});')
            stack.append((temp, kind))
            mnemonic = 'select'
        elif opcode in (0x45, 0x50):
            in_kind = 0x7f if opcode == 0x45 else 0x7e
            val, _ = pop(in_kind)
            serial += 1
            temp = f't{serial}'
            statements.append(f'    uint32_t {temp} = (uint32_t)({val} == 0u);')
            stack.append((temp, 0x7f))
            mnemonic = f'i{names[in_kind][1]}.eqz'
        elif opcode in (
            0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
            0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a,
        ):
            cmp_table = {
                0x46: (0x7f, '==', False, 'eq'),   0x47: (0x7f, '!=', False, 'ne'),
                0x48: (0x7f, '<',  True,  'lt_s'), 0x49: (0x7f, '<',  False, 'lt_u'),
                0x4a: (0x7f, '>',  True,  'gt_s'), 0x4b: (0x7f, '>',  False, 'gt_u'),
                0x4c: (0x7f, '<=', True,  'le_s'), 0x4d: (0x7f, '<=', False, 'le_u'),
                0x4e: (0x7f, '>=', True,  'ge_s'), 0x4f: (0x7f, '>=', False, 'ge_u'),
                0x51: (0x7e, '==', False, 'eq'),   0x52: (0x7e, '!=', False, 'ne'),
                0x53: (0x7e, '<',  True,  'lt_s'), 0x54: (0x7e, '<',  False, 'lt_u'),
                0x55: (0x7e, '>',  True,  'gt_s'), 0x56: (0x7e, '>',  False, 'gt_u'),
                0x57: (0x7e, '<=', True,  'le_s'), 0x58: (0x7e, '<=', False, 'le_u'),
                0x59: (0x7e, '>=', True,  'ge_s'), 0x5a: (0x7e, '>=', False, 'ge_u'),
            }
            in_kind, op, is_signed, op_name = cmp_table[opcode]
            right, _ = pop(in_kind)
            left, _ = pop(in_kind)
            bits = names[in_kind][1]
            serial += 1
            temp = f't{serial}'
            if is_signed:
                stype = f'int{bits}_t'
                statements.append(f'    uint32_t {temp} = (uint32_t)(({stype}){left} {op} ({stype}){right});')
            else:
                statements.append(f'    uint32_t {temp} = (uint32_t)({left} {op} {right});')
            stack.append((temp, 0x7f))
            mnemonic = f'i{bits}.{op_name}'
        elif opcode in (0x67, 0x68, 0x69, 0x79, 0x7a, 0x7b):
            unary_table = {
                0x67: (0x7f, 'clz',    lambda v: f'({v} ? (uint32_t)__builtin_clz({v}) : 32u)'),
                0x68: (0x7f, 'ctz',    lambda v: f'({v} ? (uint32_t)__builtin_ctz({v}) : 32u)'),
                0x69: (0x7f, 'popcnt', lambda v: f'(uint32_t)__builtin_popcount({v})'),
                0x79: (0x7e, 'clz',    lambda v: f'({v} ? (uint64_t)__builtin_clzll({v}) : 64ULL)'),
                0x7a: (0x7e, 'ctz',    lambda v: f'({v} ? (uint64_t)__builtin_ctzll({v}) : 64ULL)'),
                0x7b: (0x7e, 'popcnt', lambda v: f'(uint64_t)__builtin_popcountll({v})'),
            }
            kind, op_name, builder = unary_table[opcode]
            val, _ = pop(kind)
            ctype, bits = names[kind]
            serial += 1
            temp = f't{serial}'
            statements.append(f'    {ctype} {temp} = {builder(val)};')
            stack.append((temp, kind))
            mnemonic = f'i{bits}.{op_name}'
        elif opcode in (0xa7, 0xac, 0xad, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4):
            conv_table = {
                0xa7: (0x7e, 0x7f, 'i32.wrap_i64',     lambda v: f'(uint32_t)({v})'),
                0xac: (0x7f, 0x7e, 'i64.extend_i32_s', lambda v: f'(uint64_t)(int64_t)(int32_t)({v})'),
                0xad: (0x7f, 0x7e, 'i64.extend_i32_u', lambda v: f'(uint64_t)({v})'),
                0xc0: (0x7f, 0x7f, 'i32.extend8_s',    lambda v: f'(uint32_t)(int32_t)(int8_t)({v})'),
                0xc1: (0x7f, 0x7f, 'i32.extend16_s',   lambda v: f'(uint32_t)(int32_t)(int16_t)({v})'),
                0xc2: (0x7e, 0x7e, 'i64.extend8_s',    lambda v: f'(uint64_t)(int64_t)(int8_t)({v})'),
                0xc3: (0x7e, 0x7e, 'i64.extend16_s',   lambda v: f'(uint64_t)(int64_t)(int16_t)({v})'),
                0xc4: (0x7e, 0x7e, 'i64.extend32_s',   lambda v: f'(uint64_t)(int64_t)(int32_t)({v})'),
            }
            in_kind, out_kind, op_name, builder = conv_table[opcode]
            val, _ = pop(in_kind)
            out_ctype, _ = names[out_kind]
            serial += 1
            temp = f't{serial}'
            statements.append(f'    {out_ctype} {temp} = {builder(val)};')
            stack.append((temp, out_kind))
            mnemonic = op_name
        elif opcode in (0x0b, 0x0f):
            value, _ = pop(returns[0])
            if stack:
                raise ValueError('Stack residuo non supportato alla fine della funzione')
            statements.append(f'    return {value};')
            mnemonic = 'end' if opcode == 0x0b else 'return'
            if opcode == 0x0f:
                if reader.take(len(body) - reader.position) != b'\x0b':
                    raise ValueError('Codice dopo return non supportato')
            reader.done()
            terminated = True
        else:
            operations = {
                0x6a: (0x7f, '+'), 0x6b: (0x7f, '-'), 0x6c: (0x7f, '*'),
                0x71: (0x7f, '&'), 0x72: (0x7f, '|'), 0x73: (0x7f, '^'),
                0x74: (0x7f, '<<'), 0x75: (0x7f, 'shr_s'), 0x76: (0x7f, '>>'),
                0x77: (0x7f, 'rotl'), 0x78: (0x7f, 'rotr'),
                0x7c: (0x7e, '+'), 0x7d: (0x7e, '-'), 0x7e: (0x7e, '*'),
                0x83: (0x7e, '&'), 0x84: (0x7e, '|'), 0x85: (0x7e, '^'),
                0x86: (0x7e, '<<'), 0x87: (0x7e, 'shr_s'), 0x88: (0x7e, '>>'),
                0x89: (0x7e, 'rotl'), 0x8a: (0x7e, 'rotr'),
            }
            if opcode not in operations:
                function.instructions.append(Instruction(address, mnemonic, ''))
                raise ValueError(f'Opcode 0x{opcode:02x} non supportato: controllo, memoria o semantica non modellata')
            kind, operator = operations[opcode]
            right, _ = pop(kind)
            left, _ = pop(kind)
            ctype, bits = names[kind]
            mask = f'{bits - 1}u'
            serial += 1
            temp = f't{serial}'
            if operator == 'shr_s':
                stype = f'int{bits}_t'
                statements.append(f'    {ctype} {temp} = ({ctype})((({stype}){left}) >> ({right} & {mask}));')
            elif operator == 'rotl':
                statements.append(f'    {ctype} {temp} = ({ctype})(({left} << ({right} & {mask})) | ({left} >> ((-{right}) & {mask})));')
            elif operator == 'rotr':
                statements.append(f'    {ctype} {temp} = ({ctype})(({left} >> ({right} & {mask})) | ({left} << ((-{right}) & {mask})));')
            else:
                if operator in ('<<', '>>'):
                    right = f'({right} & {mask})'
                statements.append(f'    {ctype} {temp} = ({ctype})({left} {operator} {right});')
            stack.append((temp, kind))
            mnemonic = f'i{bits}.{operator}'
        function.instructions.append(Instruction(address, mnemonic, operands))
        if terminated:
            break
    if not terminated:
        raise ValueError('Funzione WASM senza end')
    signature = ', '.join(f'{names[kind][0]} p{i}' for i, kind in enumerate(parameters)) or 'void'
    return_kind = names[returns[0]]
    function.source = '\n'.join([
        f'{return_kind[0]} {function.metadata["export_name"]}({signature}) {{',
        *declarations, *statements, '}',
    ])
    function.metadata.update(parameter_bits=[names[t][1] for t in parameters], return_bits=return_kind[1],
                             recovery_scope='WASM integer straight-line MVP, modular arithmetic',
                             type_evidence='WASM value types; original source types unknown')


def analyze(path: Path, timeout: float = 60) -> Analysis:
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not math.isfinite(timeout) or timeout <= 0:
        raise ValueError('Timeout non valido')
    deadline = time.monotonic() + timeout
    if Path(path).stat().st_size > 256 * 1024 * 1024:
        raise ValueError('Modulo WASM troppo grande')
    data = Path(path).read_bytes()
    if len(data) > 256 * 1024 * 1024 or data[:8] != b'\0asm\x01\0\0\0':
        raise ValueError('Modulo WASM non valido o eccessivo')
    reader = Reader(data[8:], 8, deadline)
    types, function_types, bodies, exports = [], [], [], {}
    imported_functions, seen = 0, set()
    while reader.position < len(reader.data):
        if time.monotonic() > deadline:
            raise TimeoutError('Parsing WASM oltre il timeout')
        section_id, length = reader.byte(), reader.leb()
        offset = reader.base + reader.position
        section = Reader(reader.take(length), offset, deadline)
        if section_id == 0:
            continue
        if section_id in seen or section_id > 12:
            raise ValueError('Sezione WASM duplicata o non supportata')
        seen.add(section_id)
        if section_id == 1:
            for _ in range(section.leb()):
                if section.byte() != 0x60:
                    raise ValueError('Tipo WASM non valido')
                params = list(section.take(section.leb()))
                returns = list(section.take(section.leb()))
                types.append((params, returns))
        elif section_id == 2:
            for _ in range(section.leb()):
                section.name(), section.name()
                kind = section.byte()
                if kind == 0:
                    index = section.leb()
                    if index >= len(types):
                        raise ValueError('Tipo import WASM non valido')
                    imported_functions += 1
                elif kind == 1:
                    section.byte()
                    _limits(section)
                elif kind == 2:
                    _limits(section)
                elif kind == 3:
                    section.take(2)
                else:
                    raise ValueError('Import WASM non supportato')
        elif section_id == 3:
            function_types = [section.leb() for _ in range(section.leb())]
        elif section_id == 7:
            for _ in range(section.leb()):
                name, kind, index = section.name(), section.byte(), section.leb()
                if kind == 0:
                    exports.setdefault(index, name)
        elif section_id == 10:
            for _ in range(section.leb()):
                size = section.leb()
                base = section.base + section.position
                bodies.append((base, section.take(size)))
        else:
            continue  # Preserved in input; not used to claim recovery of effects.
        section.done()
    if len(function_types) != len(bodies):
        raise ValueError('Numero di corpi e firme WASM incoerente')
    if any(index >= len(types) for index in function_types):
        raise ValueError('Indice tipo WASM inesistente')
    if any(index >= imported_functions + len(bodies) for index in exports):
        raise ValueError('Export funzione WASM inesistente')
    result = Analysis(hashlib.sha256(data).hexdigest(), 'WASM', 'wasm32', 'wasm')
    for ordinal, ((address, body), type_index) in enumerate(zip(bodies, function_types)):
        index = ordinal + imported_functions
        original = exports.get(index, f'function_{index}')
        function = Function(f'wasm:{index}', original, address, metadata={
            'export_name': _name(original, index), 'original_symbol': original,
            'body_hex': body.hex(), 'function_index': index,
        })
        try:
            _recover(function, body, *types[type_index], deadline=deadline)
        except (ValueError, IndexError) as error:
            function.source = None
            function.diagnostics.append(str(error))
        result.functions.append(function)
    result.metadata.update(imported_functions=imported_functions, validation='partial parser; not full WASM validation')
    if time.monotonic() >= deadline:
        raise TimeoutError('Analisi WASM oltre il timeout')
    return result
