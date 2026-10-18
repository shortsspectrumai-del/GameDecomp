"""Read evidence-backed C/C++ type graphs, without loading the input binary.

DWARF supplies declarations and layout metadata. ELF Itanium RTTI supplies only
partial class/base/vtable evidence. Register-relative accesses remain hypotheses.
The returned graph never changes the conservative decompiler's C baseline.
"""
from __future__ import annotations

import math
import re
import time
from itertools import chain
from pathlib import Path

from .models import Analysis


_TYPE_TAGS = {
    'DW_TAG_base_type': 'base', 'DW_TAG_class_type': 'class',
    'DW_TAG_structure_type': 'struct', 'DW_TAG_union_type': 'union',
    'DW_TAG_enumeration_type': 'enum', 'DW_TAG_pointer_type': 'pointer',
    'DW_TAG_reference_type': 'reference', 'DW_TAG_rvalue_reference_type': 'rvalue_reference',
    'DW_TAG_const_type': 'const', 'DW_TAG_volatile_type': 'volatile',
    'DW_TAG_restrict_type': 'restrict', 'DW_TAG_typedef': 'typedef',
    'DW_TAG_array_type': 'array', 'DW_TAG_subroutine_type': 'subroutine',
    'DW_TAG_ptr_to_member_type': 'member_pointer', 'DW_TAG_unspecified_type': 'unspecified',
    'DW_TAG_atomic_type': 'atomic',
}
_AGGREGATES = {'class', 'struct', 'union'}
_ACCESS = {1: 'public', 2: 'protected', 3: 'private'}
_MAX_INPUT = 256 * 1024 * 1024
_MAX_DEBUG = 64 * 1024 * 1024
_MAX_SYMBOLS = 200000
_MAX_CHILDREN = 20000


class _LimitReached(Exception):
    pass


def _check(deadline: float) -> None:
    if time.monotonic() >= deadline:
        raise _LimitReached('Type recovery deadline exceeded; partial evidence retained.')


def _load_elftools():
    try:
        from elftools.elf.elffile import ELFFile
        return ELFFile
    except ImportError:
        return None


def _text(value) -> str | None:
    if value is None:
        return None
    if isinstance(value, bytes):
        return value[:4096].decode('utf-8', errors='replace')
    return str(value)[:4096]


def _die_id(die) -> str:
    section = 'types:' if die.cu.__class__.__name__ == 'TypeUnit' else ''
    return f'dwarf:{section}{die.offset:x}'


def _evidence(die) -> dict:
    return {'id': f'{_die_id(die)}:evidence', 'source': 'DWARF',
            'die_offset': die.offset, 'cu_offset': die.cu.cu_offset, 'tag': die.tag}


class _DwarfReader:
    def __init__(self, elf, result, analysis, deadline, maximum):
        self.elf, self.result, self.analysis = elf, result, analysis
        self.deadline, self.maximum = deadline, maximum
        self.dies, self.parents, self.children = {}, {}, {}
        self.type_ids = set()

    def referenced_die(self, die, name):
        try:
            return die.get_DIE_from_attribute(name)
        except Exception as error:
            message = f'DWARF reference {name} at {die.offset:#x} is unresolved: {type(error).__name__}.'
            if message not in self.result['diagnostics'] and len(self.result['diagnostics']) < 100:
                self.result['diagnostics'].append(message)
            return None

    def attr(self, die, name, depth=0):
        if die is None or depth >= 16:
            return None
        value = die.attributes.get(name)
        if value is not None:
            return value
        for reference in ('DW_AT_specification', 'DW_AT_abstract_origin'):
            if reference in die.attributes:
                target = self.referenced_die(die, reference)
                value = self.attr(target, name, depth + 1)
                if value is not None:
                    return value
        return None

    def value(self, die, name, default=None):
        attribute = self.attr(die, name)
        return attribute.value if attribute is not None else default

    def ref(self, die, name='DW_AT_type', depth=0):
        if die is None or depth >= 16:
            return None
        if name in die.attributes:
            target = self.referenced_die(die, name)
            return _die_id(target) if target is not None else None
        for reference in ('DW_AT_specification', 'DW_AT_abstract_origin'):
            if reference in die.attributes:
                target = self.referenced_die(die, reference)
                if target is not None:
                    found = self.ref(target, name, depth + 1)
                    if found:
                        return found
        return None

    def qualified_name(self, die):
        names, current, seen = [], die, set()
        while current is not None and len(seen) < 64:
            identifier = _die_id(current)
            if identifier in seen:
                break
            seen.add(identifier)
            if current.tag in {'DW_TAG_namespace', 'DW_TAG_class_type',
                               'DW_TAG_structure_type', 'DW_TAG_union_type',
                               'DW_TAG_enumeration_type', 'DW_TAG_typedef', 'DW_TAG_base_type'}:
                name = _text(self.value(current, 'DW_AT_name'))
                if name:
                    names.append(name)
            current = self.parents.get(identifier)
        return '::'.join(reversed(names)) or None

    def offset(self, die, name='DW_AT_data_member_location'):
        attribute = self.attr(die, name)
        if attribute is None:
            return None, None
        if isinstance(attribute.value, int):
            return attribute.value, None
        data = list(attribute.value)[:4096]
        # DW_OP_plus_uconst alone is a constant member offset. No expression
        # evaluator is used: dereferences in virtual-base locations stay unknown.
        constant_ops = {0x23}
        if name == 'DW_AT_vtable_elem_location':
            constant_ops.add(0x10)  # DW_OP_constu: documented vtable slot index.
            if len(data) == 1 and 0x30 <= data[0] <= 0x4f:
                return data[0] - 0x30, None
        if len(data) >= 2 and data[0] in constant_ops:
            value, shift = 0, 0
            for index, byte in enumerate(data[1:11], start=1):
                value |= (byte & 0x7f) << shift
                if not byte & 0x80:
                    if index == len(data) - 1:
                        return value, None
                    break
                shift += 7
        return None, data

    def child_dies(self, die):
        return self.children.get(_die_id(die), [])

    def signature(self, die):
        parameters = []
        children = self.child_dies(die)
        # Concrete out-of-line functions often refer to the declaration for
        # signature children; their own parameter children take precedence.
        if not any(child.tag == 'DW_TAG_formal_parameter' for child in children):
            for key in ('DW_AT_specification', 'DW_AT_abstract_origin'):
                if key in die.attributes:
                    target = self.referenced_die(die, key)
                    children = self.child_dies(target) if target is not None else []
                    break
        for child in children:
            if child.tag == 'DW_TAG_formal_parameter':
                parameters.append({'name': _text(self.value(child, 'DW_AT_name')),
                                   'type_id': self.ref(child),
                                   'artificial': bool(self.value(child, 'DW_AT_artificial', False)),
                                   'evidence': [_evidence(child)]})
        receiver = self.ref(die, 'DW_AT_object_pointer')
        if receiver:
            parameter = self.dies.get(receiver)
            receiver = self.ref(parameter) if parameter is not None else None
        if receiver is None:
            receiver = next((p['type_id'] for p in parameters if p['name'] == 'this'), None)
        parent = self.parents.get(_die_id(die))
        containing = _die_id(parent) if parent is not None and parent.tag in _TYPE_TAGS else None
        virtuality = self.value(die, 'DW_AT_virtuality', 0)
        vtable_index, vtable_expression = self.offset(die, 'DW_AT_vtable_elem_location')
        return {'name': _text(self.value(die, 'DW_AT_name')),
                'linkage_name': _text(self.value(die, 'DW_AT_linkage_name') or
                                      self.value(die, 'DW_AT_MIPS_linkage_name')),
                'return_type': self.ref(die), 'parameters': parameters,
                'receiver_type': receiver, 'containing_type': containing,
                'variadic': any(child.tag == 'DW_TAG_unspecified_parameters' for child in children),
                'virtual': bool(virtuality), 'pure_virtual': virtuality == 2,
                'vtable_index': vtable_index, 'vtable_expression': vtable_expression,
                'status': 'METADATA', 'evidence': [_evidence(die)]}

    def collect(self):
        # Supplementary DWARF files are not part of the bounded, hashed input;
        # do not follow paths supplied by untrusted .debug_sup/altlink metadata.
        dwarf = self.elf.get_dwarf_info(follow_links=False)
        units = dwarf.iter_CUs()
        if hasattr(dwarf, 'iter_TUs'):
            units = chain(units, dwarf.iter_TUs())
        elif self.elf.get_section_by_name('.debug_types') is not None:
            self.result['diagnostics'].append('Installed pyelftools cannot decode DWARF type units; their references remain unresolved.')
        count = 0
        for cu in units:
            _check(self.deadline)
            stack = []
            for die in cu.iter_DIEs():
                _check(self.deadline)
                count += 1
                if count > min(500000, max(1000, self.maximum * 40)):
                    raise _LimitReached('DWARF DIE count limit reached; partial graph retained.')
                if die.is_null():
                    if stack:
                        stack.pop()
                    continue
                identifier = _die_id(die)
                self.dies[identifier] = die
                if stack:
                    parent = stack[-1]
                    self.parents[identifier] = parent
                    entries = self.children.setdefault(_die_id(parent), [])
                    if len(entries) >= _MAX_CHILDREN:
                        raise _LimitReached('DWARF child count limit reached.')
                    entries.append(die)
                if die.has_children:
                    stack.append(die)

    def parse_type(self, die):
        kind = _TYPE_TAGS[die.tag]
        record = {'id': _die_id(die), 'kind': kind,
                  'name': _text(self.value(die, 'DW_AT_name')),
                  'qualified_name': self.qualified_name(die),
                  'byte_size': self.value(die, 'DW_AT_byte_size'),
                  'alignment': self.value(die, 'DW_AT_alignment'),
                  'definition_available': not bool(self.value(die, 'DW_AT_declaration', False)),
                  'status': 'METADATA', 'evidence': [_evidence(die)]}
        target = self.ref(die)
        if kind not in _AGGREGATES:
            record['target_type'] = target
        if kind == 'base':
            record['encoding'] = self.value(die, 'DW_AT_encoding')
        if kind == 'member_pointer':
            record['containing_type'] = self.ref(die, 'DW_AT_containing_type')
        if kind in _AGGREGATES:
            members, bases, methods = [], [], []
            default_access = 'private' if kind == 'class' else 'public'
            for child in self.child_dies(die):
                _check(self.deadline)
                if child.tag == 'DW_TAG_member':
                    offset, expression = self.offset(child)
                    members.append({'name': _text(self.value(child, 'DW_AT_name')),
                                    'type_id': self.ref(child), 'offset_bytes': offset,
                                    'offset_expression': expression,
                                    'bit_size': self.value(child, 'DW_AT_bit_size'),
                                    'data_bit_offset': self.value(child, 'DW_AT_data_bit_offset'),
                                    'legacy_bit_offset': self.value(child, 'DW_AT_bit_offset'),
                                    'static': bool(self.value(child, 'DW_AT_external', False)) and offset is None,
                                    'accessibility': _ACCESS.get(self.value(child, 'DW_AT_accessibility'), default_access),
                                    'evidence': [_evidence(child)]})
                elif child.tag == 'DW_TAG_inheritance':
                    offset, expression = self.offset(child)
                    virtual = bool(self.value(child, 'DW_AT_virtuality', 0))
                    bases.append({'type_id': self.ref(child), 'offset_bytes': None if virtual else offset,
                                  'offset_expression': expression, 'virtual': virtual,
                                  'accessibility': _ACCESS.get(self.value(child, 'DW_AT_accessibility'), default_access),
                                  'evidence': [_evidence(child)]})
                elif child.tag == 'DW_TAG_subprogram':
                    methods.append(self.signature(child))
            record.update(members=members, bases=bases, methods=methods, vtables=[])
        elif kind == 'enum':
            record['enumerators'] = [
                {'name': _text(self.value(child, 'DW_AT_name')),
                 'value': self.value(child, 'DW_AT_const_value')}
                for child in self.child_dies(die) if child.tag == 'DW_TAG_enumerator']
        elif kind == 'array':
            dimensions = []
            for child in self.child_dies(die):
                if child.tag != 'DW_TAG_subrange_type':
                    continue
                lower = self.value(child, 'DW_AT_lower_bound', 0)
                upper = self.value(child, 'DW_AT_upper_bound')
                count = self.value(child, 'DW_AT_count')
                if count is None and isinstance(lower, int) and isinstance(upper, int):
                    count = upper - lower + 1
                dimensions.append({'lower_bound': lower if isinstance(lower, int) else None,
                                   'upper_bound': upper if isinstance(upper, int) else None,
                                   'count': count if isinstance(count, int) else None})
            record['dimensions'] = dimensions
        elif kind == 'subroutine':
            record.update(self.signature(die))
        return record

    def recover(self):
        self.collect()
        for die in self.dies.values():
            _check(self.deadline)
            if die.tag in _TYPE_TAGS:
                if len(self.result['types']) >= self.maximum:
                    raise _LimitReached(f'Type count limit {self.maximum} reached; graph is partial.')
                self.result['types'].append(self.parse_type(die))
                self.type_ids.add(_die_id(die))
        by_address = {function.address: function for function in self.analysis.functions}
        by_name = {}
        for function in self.analysis.functions:
            by_name.setdefault(function.name, []).append(function)
        match_priority = {}
        for die in self.dies.values():
            _check(self.deadline)
            if die.tag != 'DW_TAG_subprogram':
                continue
            low_pc = self.value(die, 'DW_AT_low_pc')
            linkage = _text(self.value(die, 'DW_AT_linkage_name') or self.value(die, 'DW_AT_MIPS_linkage_name'))
            function = by_address.get(low_pc)
            priority = 2
            if function is None and low_pc is None and linkage:
                matches = by_name.get(linkage, [])
                function = matches[0] if len(matches) == 1 else None
                priority = 1
            if function is not None:
                if priority <= match_priority.get(function.id, 0):
                    continue
                previous = self.result['functions'].get(function.id, {})
                signature = self.signature(die)
                if signature['containing_type'] is None and 'DW_AT_specification' in die.attributes:
                    declaration = self.referenced_die(die, 'DW_AT_specification')
                    parent = self.parents.get(_die_id(declaration)) if declaration is not None else None
                    if parent is not None and parent.tag in _TYPE_TAGS:
                        signature['containing_type'] = _die_id(parent)
                self.result['functions'][function.id] = {**previous, **signature}
                match_priority[function.id] = priority


class _NameParser:
    """Small bounded Itanium type-name decoder; unsupported encodings stay raw."""
    _PRIMITIVES = {'v': 'void', 'b': 'bool', 'c': 'char', 'a': 'signed char',
                   'h': 'unsigned char', 's': 'short', 't': 'unsigned short',
                   'i': 'int', 'j': 'unsigned int', 'l': 'long', 'm': 'unsigned long',
                   'x': 'long long', 'y': 'unsigned long long', 'f': 'float', 'd': 'double'}

    def __init__(self, text):
        self.text, self.index, self.depth = text[:4096], 0, 0

    def parse(self):
        self.depth += 1
        if self.depth > 32 or self.index >= len(self.text):
            raise ValueError('unsupported mangled name')
        token = self.text[self.index]
        if token in self._PRIMITIVES:
            self.index += 1
            value = self._PRIMITIVES[token]
        elif token in 'PKVR':
            self.index += 1
            child = self.parse()
            value = {'P': child + '*', 'K': 'const ' + child, 'V': 'volatile ' + child,
                     'R': child + '&'}[token]
        elif token == 'N':
            self.index += 1
            entries = []
            while self.index < len(self.text) and self.text[self.index] != 'E':
                entries.append(self.parse())
                if len(entries) > 64:
                    raise ValueError('mangled name too deep')
            if self.index >= len(self.text):
                raise ValueError('unterminated nested name')
            self.index += 1
            value = '::'.join(entries)
        elif token.isdigit():
            start = self.index
            while self.index < len(self.text) and self.text[self.index].isdigit():
                self.index += 1
            length = int(self.text[start:self.index])
            if length > 4096 or self.index + length > len(self.text):
                raise ValueError('invalid source name')
            value = self.text[self.index:self.index + length]
            self.index += length
            if self.index < len(self.text) and self.text[self.index] == 'I':
                self.index += 1
                arguments = []
                while self.index < len(self.text) and self.text[self.index] != 'E':
                    arguments.append(self.parse())
                    if len(arguments) > 64:
                        raise ValueError('too many template arguments')
                if self.index >= len(self.text):
                    raise ValueError('unterminated template')
                self.index += 1
                value += '<' + ', '.join(arguments) + '>'
        else:
            raise ValueError('unsupported Itanium name encoding')
        self.depth -= 1
        return value


def _decode_name(value):
    try:
        parser = _NameParser(value)
        name = parser.parse()
        if parser.index == len(parser.text):
            return name
    except (ValueError, RecursionError):
        pass
    return value


class _ItaniumReader:
    def __init__(self, elf, result, analysis, deadline, maximum):
        self.elf, self.result, self.deadline, self.maximum = elf, result, deadline, maximum
        self.ptr = elf.elfclass // 8
        self.order = 'little' if elf.little_endian else 'big'
        self.symbols, self.addresses, self.relocations = {}, {}, {}
        self.segments = list(elf.iter_segments())
        self.function_names = {f.name: f.id for f in analysis.functions}
        self.function_addresses = {f.address: f.id for f in analysis.functions}
        self.by_name = {item.get('qualified_name'): item for item in result['types']
                        if item['kind'] in _AGGREGATES and item.get('qualified_name')}

    def read(self, address, size):
        if address is None or size < 0 or size > _MAX_DEBUG:
            return None
        for segment in self.segments:
            _check(self.deadline)
            if segment['p_type'] == 'PT_LOAD':
                start = int(segment['p_vaddr'])
                if start <= address and address + size <= start + int(segment['p_filesz']):
                    self.elf.stream.seek(int(segment['p_offset']) + address - start)
                    data = self.elf.stream.read(size)
                    return data if len(data) == size else None
        return None

    def integer(self, address, size=None, signed=False):
        data = self.read(address, size or self.ptr)
        return int.from_bytes(data, self.order, signed=signed) if data is not None else None

    def pointer(self, address):
        if address in self.relocations:
            return self.relocations[address]
        value = self.integer(address)
        if value is None:
            return None, None
        symbol = self.addresses.get(value)
        return value, symbol['name'] if symbol is not None else None

    def scan(self):
        count = 0
        for section in self.elf.iter_sections():
            _check(self.deadline)
            if section['sh_type'] not in ('SHT_SYMTAB', 'SHT_DYNSYM'):
                continue
            if section.num_symbols() > _MAX_SYMBOLS:
                raise _LimitReached('ELF symbol count limit reached.')
            for symbol in section.iter_symbols():
                _check(self.deadline)
                count += 1
                if count > _MAX_SYMBOLS:
                    raise _LimitReached('ELF symbol count limit reached.')
                name = symbol.name[:4096]
                record = {'name': name, 'address': int(symbol['st_value']),
                          'size': int(symbol['st_size']), 'section': symbol['st_shndx']}
                if name and (name not in self.symbols or record['section'] != 'SHN_UNDEF'):
                    self.symbols[name] = record
                if record['section'] != 'SHN_UNDEF' and record['address']:
                    self.addresses.setdefault(record['address'], record)
        count = 0
        # Only absolute-pointer and relative-pointer relocation types are used.
        # Instruction relocations and architecture-specific encodings are ignored.
        machine = self.elf['e_machine']
        absolute, relative = {
            'EM_X86_64': ({1, 6, 7}, {8}), 'EM_386': ({1, 6, 7}, {8}),
            'EM_AARCH64': ({257, 1025, 1026}, {1027}), 'EM_ARM': ({2, 21, 22}, {23}),
        }.get(machine, (set(), set()))
        for section in self.elf.iter_sections():
            _check(self.deadline)
            if section['sh_type'] not in ('SHT_RELA', 'SHT_REL'):
                continue
            if section.num_relocations() > _MAX_SYMBOLS:
                raise _LimitReached('ELF relocation count limit reached.')
            table = self.elf.get_section(section['sh_link'])
            for relocation in section.iter_relocations():
                _check(self.deadline)
                count += 1
                if count > _MAX_SYMBOLS:
                    raise _LimitReached('ELF relocation count limit reached.')
                offset, kind = int(relocation['r_offset']), relocation['r_info_type']
                if kind not in absolute | relative:
                    continue
                addend = int(relocation['r_addend']) if relocation.is_RELA() else self.integer(offset)
                if addend is None:
                    continue
                if kind in relative:
                    symbol = self.addresses.get(addend)
                    self.relocations[offset] = (addend, symbol['name'] if symbol else None)
                else:
                    symbol = table.get_symbol(relocation['r_info_sym'])
                    self.relocations[offset] = (int(symbol['st_value']) + addend, symbol.name[:4096])

    def record(self, suffix):
        name = _decode_name(suffix)
        if name in self.by_name:
            return self.by_name[name]
        if len(self.result['types']) >= self.maximum:
            raise _LimitReached(f'Type count limit {self.maximum} reached; graph is partial.')
        record = {'id': 'itanium:' + suffix, 'kind': 'class',
                  'name': name.split('::')[-1], 'qualified_name': name,
                  'byte_size': None, 'definition_available': False,
                  'status': 'ABI_EVIDENCE', 'members': [], 'bases': [],
                  'methods': [], 'vtables': [], 'evidence': []}
        self.result['types'].append(record)
        self.by_name[name] = record
        return record

    def symbol_evidence(self, symbol):
        return {'id': f"elf:symbol:{symbol['name']}:{symbol['address']:x}",
                'source': 'ITANIUM_RTTI', 'symbol': symbol['name'], 'address': symbol['address']}

    def base(self, address, offset, virtual, access, evidence):
        _, name = self.pointer(address)
        if not name or not name.startswith('_ZTI'):
            return None
        target = self.record(name[4:])
        return {'type_id': target['id'], 'offset_bytes': None if virtual else offset,
                'virtual': virtual, 'virtual_offset_index': offset if virtual else None,
                'accessibility': access, 'evidence': [evidence], 'status': 'ABI_EVIDENCE'}

    def recover(self):
        self.scan()
        type_symbols = [s for n, s in self.symbols.items()
                        if n.startswith('_ZTI') and s['section'] != 'SHN_UNDEF']
        for symbol in type_symbols:
            _check(self.deadline)
            suffix = symbol['name'][4:]
            if len(suffix) == 1 and suffix in _NameParser._PRIMITIVES:
                continue
            _, abi_vtable = self.pointer(symbol['address'])
            abi_kind = _decode_name(abi_vtable[4:]) if abi_vtable and abi_vtable.startswith('_ZTV') else None
            if abi_kind not in {'__cxxabiv1::__class_type_info', '__cxxabiv1::__si_class_type_info',
                                '__cxxabiv1::__vmi_class_type_info'}:
                if len(self.result['diagnostics']) < 100:
                    self.result['diagnostics'].append(f'Unvalidated RTTI symbol {symbol["name"]} skipped; ABI vptr is unknown.')
                continue
            record = self.record(suffix)
            evidence = self.symbol_evidence(symbol)
            record['evidence'].append(evidence)
            bases = []
            if abi_kind == '__cxxabiv1::__si_class_type_info':
                base = self.base(symbol['address'] + self.ptr * 2, 0, False, 'public', evidence)
                if base:
                    bases.append(base)
            elif abi_kind == '__cxxabiv1::__vmi_class_type_info':
                count = self.integer(symbol['address'] + self.ptr * 2 + 4, 4)
                if count is not None and count <= 4096:
                    for index in range(count):
                        _check(self.deadline)
                        location = symbol['address'] + self.ptr * 2 + 8 + index * self.ptr * 2
                        flags = self.integer(location + self.ptr, signed=True)
                        if flags is None:
                            break
                        base = self.base(location, flags >> 8, bool(flags & 1),
                                         'public' if flags & 2 else 'nonpublic', evidence)
                        if base:
                            bases.append(base)
                elif count is not None:
                    self.result['diagnostics'].append(f'RTTI base count rejected for {symbol["name"]}.')
            if record['status'] == 'ABI_EVIDENCE':
                record['bases'] = bases
        for name, symbol in list(self.symbols.items()):
            _check(self.deadline)
            if not name.startswith('_ZTV') or symbol['section'] == 'SHN_UNDEF':
                continue
            suffix = name[4:]
            if '__cxxabiv1' in _decode_name(suffix):
                continue
            rtti_index = None
            # Virtual-base offset entries may precede offset_to_top/typeinfo;
            # the ELF vtable symbol is not always its address point minus 2.
            for prefix_index in range(1, min(128, symbol['size'] // self.ptr)):
                _, typeinfo = self.pointer(symbol['address'] + prefix_index * self.ptr)
                if typeinfo == '_ZTI' + suffix:
                    rtti_index = prefix_index
                    break
            if rtti_index is None:
                if len(self.result['diagnostics']) < 100:
                    self.result['diagnostics'].append(f'Unvalidated vtable symbol {name} skipped; typeinfo prefix is unknown.')
                continue
            record = self.record(suffix)
            evidence = self.symbol_evidence(symbol)
            count = min(4096, max(0, symbol['size'] // self.ptr - rtti_index - 1))
            entries = []
            for index in range(count):
                _check(self.deadline)
                address, target = self.pointer(symbol['address'] + self.ptr * (index + rtti_index + 1))
                if target and target.startswith('_ZTI'):
                    break  # A secondary vtable prefix, not a method pointer.
                if address is not None and address >= 1 << (self.ptr * 8 - 1):
                    break
                if target is None and (address is None or not address):
                    continue
                entries.append({'slot_index': index, 'address': address, 'symbol': target,
                                'function_id': self.function_names.get(target) or self.function_addresses.get(address),
                                'evidence': [evidence]})
            record['vtables'].append({'address': symbol['address'], 'symbol': name,
                                      'address_point': symbol['address'] + (rtti_index + 1) * self.ptr,
                                      'prefix_offset_slots': rtti_index - 1,
                                      'offset_to_top': self.integer(symbol['address'] + (rtti_index - 1) * self.ptr, signed=True),
                                      'entries': entries, 'evidence': [evidence]})
            record['evidence'].append(evidence)


def _memory_hypotheses(analysis, result, deadline):
    if analysis.architecture != 'x86_64' or analysis.metadata.get('abi') != 'sysv-amd64':
        return
    pattern = re.compile(r'(?:(?<![\w])(BYTE|WORD|DWORD|QWORD|TBYTE|XMMWORD|YMMWORD|ZMMWORD)\s+PTR\s+)?'
                         r'\[rdi(?:\s*([+-])\s*(0x[0-9a-f]+|[0-9]+))?\]', re.I)
    widths = {'BYTE': 1, 'WORD': 2, 'DWORD': 4, 'QWORD': 8, 'TBYTE': 10,
              'XMMWORD': 16, 'YMMWORD': 32, 'ZMMWORD': 64}
    for function in analysis.functions:
        _check(deadline)
        facts = []
        for instruction in function.instructions[:100000]:
            _check(deadline)
            if instruction.mnemonic.lower() in ('lea', 'nop'):
                continue
            for match in pattern.finditer(instruction.operands):
                literal = match.group(3) or '0'
                offset = int(literal, 16 if literal.lower().startswith('0x') else 10)
                if match.group(2) == '-':
                    offset = -offset
                facts.append({'base_register': 'rdi', 'base_parameter_index': None, 'offset_bytes': offset,
                              'width_bytes': widths.get((match.group(1) or '').upper()),
                              'status': 'HYPOTHESIS',
                              'basis': 'Observed register-relative memory access; register provenance, receiver identity and field type are unknown.',
                              'evidence': [{'id': f'instruction:{function.id}:{instruction.address:x}',
                                            'source': 'DISASSEMBLY', 'address': instruction.address}]})
                if len(facts) >= 4096:
                    break
            if len(facts) >= 4096:
                break
        if facts:
            result['functions'].setdefault(function.id, {})['memory_layout_hypotheses'] = facts
    if any(value.get('memory_layout_hypotheses') for value in result['functions'].values()):
        result['sources'].append('MEMORY_ACCESSES')


def recover_types(path: Path, analysis: Analysis, *, timeout=30, max_types=20000) -> dict:
    """Recover a JSON type graph from metadata and conservative ABI evidence.

    Timeout and count exhaustion return a partial graph with diagnostics. Bad
    configuration raises ValueError; absent metadata/dependencies is nonfatal.
    Only ELF is currently supported for metadata recovery.
    """
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not math.isfinite(timeout) or timeout <= 0:
        raise ValueError('Type timeout must be positive and finite.')
    if isinstance(max_types, bool) or not isinstance(max_types, int) or not 1 <= max_types <= 100000:
        raise ValueError('max_types must be an integer between 1 and 100000.')
    deadline = time.monotonic() + timeout
    result = {'schema_version': 1, 'types': [], 'functions': {}, 'diagnostics': [], 'sources': []}
    try:
        _check(deadline)
        _memory_hypotheses(analysis, result, deadline)
        if analysis.format != 'ELF':
            result['diagnostics'].append('Metadata type recovery currently supports ELF/DWARF and Itanium RTTI only.')
            return result
        loader = _load_elftools()
        if loader is None:
            result['diagnostics'].append('Optional dependency pyelftools is unavailable; install gamedecomp[types].')
            return result
        path = Path(path)
        if not path.is_file() or path.stat().st_size > _MAX_INPUT:
            result['diagnostics'].append('Type input must be a regular ELF file of at most 256 MiB.')
            return result
        with path.open('rb') as handle:
            _check(deadline)
            elf = loader(handle)
            if elf.num_sections() > 65536 or elf.num_segments() > 4096:
                raise _LimitReached('ELF section or segment count limit reached.')
            debug_total, debug_safe, metadata_entries = 0, True, 0
            for section in elf.iter_sections():
                _check(deadline)
                if section['sh_type'] in ('SHT_SYMTAB', 'SHT_DYNSYM', 'SHT_RELA', 'SHT_REL'):
                    entry_size = int(section['sh_entsize'])
                    section_size = int(section['sh_size'])
                    if entry_size <= 0 and section_size:
                        raise _LimitReached('Invalid ELF metadata entry size rejected.')
                    metadata_entries += section_size // max(entry_size, 1)
                    if metadata_entries > _MAX_SYMBOLS * 2:
                        raise _LimitReached('ELF metadata entry count limit reached.')
                if section.name.startswith(('.debug_', '.zdebug_')) or section.name in ('.eh_frame', '.gnu_debugaltlink'):
                    size = int(section['sh_size'])
                    debug_total += size
                    if size > _MAX_DEBUG or section['sh_flags'] & 0x800 or section.name.startswith('.zdebug_'):
                        debug_safe = False
            if debug_total > _MAX_DEBUG * 2:
                debug_safe = False
            if elf.get_section_by_name('.debug_info') is not None and debug_safe:
                result['sources'].append('DWARF')
                try:
                    _DwarfReader(elf, result, analysis, deadline, max_types).recover()
                except _LimitReached:
                    raise
                except Exception as error:
                    result['diagnostics'].append(f'DWARF metadata could not be fully decoded: {type(error).__name__}: {str(error)[:240]}')
            elif not debug_safe:
                result['diagnostics'].append('Compressed or oversized DWARF sections skipped to bound resource usage.')
            before = sum(len(item['evidence']) for item in result['types'])
            _ItaniumReader(elf, result, analysis, deadline, max_types).recover()
            if sum(len(item['evidence']) for item in result['types']) > before:
                result['sources'].append('ITANIUM_RTTI')
            if not result['types']:
                result['diagnostics'].append('No supported DWARF declarations or exported Itanium RTTI/vtable symbols found.')
    except _LimitReached as error:
        result['diagnostics'].append(str(error))
    except Exception as error:
        result['diagnostics'].append(f'ELF type metadata could not be decoded: {type(error).__name__}: {str(error)[:240]}')
    return result


def _comment(value) -> str:
    # Binary metadata is untrusted. Keep it on one comment line, even for names
    # containing source delimiters or control characters.
    return ''.join(char if char.isprintable() else ' ' for char in str(value))[:4096].replace('*/', '* /').replace('\\', '<backslash>')


def render_types_header(result: dict) -> str:
    """Render valid C++ forward declarations plus an evidence/layout summary.

    Forward declarations deliberately avoid inventing definitions or object
    sizes. Documented members/signatures remain comments; the JSON is canonical.
    """
    records = result.get('types', [])
    by_id = {item['id']: item for item in records}

    def type_name(identifier, depth=0):
        if identifier is None:
            return 'void / unknown'
        item = by_id.get(identifier)
        if item is None or depth >= 16:
            return identifier
        name = item.get('qualified_name') or item.get('name')
        if name:
            return name
        kind = item['kind']
        target = type_name(item.get('target_type'), depth + 1)
        if kind in ('pointer', 'reference', 'rvalue_reference'):
            return target + {'pointer': '*', 'reference': '&', 'rvalue_reference': '&&'}[kind]
        if kind in ('const', 'volatile', 'restrict', 'atomic'):
            return kind + ' ' + target
        if kind == 'array':
            return target + ''.join(f'[{d["count"] if d.get("count") is not None else "?"}]'
                                    for d in item.get('dimensions', []))
        return f'{kind} ({identifier})'

    lines = ['// GameDecomp evidence summary; not an ABI-compatible reconstructed definition.',
             '// Original layout is documented where metadata exists; unknown layout remains unknown.',
             '// Declarations below are opaque. See types.json for canonical evidence and type references.',
             '#ifndef GAMEDECOMP_RECOVERED_TYPES_HPP', '#define GAMEDECOMP_RECOVERED_TYPES_HPP',
             'namespace gamedecomp_recovered {']
    used = set()
    keywords = set(('alignas alignof and and_eq asm auto bitand bitor bool break case catch char '
                    'char8_t char16_t char32_t class compl concept const consteval constexpr '
                    'constinit const_cast continue co_await co_return co_yield decltype default '
                    'delete do double dynamic_cast else enum explicit export extern false float '
                    'for friend goto if inline int long mutable namespace new noexcept not not_eq '
                    'nullptr operator or or_eq private protected public register reinterpret_cast '
                    'requires return short signed sizeof static static_assert static_cast struct '
                    'switch template this thread_local throw true try typedef typeid typename union '
                    'unsigned using virtual void volatile wchar_t while xor xor_eq').split())
    for item in records:
        if item['kind'] not in _AGGREGATES | {'enum'}:
            continue
        name = item.get('qualified_name') or item.get('name') or item['id']
        local = (item.get('name') or item['id']).split('::')[-1]
        safe = re.sub(r'[^A-Za-z0-9_]', '_', local)
        if not safe or safe[0].isdigit():
            safe = 'type_' + safe
        if safe in used or safe in keywords:
            safe += '_' + re.sub(r'[^A-Za-z0-9_]', '_', item['id'])
        while safe in used or safe in keywords:
            safe += '_'
        used.add(safe)
        lines.extend(['', f'// {_comment(name)}; status {_comment(item.get("status"))}; '
                      f'byte size {_comment(item.get("byte_size"))}; id {_comment(item["id"])}'])
        if item['kind'] != 'enum':
            lines.append(f'{item["kind"]} {safe};')
        for base in item.get('bases', []):
            lines.append(f'// base: {_comment(type_name(base.get("type_id")))}; '
                         f'{_comment(base.get("accessibility"))}; virtual {bool(base.get("virtual"))}; '
                         f'offset {_comment(base.get("offset_bytes"))}')
        for member in item.get('members', []):
            lines.append(f'// member: {_comment(type_name(member.get("type_id")))} '
                         f'{_comment(member.get("name"))}; offset {_comment(member.get("offset_bytes"))}; '
                         f'{_comment(member.get("accessibility"))}')
        for method in item.get('methods', []):
            params = ', '.join(type_name(p.get('type_id')) + ' ' + (p.get('name') or '?')
                               for p in method.get('parameters', []))
            lines.append(f'// method: {"virtual " if method.get("virtual") else ""}'
                         f'{_comment(type_name(method.get("return_type")))} '
                         f'{_comment(method.get("name"))}({_comment(params)})')
        for enumerator in item.get('enumerators', []):
            lines.append(f'// enumerator: {_comment(enumerator.get("name"))} = {_comment(enumerator.get("value"))}')
        for vtable in item.get('vtables', []):
            lines.append(f'// vtable: {_comment(vtable.get("symbol"))}; {len(vtable.get("entries", []))} observed entries')
    lines.extend(['}', '#endif', ''])
    return '\n'.join(lines)
