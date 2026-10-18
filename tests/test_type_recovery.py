"""Type recovery reads original C++ fixtures, without executing the binary."""
import importlib.util
import json
import math
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

from gamedecomp.models import Analysis, Function, Instruction

try:
    from gamedecomp.type_recovery import recover_types, render_types_header
except ImportError:
    recover_types = render_types_header = None


@unittest.skipUnless(shutil.which('g++') and importlib.util.find_spec('elftools'),
                     'C++ and optional pyelftools required')
class TypeRecoveryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix='type recovery fixture ')
        cls.root = Path(cls.temporary.name)
        fixture = Path(__file__).parent / 'fixtures' / 'types.cpp'
        cls.debug = cls.root / 'debug.so'
        cls.stripped = cls.root / 'stripped.so'
        subprocess.run(['g++', '-std=c++17', '-g', '-O0', '-fPIC', '-shared',
                        str(fixture), '-o', str(cls.debug)], check=True, capture_output=True)
        subprocess.run(['g++', '-std=c++17', '-O2', '-s', '-fPIC', '-shared',
                        str(fixture), '-o', str(cls.stripped)], check=True, capture_output=True)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def recover(self, path=None, **kwargs):
        self.assertTrue(callable(recover_types), 'type recovery must be implemented')
        artifact = Analysis('', 'ELF', 'x86_64', 'fixture')
        return recover_types(path or self.debug, artifact, **kwargs)

    def test_dwarf_graph_recovers_recursive_members_and_template_names(self):
        result = self.recover()
        types = {item['qualified_name']: item for item in result['types'] if item.get('qualified_name')}
        self.assertEqual(result['schema_version'], 1)
        node = types['Game::Node']
        self.assertEqual(node['kind'], 'struct')
        self.assertEqual(node['status'], 'METADATA')
        self.assertEqual(node['byte_size'], 16)
        members = {item['name']: item for item in node['members']}
        self.assertEqual(members['value']['offset_bytes'], 0)
        self.assertEqual(members['next']['offset_bytes'], 8)
        by_id = {item['id']: item for item in result['types']}
        pointer = by_id[members['next']['type_id']]
        self.assertEqual(pointer['kind'], 'pointer')
        self.assertEqual(pointer['target_type'], node['id'])
        self.assertIn('Game::Holder<int>', types)
        self.assertEqual(types['Game::Scalar']['kind'], 'union')
        enum = types['Game::Kind']
        self.assertEqual(enum['enumerators'], [{'name': 'Actor', 'value': 3}, {'name': 'Camera', 'value': 9}])
        self.assertTrue(any(item['kind'] == 'array' and item['dimensions'][0]['count'] == 3
                            for item in result['types']))
        flags = {item['name']: item for item in types['Game::Flags']['members']}
        self.assertEqual(flags['bits']['bit_size'], 3)
        self.assertEqual(flags['code']['bit_size'], 5)
        self.assertTrue(any(item['kind'] == 'const' for item in result['types']))
        self.assertTrue(any(item['kind'] == 'volatile' for item in result['types']))
        json.dumps(result, allow_nan=False)

    def test_dwarf_inheritance_methods_and_unknown_virtual_base_offsets(self):
        result = self.recover()
        types = {item['qualified_name']: item for item in result['types'] if item.get('qualified_name')}
        actor = types['Game::Actor']
        moving = types['Game::Moving']
        self.assertEqual(moving['bases'][0]['type_id'], actor['id'])
        self.assertEqual(moving['bases'][0]['offset_bytes'], 0)
        self.assertEqual(moving['bases'][0]['accessibility'], 'public')
        self.assertTrue(any(method['name'] == 'update' and method['virtual'] for method in actor['methods']))
        virtual = types['Game::VirtualEntity']['bases'][0]
        self.assertTrue(virtual['virtual'])
        self.assertIsNone(virtual['offset_bytes'])
        self.assertTrue(types['Game::VirtualEntity']['vtables'])
        self.assertTrue(virtual.get('offset_expression'))

    def test_function_signatures_attach_by_address_and_preserve_receiver_type(self):
        from elftools.elf.elffile import ELFFile
        with self.debug.open('rb') as handle:
            symbols = ELFFile(handle).get_section_by_name('.symtab')
            symbol = next(item for item in symbols.iter_symbols()
                          if item.name == '_ZNK4Game5Actor6updateEi')
        function = Function('function:actor', symbol.name, int(symbol['st_value']))
        analysis = Analysis('', 'ELF', 'x86_64', 'fixture', functions=[function])
        result = recover_types(self.debug, analysis)
        signature = result['functions'][function.id]
        self.assertTrue(signature['return_type'])
        self.assertTrue(signature['receiver_type'])
        self.assertEqual([item['name'] for item in signature['parameters']], ['this', 'ticks'])
        self.assertEqual(signature['status'], 'METADATA')
        self.assertEqual(function.metadata, {}, 'type recovery must not mutate analysis')

    def test_abstract_namesake_cannot_overwrite_concrete_address_signature(self):
        from gamedecomp.backends.native import analyze
        first, second, binary = self.root / 'a.c', self.root / 'b.c', self.root / 'namesakes.so'
        first.write_text('static __attribute__((noinline)) int common(int x){return x+7;} '
                         'int use_a(int x){return common(x);}')
        second.write_text('static inline double common(double x){return x*2.0;} '
                          'double use_b(double x){return common(x);}')
        subprocess.run(['gcc', '-O2', '-g', '-fPIC', '-shared', str(first), str(second), '-o', str(binary)],
                       check=True, capture_output=True, timeout=20)
        analysis = analyze(binary)
        function = next(item for item in analysis.functions if item.name == 'common')
        result = recover_types(binary, analysis)
        signature = result['functions'][function.id]
        by_id = {item['id']: item for item in result['types']}
        self.assertEqual(by_id[signature['return_type']]['name'], 'int')
        self.assertEqual(signature['parameters'][0]['name'], 'x')

    def test_stripped_itanium_rtti_recovers_real_base_relationships(self):
        result = self.recover(self.stripped)
        types = {item['qualified_name']: item for item in result['types'] if item.get('qualified_name')}
        self.assertIn('Game::Entity', types)
        entity = types['Game::Entity']
        self.assertEqual(entity['status'], 'ABI_EVIDENCE')
        self.assertEqual(entity['bases'][0]['type_id'], types['Game::Moving']['id'])
        self.assertEqual(entity['bases'][1]['type_id'], types['Game::Drawable']['id'])
        self.assertEqual(entity['bases'][1]['offset_bytes'], 16)
        self.assertTrue(entity['vtables'])
        self.assertTrue(entity['vtables'][0]['entries'])
        self.assertFalse(entity['definition_available'])
        virtual = types['Game::VirtualEntity']['bases'][0]
        self.assertTrue(virtual['virtual'])
        self.assertIsNone(virtual['offset_bytes'])

    def test_header_is_compilable_summary_with_explicit_layout_limits(self):
        text = render_types_header(self.recover())
        self.assertIn('class Actor', text)
        self.assertIn('Game::Holder<int>', text)
        self.assertIn('offset 8', text)
        self.assertIn('layout', text.lower())
        header = self.root / 'types.hpp'
        header.write_text(text)
        subprocess.run(['g++', '-std=c++17', '-Wall', '-Wextra', '-Werror',
                        '-x', 'c++', '-fsyntax-only', str(header)], check=True, capture_output=True)

    def test_limits_dependency_failure_and_invalid_input_are_explicit(self):
        for timeout in (0, -1, math.inf, math.nan, True):
            with self.subTest(timeout=timeout), self.assertRaises(ValueError):
                self.recover(timeout=timeout)
        result = self.recover(max_types=2)
        self.assertLessEqual(len(result['types']), 2)
        self.assertTrue(result['diagnostics'])
        with mock.patch('gamedecomp.type_recovery._load_elftools', return_value=None):
            missing = self.recover()
        self.assertFalse(missing['types'])
        self.assertIn('pyelftools', ' '.join(missing['diagnostics']))
        malformed = self.root / 'bad.elf'
        malformed.write_bytes(b'\x7fELF' + b'\xff' * 60)
        invalid = self.recover(malformed)
        self.assertFalse(invalid['types'])
        self.assertTrue(invalid['diagnostics'])

    def test_shared_deadline_stops_before_parsing(self):
        self.assertTrue(callable(recover_types))
        with mock.patch('gamedecomp.type_recovery.time.monotonic', side_effect=[0.0, 2.0]):
            result = self.recover(timeout=1)
        self.assertTrue(any('deadline' in item.lower() for item in result['diagnostics']))

    def test_symbol_prefixes_alone_do_not_attest_classes(self):
        source = self.root / 'fake-rtti.cpp'
        source.write_text('extern "C" { unsigned long _ZTI4Fake[3] = {1, 2, 3}; '
                          'unsigned long _ZTV4Fake[3] = {0, 0, 1}; }')
        path = self.root / 'fake-rtti.so'
        subprocess.run(['g++', '-fPIC', '-shared', str(source), '-o', str(path)],
                       check=True, capture_output=True)
        result = self.recover(path)
        self.assertFalse(result['types'])
        self.assertTrue(any('unvalidated' in message.lower() for message in result['diagnostics']))

    def test_header_sanitizes_keywords_and_comment_continuations(self):
        value = {'types': [{'id': 'one', 'kind': 'class', 'name': 'delete',
                            'qualified_name': 'evil*/name\\', 'status': 'METADATA',
                            'byte_size': 1},
                           {'id': 'two', 'kind': 'struct', 'name': 'a-b',
                            'qualified_name': 'a-b', 'status': 'METADATA', 'byte_size': 1},
                           {'id': 'three', 'kind': 'struct', 'name': 'a_b',
                            'qualified_name': 'a_b', 'status': 'METADATA', 'byte_size': 1}]}
        text = render_types_header(value)
        path = self.root / 'untrusted-names.hpp'
        path.write_text(text)
        subprocess.run(['g++', '-std=c++17', '-Wall', '-Wextra', '-Werror',
                        '-x', 'c++', '-fsyntax-only', str(path)], check=True, capture_output=True)


class MemoryTypeHypothesesTests(unittest.TestCase):
    def test_register_access_does_not_claim_argument_provenance_after_clobber(self):
        analysis = Analysis('', 'PE', 'x86_64', 'fixture', functions=[Function('f', 'f', 1, instructions=[
            Instruction(1, 'mov', 'rdi,rax'),
            Instruction(4, 'mov', 'eax,DWORD PTR [rdi+0x8]'),
        ])], metadata={'abi': 'sysv-amd64'})
        result = recover_types(Path('/unused'), analysis)
        fact = result['functions']['f']['memory_layout_hypotheses'][0]
        self.assertIsNone(fact.get('base_parameter_index'))
        self.assertEqual(fact.get('base_register'), 'rdi')

    def test_extended_memory_qualifiers_do_not_match_shorter_suffixes(self):
        analysis = Analysis('', 'PE', 'x86_64', 'fixture', functions=[Function('f', 'f', 1, instructions=[
            Instruction(1, 'vmovdqu64', 'zmm0,ZMMWORD PTR [rdi+0x40]'),
            Instruction(5, 'fld', 'TBYTE PTR [rdi+0x20]'),
        ])], metadata={'abi': 'sysv-amd64'})
        result = recover_types(Path('/unused'), analysis)
        facts = result['functions']['f']['memory_layout_hypotheses']
        self.assertEqual([fact['width_bytes'] for fact in facts], [64, 10])

    def test_memory_offsets_are_hypotheses_not_class_proofs(self):
        self.assertTrue(callable(recover_types))
        function = Function('f', 'anonymous', 1, instructions=[
            Instruction(1, 'mov', 'eax,DWORD PTR [rdi+0x8]'),
            Instruction(4, 'lea', 'rax,[rdi+0x10]'),
        ])
        analysis = Analysis('', 'PE', 'x86_64', 'fixture', functions=[function],
                            metadata={'abi': 'sysv-amd64'})
        result = recover_types(Path('/does-not-exist'), analysis)
        facts = result['functions']['f']['memory_layout_hypotheses']
        self.assertEqual(len(facts), 1)
        self.assertEqual(facts[0]['offset_bytes'], 8)
        self.assertEqual(facts[0]['width_bytes'], 4)
        self.assertEqual(facts[0]['status'], 'HYPOTHESIS')
        self.assertFalse(result['types'])
