"""Observed cross-references survive optimization and stripped symbols."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


@unittest.skipUnless(os.environ.get('GAMEDECOMP_TEST_GHIDRA_HOME') and
                     all(shutil.which(tool) for tool in ('gcc', 'nm', 'strip')),
                     'requires explicitly configured Ghidra and native build tools')
class GhidraReferenceTests(unittest.TestCase):
    def analyze_fixture(self, *, stripped, got, many=False):
        from gamedecomp.backends.ghidra import analyze
        root = Path(self.temp.name)
        source = root / 'fixture.c'
        source.write_text('#include <stdio.h>\n'
            '__attribute__((used)) static const char unused[]="UNREFERENCED_PRIVATE_LITERAL";\n'
            '__attribute__((noinline)) int load_asset(int code) {\n'
            ' return puts(code ? "asset://textures/player.dds" : "asset://audio/hit.ogg"); }\n'
            '__attribute__((noinline)) int connect_lobby(void) { return puts("network://lobby/connect"); }\n'
            '__attribute__((noinline)) int long_message(void) { return puts("' + 'R' * 1500 + '"); }\n'
            'int main(int argc,char **argv) { return load_asset(argc)+connect_lobby()+long_message(); }\n')
        if many:
            with source.open('a') as stream:
                stream.write('__attribute__((noinline)) int many_assets(void) { int total=0;\n')
                for index in range(300):
                    stream.write(f'total += puts("asset://texture/{index:03d}");\n')
                stream.write('return total; }\n')
        binary = root / 'fixture'
        flags = ['-fPIE', '-pie', '-fno-plt'] if got else ['-fno-pie', '-no-pie']
        subprocess.run(['gcc', '-O2', '-fno-builtin', *flags, str(source), '-o', str(binary)],
                       check=True, capture_output=True, timeout=30)
        symbols = subprocess.check_output(['nm', '--format=posix', '--defined-only', str(binary)],
                                          text=True, timeout=30)
        addresses = {row[0]: int(row[2], 16) for line in symbols.splitlines()
                     if (row := line.split()) and row[0] in ('load_asset', 'connect_lobby', 'long_message', 'many_assets')}
        if stripped:
            subprocess.run(['strip', '--strip-all', str(binary)], check=True, capture_output=True, timeout=30)
        analysis = analyze(binary, ghidra_home=Path(os.environ['GAMEDECOMP_TEST_GHIDRA_HOME']), timeout=120)
        if stripped:
            selected = {name: next(f for f in analysis.functions if f.address == address)
                        for name, address in addresses.items()}
        else:
            selected = {name: next(f for f in analysis.functions if f.name == name) for name in addresses}
        return analysis, selected

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)

    def assert_references(self, analysis, function):
        from gamedecomp.evidence import function_context, known_evidence_ids
        refs = function.metadata.get('binary_references', [])
        self.assertTrue(refs, 'No structured string or external API references exported')
        summary = function.metadata['binary_reference_summary']
        self.assertFalse(summary['scan_truncated'])
        origins = {instruction.address for instruction in function.instructions}
        self.assertTrue(all(ref['from_address'] in origins for ref in refs))
        strings = [ref['value'] for ref in refs if ref['kind'] == 'string_reference']
        self.assertEqual(set(strings), {'asset://textures/player.dds', 'asset://audio/hit.ogg'})
        imports = [ref for ref in refs if ref['kind'] == 'external_function_reference']
        self.assertTrue(any(ref['target_name'] == 'puts' for ref in imports), imports)
        self.assertNotIn('UNREFERENCED_PRIVATE_LITERAL', str(refs))
        self.assertNotIn('network://lobby/connect', str(refs))
        context = function_context(function, analysis.binary_hash, {})
        facts = [fact for fact in context['evidence'] if fact['kind'] in
                 ('string_reference', 'external_function_reference')]
        self.assertEqual(len(facts), len(refs))
        self.assertTrue(all(fact['id'] in known_evidence_ids(context) for fact in facts))
        self.assertEqual(function.metadata['semantic_status'], 'UNKNOWN')

    def test_stripped_optimized_references_remain_per_function_and_citable(self):
        analysis, functions = self.analyze_fixture(stripped=True, got=False)
        self.assert_references(analysis, functions['load_asset'])

    def test_pie_got_imports_and_long_literals_have_explicit_provenance(self):
        analysis, functions = self.analyze_fixture(stripped=False, got=True)
        self.assert_references(analysis, functions['load_asset'])
        refs = functions['long_message'].metadata['binary_references']
        literal = next(ref for ref in refs if ref['kind'] == 'string_reference')
        self.assertTrue(literal['text_truncated'])
        self.assertEqual(literal['original_text_bytes'], 1500)
        self.assertLessEqual(len(literal['value'].encode()), 1024)
        self.assertTrue(set(literal['value']) == {'R'})

    def test_large_asset_reference_set_has_bounded_export_and_explicit_omissions(self):
        import json
        analysis, functions = self.analyze_fixture(stripped=False, got=False, many=True)
        function = functions['many_assets']
        refs = function.metadata['binary_references']
        summary = function.metadata['binary_reference_summary']
        self.assertGreater(len(refs), 0)
        self.assertLessEqual(len(refs), 256)
        self.assertLessEqual(len(json.dumps(refs, separators=(',', ':')).encode()), 65536)
        self.assertTrue(summary['scan_truncated'])
        self.assertGreater(summary['omitted'], 0)
        self.assertEqual(summary['emitted'], len(refs))
