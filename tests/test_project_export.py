import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from gamedecomp.project_export import export_project


def function(name, source, *, preamble=None, status='COMPILED', calls=None):
    metadata = {'language': 'c'}
    if preamble is not None:
        metadata.update(compile_preamble=preamble, compile_preamble_status='AVAILABLE')
    return {'id': name, 'name': name, 'address': 1, 'source': source,
            'metadata': metadata, 'compilation': {'status': status}, 'calls': calls or []}


class ProjectExportTests(unittest.TestCase):
    def test_exports_only_compiled_baseline_with_hashes(self):
        source = 'uint32_t recovered(uint32_t value) { return value + 1; }\n'
        report = {'backend': 'native', 'functions': [function('recovered', source),
                  function('missing', None, status='UNKNOWN')], 'input': {'sha256': 'binaryhash'}}
        with tempfile.TemporaryDirectory() as directory:
            manifest = export_project(report, Path(directory))
            project = Path(directory) / 'project'
            self.assertFalse(manifest['complete'])
            self.assertEqual(manifest['summary']['exported_units'], 1)
            self.assertEqual(manifest['summary']['excluded_functions'], 1)
            record = manifest['units'][0]
            self.assertEqual(record['source_sha256'], hashlib.sha256(source.encode()).hexdigest())
            self.assertTrue((project / record['path']).read_text().endswith(source))
            self.assertEqual(manifest, json.loads((project / 'manifest.json').read_text()))
            self.assertIn('OBJECT', (project / 'CMakeLists.txt').read_text())
            self.assertIn('asset', (project / 'README.md').read_text())

    def test_preserves_ghidra_context_and_lists_external_declarations(self):
        context = '#include <stdbool.h>\n#undef bool\ntypedef unsigned char bool;\nextern int engine_score;\nextern int missing_helper(int);\n'
        source = 'int recovered(int value) { return missing_helper(value) + engine_score; }\n'
        report = {'backend': 'ghidra', 'functions': [function('one', source, preamble=context)]}
        with tempfile.TemporaryDirectory() as directory:
            manifest = export_project(report, Path(directory))
            record = manifest['units'][0]
            text = (Path(directory) / 'project' / record['path']).read_text()
            self.assertIn(context + '\n\n' + source, text)
            self.assertEqual(record['preamble_sha256'], hashlib.sha256(context.encode()).hexdigest())
            self.assertTrue(any('engine_score' in d['declaration'] for d in manifest['dependencies']))
            self.assertFalse(manifest['complete'])
            self.assertNotIn('engine_score =', text)

    def test_duplicate_symbols_are_excluded_without_renaming(self):
        report = {'backend': 'ghidra', 'functions': [function('a', 'int same(void) { return 1; }'),
                  function('b', 'int same(void) { return 2; }'), function('c', 'int unique(void) { return 3; }')]}
        with tempfile.TemporaryDirectory() as directory:
            manifest = export_project(report, Path(directory))
            self.assertEqual([x['symbol'] for x in manifest['units']], ['unique'])
            self.assertEqual(len(manifest['excluded']), 2)
            self.assertTrue(all('collision' in x['reason'] for x in manifest['excluded']))

    def test_unavailable_context_candidate_and_unsupported_language_are_not_exported(self):
        candidate_only = function('candidate', None, status='UNKNOWN')
        candidate_only['candidate'] = {'source': 'int fake(void) { return 0; }'}
        invalid = function('bad', 'int bad(void) { return 0; }', preamble='x\x00')
        unsupported = function('cs', 'class Foo {}')
        unsupported['metadata']['language'] = 'csharp'
        report = {'backend': 'ghidra', 'functions': [candidate_only, invalid, unsupported]}
        with tempfile.TemporaryDirectory() as directory:
            manifest = export_project(report, Path(directory))
            self.assertEqual(manifest['summary']['exported_units'], 0)
            self.assertEqual(manifest['summary']['excluded_functions'], 3)

    def test_refuses_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            export_project({'functions': []}, Path(directory))
            with self.assertRaises(FileExistsError):
                export_project({'functions': []}, Path(directory))

    @unittest.skipUnless(shutil.which('cmake') and shutil.which('gcc'), 'CMake/GCC required')
    def test_cmake_build_and_strict_link_for_leaf_subset(self):
        report = {'backend': 'wasm', 'functions': [function('one', 'uint32_t one(uint32_t x) { return x + 1; }'),
                  function('two', 'uint64_t two(uint64_t x) { return x ^ 19; }')]}
        with tempfile.TemporaryDirectory() as directory:
            export_project(report, Path(directory))
            project, build = Path(directory) / 'project', Path(directory) / 'build'
            for command in (['cmake', '-S', str(project), '-B', str(build)],
                            ['cmake', '--build', str(build)],
                            ['cmake', '--build', str(build), '--target', 'verify_link']):
                result = subprocess.run(command, capture_output=True, timeout=60)
                self.assertEqual(result.returncode, 0, result.stdout.decode() + result.stderr.decode())
            self.assertFalse(json.loads((project / 'manifest.json').read_text())['complete'])

    @unittest.skipUnless(shutil.which('cmake') and shutil.which('gcc'), 'CMake/GCC required')
    def test_external_global_builds_objects_but_fails_link(self):
        report = {'backend': 'ghidra', 'functions': [function('global', 'int read_score(void) { return engine_score; }',
                  preamble='extern int engine_score;')]}
        with tempfile.TemporaryDirectory() as directory:
            manifest = export_project(report, Path(directory))
            project, build = Path(directory) / 'project', Path(directory) / 'build'
            for command in (['cmake', '-S', str(project), '-B', str(build)], ['cmake', '--build', str(build)]):
                result = subprocess.run(command, capture_output=True, timeout=60)
                self.assertEqual(result.returncode, 0, result.stdout.decode() + result.stderr.decode())
            result = subprocess.run(['cmake', '--build', str(build), '--target', 'verify_link'], capture_output=True, timeout=60)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('engine_score', result.stderr.decode())
            self.assertFalse(manifest['complete'])
