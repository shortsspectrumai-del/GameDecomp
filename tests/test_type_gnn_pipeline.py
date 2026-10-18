import json
import shutil
import subprocess
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch


class StructuralPipelineTests(unittest.TestCase):
    def fixture(self, root):
        compiler = shutil.which('gcc')
        if not compiler:
            self.skipTest('gcc richiesto per fixture ELF fidata')
        source, binary = root / 'input.c', root / 'input.so'
        source.write_text('unsigned int add(unsigned int a, unsigned int b) { return a + b; }')
        subprocess.run([compiler, '-O2', '-shared', '-fPIC', str(source), '-o', str(binary)],
                       check=True, capture_output=True, timeout=10)
        return binary

    def test_types_and_neural_hypotheses_are_exported_without_rewriting_source(self):
        from gamedecomp.backends.native import analyze
        from gamedecomp.pipeline import AnalysisConfig, run_analysis
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = self.fixture(root)
            baseline = analyze(binary)
            function = next(f for f in baseline.functions if f.name == 'add')
            types_result = {'schema_version': 1, 'types': [
                {'id': 'dwarf:1', 'kind': 'structure', 'name': 'Vec2', 'byte_size': 8,
                 'evidence': [{'kind': 'METADATA', 'source': 'DWARF'}]}],
                'functions': {function.id: {'return_type': 'dwarf:1'}},
                'sources': ['DWARF'], 'diagnostics': []}
            gnn_result = {'model_hash': 'a' * 64, 'predictions': {function.id:
                {'label': 'arithmetic', 'confidence': 0.75, 'distribution': {'arithmetic': 0.75, 'bitwise': 0.25},
                 'evidence_ids': ['i:' + format(function.instructions[0].address, 'x')],
                 'status': 'HYPOTHESIS'}}, 'diagnostics': []}
            type_module = types.ModuleType('gamedecomp.type_recovery')
            type_module.recover_types = lambda *a, **k: types_result
            type_module.render_types_header = lambda result: '// Vec2: metadata summary\n'
            gnn_module = types.ModuleType('gamedecomp.gnn')
            gnn_module.predict = lambda *a, **k: gnn_result
            model = root / 'model.json'
            model.write_text('{}')
            with patch.dict('sys.modules', {'gamedecomp.type_recovery': type_module, 'gamedecomp.gnn': gnn_module}):
                report = run_analysis(binary, root / 'out', AnalysisConfig(
                    cache_path=root / 'cache.sqlite', check_compile=False,
                    function_pattern='add', gnn_model=model))
            recovered = report['functions'][0]
            self.assertEqual(recovered['source'], function.source)
            self.assertEqual(recovered['semantic_status'], 'UNKNOWN')
            self.assertEqual(report['type_recovery'], types_result)
            self.assertEqual(report['gnn']['model_hash'], gnn_result['model_hash'])
            self.assertEqual(recovered['metadata']['gnn_prediction']['status'], 'HYPOTHESIS')
            self.assertIn('type_recovery', recovered['metadata'])
            kinds = {fact['kind'] for fact in recovered['context']['evidence']}
            self.assertIn('type_metadata', kinds)
            self.assertIn('gnn_hypothesis', kinds)
            self.assertEqual(json.loads((root / 'out' / 'types.json').read_text()), types_result)
            self.assertIn('Vec2', (root / 'out' / 'types.hpp').read_text())
            self.assertIn('arithmetic', (root / 'out' / 'report.html').read_text())

    def test_disabled_optional_features_keep_analysis_and_report(self):
        from gamedecomp.pipeline import AnalysisConfig, run_analysis
        from tests.test_wasm import wasm_fixture
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = root / 'input.wasm'
            binary.write_bytes(wasm_fixture())
            report = run_analysis(binary, root / 'out', AnalysisConfig(
                cache_path=root / 'cache.sqlite', check_compile=False, recover_types=False))
            self.assertEqual(report['type_recovery']['types'], [])
            self.assertEqual(report['gnn']['status'], 'DISABLED')
            self.assertEqual(report['summary']['recovered'], 1)

    def test_api_key_is_excluded_from_configuration_repr(self):
        from gamedecomp.pipeline import AnalysisConfig
        self.assertNotIn('secret-test-key', repr(AnalysisConfig(llm_api_key='secret-test-key')))
