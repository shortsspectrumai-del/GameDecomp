import json
import hashlib
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch
from pathlib import Path

from tests.test_wasm import wasm_fixture


class GhidraCompilationContextTests(unittest.TestCase):
    def test_frontend_display_names_do_not_disable_elf_type_recovery(self):
        from gamedecomp.models import Analysis
        from gamedecomp.pipeline import AnalysisConfig, run_analysis
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = root / 'input.elf'
            header = bytearray(64)
            header[:6] = b'\x7fELF\x02\x01'
            header[18:20] = (62).to_bytes(2, 'little')
            binary.write_bytes(header)
            analysis = Analysis(hashlib.sha256(header).hexdigest(),
                'Executable and Linking Format (ELF)', 'x86:LE:64:default', 'ghidra', [])
            types = {'schema_version': 1, 'types': [], 'functions': {}, 'sources': [], 'diagnostics': []}
            with patch('gamedecomp.pipeline._analyze', return_value=analysis), \
                 patch('gamedecomp.type_recovery.recover_types', return_value=types) as recovery:
                report = run_analysis(binary, root / 'output', AnalysisConfig(
                    backend='ghidra', cache_path=root / 'cache.sqlite'))
            observed = recovery.call_args.args[1]
            self.assertEqual((observed.format, observed.architecture), ('ELF', 'x86_64'))
            self.assertEqual(observed.metadata['frontend_architecture'], 'x86:LE:64:default')
            self.assertEqual(report['input']['format'], 'ELF')

    def analyze_fixture(self, root, backend='ghidra', preamble='typedef unsigned char GameByte;', status='AVAILABLE'):
        from gamedecomp.models import Analysis, Function
        from gamedecomp.pipeline import AnalysisConfig, run_analysis
        binary = root / 'input.wasm'
        binary.write_bytes(wasm_fixture())
        source = 'GameByte digit_count(unsigned int number) { return number > 9 ? 2 : 1; }'
        analysis = Analysis(hashlib.sha256(binary.read_bytes()).hexdigest(), 'WASM', 'x86_64', backend,
            [Function('native:1000', 'digit_count', 0x1000, source=source,
                metadata={'language': 'c', 'compile_preamble': preamble, 'compile_preamble_status': status})])
        with patch('gamedecomp.pipeline._analyze', return_value=analysis):
            return run_analysis(binary, root / 'output', AnalysisConfig(
                backend=backend, cache_path=root / 'cache.sqlite', recover_types=False)), source

    @unittest.skipUnless(shutil.which('gcc') or shutil.which('clang'), 'C compiler required')
    def test_ghidra_observed_declarations_compile_without_rewriting_source(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report, source = self.analyze_fixture(root)
            function = report['functions'][0]
            self.assertEqual(function['source'], source)
            self.assertEqual(function['compilation']['status'], 'COMPILED')
            self.assertEqual(function['semantic_status'], 'UNKNOWN')
            context = function['compilation']['context']
            self.assertEqual(context['source'], 'ghidra_observed_declarations')
            preamble = function['metadata']['compile_preamble']
            self.assertEqual(context['sha256'], hashlib.sha256(preamble.encode()).hexdigest())
            unit = root / 'output' / 'functions' / '00000_1000.unit.c'
            self.assertEqual(unit.read_text(), preamble + '\n\n' + source)
            self.assertEqual((root / 'output' / 'functions' / '00000_1000.c').read_text(), source)

    def test_invalid_or_unavailable_context_never_reaches_compiler(self):
        for preamble, status in [('typedef int T;', 'UNAVAILABLE'), ('x' * (256 * 1024 + 1), 'AVAILABLE'),
                                 ('x\x00y', 'AVAILABLE'), (42, 'AVAILABLE')]:
            with self.subTest(status=status, type=type(preamble)), tempfile.TemporaryDirectory() as directory:
                with patch('gamedecomp.pipeline.compile_source', return_value={'status': 'COMPILED', 'diagnostics': []}) as compiler:
                    report, _ = self.analyze_fixture(Path(directory), preamble=preamble, status=status)
                compiler.assert_not_called()
                self.assertEqual(report['functions'][0]['compilation']['status'], 'UNKNOWN')

    @unittest.skipUnless(shutil.which('gcc') or shutil.which('clang'), 'C compiler required')
    def test_other_backends_cannot_supply_ghidra_compilation_declarations(self):
        with tempfile.TemporaryDirectory() as directory:
            report, _ = self.analyze_fixture(Path(directory), backend='wasm')
            self.assertEqual(report['functions'][0]['compilation']['status'], 'COMPILE_FAILED')
            self.assertNotIn('context', report['functions'][0]['compilation'])


class PipelineTests(unittest.TestCase):
    def test_wasm_end_to_end_and_cached_analysis(self):
        from gamedecomp.pipeline import AnalysisConfig, run_analysis
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = root / 'input with spaces.wasm'
            binary.write_bytes(wasm_fixture())
            config = AnalysisConfig(cache_path=root / 'cache.sqlite', workers=2)
            first = run_analysis(binary, root / 'first', config)
            second = run_analysis(binary, root / 'second', config)
            self.assertFalse(first['cache_hit'])
            self.assertTrue(second['cache_hit'])
            self.assertEqual(first['summary']['recovered'], 1)
            self.assertEqual(first['summary']['compiled'], 1)
            self.assertEqual(first['summary']['proved'], 0)
            self.assertTrue((root / 'first' / 'report.html').is_file())
            report = json.loads((root / 'first' / 'report.json').read_text())
            self.assertEqual(report['functions'][0]['semantic_status'], 'UNKNOWN')
            self.assertTrue((root / 'first' / 'recovered.c').is_file())
            with self.assertRaises(FileExistsError):
                run_analysis(binary, root / 'first', config)

    def test_unsupported_wasm_keeps_assembly_and_unknown(self):
        from gamedecomp.pipeline import AnalysisConfig, run_analysis
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / 'bad.wasm'
            path.write_bytes(wasm_fixture(0x6d))
            report = run_analysis(path, root / 'output', AnalysisConfig(cache_path=root / 'cache.sqlite'))
            self.assertEqual(report['summary']['recovered'], 0)
            self.assertTrue(report['functions'][0]['diagnostics'])

    def test_cli_doctor_is_machine_readable(self):
        process = subprocess.run([sys.executable, '-m', 'gamedecomp', 'doctor', '--json'],
                                 capture_output=True, text=True, timeout=10)
        self.assertEqual(process.returncode, 0, process.stderr)
        result = json.loads(process.stdout)
        self.assertIn('backends', result)
        self.assertIn('native', result['backends'])

    def test_llm_needs_explicit_model(self):
        from gamedecomp.pipeline import AnalysisConfig
        with self.assertRaises(ValueError):
            AnalysisConfig(llm_endpoint='http://localhost:9999/v1')

    def test_cache_cannot_overwrite_input_or_live_inside_output(self):
        from gamedecomp.pipeline import AnalysisConfig, run_analysis
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = root / 'input.wasm'
            data = wasm_fixture()
            binary.write_bytes(data)
            for cache in (binary, root / 'output' / 'cache.sqlite'):
                with self.subTest(cache=cache), self.assertRaises(ValueError):
                    run_analysis(binary, root / 'output', AnalysisConfig(cache_path=cache, check_compile=False))
                self.assertEqual(binary.read_bytes(), data)
                self.assertFalse((root / 'output').exists())

    def test_cache_fingerprint_tracks_effective_ghidra_home(self):
        from gamedecomp.pipeline import AnalysisConfig, _fingerprint
        config = AnalysisConfig(backend='ghidra')
        with patch.dict('os.environ', {'GHIDRA_HOME': '/tmp/ghidra-one'}):
            first = _fingerprint('ghidra', config)
        with patch.dict('os.environ', {'GHIDRA_HOME': '/tmp/ghidra-two'}):
            second = _fingerprint('ghidra', config)
        self.assertNotEqual(first, second)

    def test_auto_backend_uses_an_explicit_available_ghidra_environment(self):
        from gamedecomp.pipeline import AnalysisConfig, _backend_name
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'support').mkdir()
            (root / 'support' / 'analyzeHeadless').touch()
            with patch.dict('os.environ', {'GHIDRA_HOME': str(root)}):
                self.assertEqual(_backend_name({'format': 'ELF'}, AnalysisConfig()), 'ghidra')
                self.assertEqual(_backend_name({'format': 'WASM'}, AnalysisConfig()), 'wasm')
                self.assertEqual(_backend_name({'format': 'ELF'}, AnalysisConfig(backend='native')), 'native')
            with patch.dict('os.environ', {'GHIDRA_HOME': str(root / 'missing')}):
                self.assertEqual(_backend_name({'format': 'ELF'}, AnalysisConfig()), 'native')

    def test_sqlite_sidecars_cannot_overwrite_binary_even_through_alias(self):
        from gamedecomp.pipeline import AnalysisConfig, run_analysis
        for suffix in ('-wal', '-shm', '-journal'):
            with self.subTest(suffix=suffix), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                cache = root / 'cache.sqlite'
                binary = Path(str(cache) + suffix)
                data = wasm_fixture()
                binary.write_bytes(data)
                with self.assertRaises(ValueError):
                    run_analysis(binary, root / 'output', AnalysisConfig(cache_path=cache, check_compile=False))
                self.assertEqual(binary.read_bytes(), data)
                alias = root / 'alias.wasm'
                alias.hardlink_to(binary)
                with self.assertRaises(ValueError):
                    run_analysis(alias, root / 'output', AnalysisConfig(cache_path=cache, check_compile=False))
                self.assertEqual(alias.read_bytes(), data)

    def test_compiled_ai_candidate_does_not_replace_baseline(self):
        from gamedecomp.pipeline import AnalysisConfig, run_analysis
        key = 'fixture-pipeline-ephemeral-key-665544'
        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
                request = json.loads(body['messages'][1]['content'])
                signature = request['context']['evidence'][-1]
                export = signature['metadata']['export_name']
                candidate = {'source': f'uint32_t {export}(uint32_t a, uint32_t b) {{ return 0; }} /* {key} */',
                             'evidence_ids': [signature['id']], 'assumptions': ['Unverified proposal ' + key]}
                if getattr(self.server, 'return_nul', False):
                    candidate['source'] += '\n/* \x00 */'
                response = json.dumps({'choices': [{'message': {'content': json.dumps(candidate)}}]}).encode()
                self.send_response(200)
                self.end_headers()
                self.wfile.write(response)
            def log_message(self, *args):
                pass
        with ThreadingHTTPServer(('127.0.0.1', 0), Handler) as server:
            server.daemon_threads = True
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                with tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    binary = root / 'add.wasm'
                    binary.write_bytes(wasm_fixture())
                    config = AnalysisConfig(cache_path=root / 'cache.sqlite', llm_model='test',
                                            llm_endpoint=f'http://127.0.0.1:{server.server_port}/v1', llm_api_key=key)
                    report = run_analysis(binary, root / 'out', config)
                    function = report['functions'][0]
                    self.assertEqual(function['candidate']['compilation']['status'], 'COMPILED')
                    self.assertEqual(function['candidate']['semantic_status'], 'UNKNOWN')
                    self.assertNotEqual(function['source'], function['candidate']['source'])
                    self.assertEqual(function['selected_source'], 'conservative_baseline')
                    for artifact in (root / 'out').rglob('*'):
                        if artifact.is_file():
                            self.assertNotIn(key.encode(), artifact.read_bytes(), str(artifact))
                    server.return_nul = True
                    malformed = run_analysis(binary, root / 'out-nul', config)
                    function = malformed['functions'][0]
                    self.assertIsNone(function['candidate'])
                    self.assertEqual(function['compilation']['status'], 'COMPILED')
                    self.assertEqual(function['ai_attempts'][0]['status'], 'UNKNOWN')
                    self.assertTrue((root / 'out-nul' / 'report.json').is_file())
            finally:
                server.shutdown()
                thread.join(timeout=2)
