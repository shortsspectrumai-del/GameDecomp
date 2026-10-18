"""Evaluator checks without network access or building the external project."""
import importlib.util
import unittest
from pathlib import Path
import tempfile
import json
import shutil
import sys

try:
    from benchmarks import real_game_differential as differential
except ImportError:
    differential = None

spec = importlib.util.spec_from_file_location('real_game_benchmark', Path(__file__).parents[1] / 'benchmarks' / 'real_game.py')
benchmark = importlib.util.module_from_spec(spec)
spec.loader.exec_module(benchmark)


class RealGameBenchmarkTests(unittest.TestCase):
    def test_ground_truth_excludes_runtime_plt_and_undefined_symbols(self):
        text = 'main T 401000 10\n_start T 400000 20\nprintf U\nmain@plt T 500000 10\nslideArray T 402000 50\n'
        self.assertEqual(benchmark.symbol_addresses(text, {'main', 'slideArray'}), {'main': 0x401000, 'slideArray': 0x402000})

    def test_stripped_text_blob_is_not_a_recovered_game_function(self):
        report = {'functions': [{'id': 'blob', 'address': 0x401000, 'name': '.text', 'source': 'anything',
                                'compilation': {'status': 'COMPILED'}}], 'type_recovery': {}}
        result = benchmark.measure(report, ['main'], {'main': 0x401000})
        self.assertEqual(result['game_entries_detected'], 0)
        self.assertEqual(result['game_sources_recovered'], 0)
        self.assertEqual(result['game_sources_compiled'], 0)
        self.assertEqual(result['non_game_records'], 1)

    def test_missing_signature_does_not_count_memory_hypotheses_as_dwarf(self):
        report = {'functions': [{'id': 'fn', 'address': 1, 'name': 'main', 'source': None,
                                'compilation': {'status': 'UNKNOWN'}}],
                  'type_recovery': {'functions': {'fn': {'memory_layout_hypotheses': [{'offset_bytes': 4}]}}}}
        result = benchmark.measure(report, ['main'], {'main': 1})
        self.assertEqual(result['game_metadata_signatures'], 0)
        self.assertEqual(result['game_names_preserved'], 1)

    def test_unsupported_backend_is_rejected_before_touching_output(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(ValueError):
                benchmark.run_benchmark(Path(directory) / 'output', backend='invented')
            self.assertFalse((Path(directory) / 'output').exists())


class RealGameDifferentialTests(unittest.TestCase):
    def test_compatibility_requires_opt_in_and_matching_hashes(self):
        import hashlib
        body = 'int fn(void){return SUB41(1,0);}'
        lowered = 'int fn(void){return 1;}'
        record = {'address': 1, 'name': 'fn', 'source': body, 'compilation': {'status': 'COMPILE_FAILED'},
                  'metadata': {'compile_preamble': '', 'compile_preamble_status': 'AVAILABLE'},
                  'compatibility': {'status': 'AVAILABLE', 'source': lowered, 'preamble': '',
                    'source_sha256': hashlib.sha256(body.encode()).hexdigest(),
                    'lowered_sha256': hashlib.sha256(lowered.encode()).hexdigest(),
                    'compilation': {'status': 'COMPILED'}}}
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            baseline = differential.write_recovered_unit(record, {}, output/'baseline')
            self.assertEqual(Path(baseline['source_file']).read_text(), body)
            result = differential.write_recovered_unit(record, {}, output/'compat', compatibility=True)
            self.assertEqual(Path(result['source_file']).read_text(), lowered)
            self.assertEqual(result['source_selection'], 'explicit_compatibility_lowering')
            record['compatibility']['source_sha256'] = 'forged'
            with self.assertRaises(ValueError):
                differential.write_recovered_unit(record, {}, output/'invalid', compatibility=True)

    def setUp(self):
        self.assertIsNotNone(differential, 'Valutatore differenziale non implementato')

    def test_digit_cases_cover_decimal_boundaries_and_uint32_range(self):
        cases = differential.function_cases('getDigitCount', random_cases=8)
        values = {case['number'] for case in cases}
        self.assertTrue({0, 1, 9, 10, 11, 99, 100, 101, 999999999,
                         1000000000, 1000000001, 4294967295} <= values)
        self.assertEqual(cases, differential.function_cases('getDigitCount', random_cases=8))
        self.assertTrue(all(0 <= value <= 4294967295 for value in values))

    def test_slide_cases_include_merges_and_wrapping_score(self):
        cases = differential.function_cases('slideArray', random_cases=0)
        self.assertIn({'array': [1, 1, 1, 1], 'score': 0}, cases)
        self.assertIn({'array': [2, 2, 1, 1], 'score': 4294967287}, cases)
        self.assertEqual(len(cases), 1875)

    def test_find_target_cases_respect_stop_before_x_precondition(self):
        cases = differential.function_cases('findTarget', random_cases=0)
        self.assertTrue(all(case['stop'] == 0 if case['x'] == 0 else
                            0 <= case['stop'] < case['x'] for case in cases))
        self.assertEqual(len(cases), 4375)

    def test_memory_or_score_mismatch_is_not_hidden_by_equal_return(self):
        original = {'return': 1, 'memory': [2, 0, 0, 0], 'score': 4}
        for changed in ({'return': 1, 'memory': [1, 1, 0, 0], 'score': 4},
                        {'return': 1, 'memory': [2, 0, 0, 0], 'score': 0}):
            result = differential.compare_observations([{'array': [1, 1, 0, 0], 'score': 0}],
                                                       [original], [changed])
            self.assertEqual(result['mismatches'], 1)
            self.assertEqual(result['matched_cases'], 0)

    def test_empty_cases_do_not_attest_a_matched_function(self):
        with self.assertRaises(ValueError):
            differential.compare_observations([], [], [])

    def test_missing_closure_helper_cannot_count_as_matched(self):
        report = {'functions': [{'address': 1, 'name': 'slideArray',
                                'source': 'unsigned char slideArray(void *a, void *s) { return 0; }',
                                'metadata': {'compile_preamble': '', 'compile_preamble_status': 'AVAILABLE'}}]}
        result = differential.recovered_closure(report, {'slideArray': 1, 'findTarget': 2}, 'slideArray')
        self.assertEqual(result['status'], 'UNKNOWN')
        self.assertIn('findTarget', result['missing_functions'])
        self.assertEqual(result['tested_cases'], 0)

    def test_translation_unit_retains_recovered_body_and_tracks_identity_mapping(self):
        body = 'unsigned char FUN_00000001(unsigned int n) { return n == 0 ? 7 : 8; }'
        record = {'name': 'FUN_00000001', 'address': 1, 'source': body,
                  'metadata': {'compile_preamble': 'typedef unsigned char byte;',
                               'compile_preamble_status': 'AVAILABLE'}}
        with tempfile.TemporaryDirectory() as directory:
            result = differential.write_recovered_unit(record, {'FUN_00000001': 'getDigitCount'}, Path(directory))
            self.assertEqual(Path(result['source_file']).read_text(), body)
            self.assertEqual(Path(result['unit_file']).read_text(), 'typedef unsigned char byte;\n\n' + body)
            self.assertEqual(result['identity_mapping'], {'FUN_00000001': 'getDigitCount'})
            self.assertIn('-DFUN_00000001=getDigitCount', result['identity_compile_flags'])

    @unittest.skipUnless(shutil.which('gcc'), 'gcc richiesto per fixture nativa nostra')
    def test_closure_artifacts_identify_each_function_for_ai_attribution(self):
        records = {name: {'name': 'fn_' + str(index), 'address': index,
                         'source': 'unsigned char fn_' + str(index) + '(void){return 1;}',
                         'metadata': {'compile_preamble': '', 'compile_preamble_status': 'AVAILABLE'}}
                   for index, name in enumerate(('slideArray', 'findTarget'), 1)}
        closure = {'records': records,
                   'identity_mapping': {record['name']: original for original, record in records.items()}}
        with tempfile.TemporaryDirectory() as directory:
            result = differential._compile_closure(closure, 'gcc', Path(directory))
            self.assertEqual(result['status'], 'AVAILABLE')
            self.assertEqual([item['original_function'] for item in result['artifacts']],
                             ['slideArray', 'findTarget'])

    def test_original_signature_check_rejects_wrong_abi(self):
        with self.assertRaises(ValueError):
            differential.check_original_signatures('uint8_t getDigitCount(uint64_t number) { return 1; }')

    def test_summary_counts_unknown_functions_separately(self):
        result = differential.summarize([
            {'status': 'MATCHED_FINITE_CASES', 'tested_cases': 12, 'matched_cases': 12, 'mismatches': 0},
            {'status': 'MISMATCH', 'tested_cases': 3, 'matched_cases': 2, 'mismatches': 1},
            {'status': 'UNKNOWN', 'tested_cases': 0},
        ])
        self.assertEqual(result['target_functions'], 3)
        self.assertEqual(result['tested_functions'], 2)
        self.assertEqual(result['matched_functions'], 1)
        self.assertEqual(result['unknown_functions'], 1)
        self.assertEqual(result['tested_cases'], 15)
        self.assertEqual(result['mismatches'], 1)

    @unittest.skipUnless(shutil.which('gcc'), 'gcc richiesto per fixture nativa nostra')
    def test_native_worker_detects_memory_and_score_mismatch(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            libraries = []
            for label, body in [('original', 'a[0]=2; a[1]=0; *s+=4; return 1;'),
                                ('recovered', 'return 1;')]:
                source = directory / (label + '.c')
                library = directory / (label + '.so')
                source.write_text('unsigned char slideArray(unsigned char *a, unsigned int *s) {' + body + '}')
                compilation = differential._command(['gcc', '-shared', '-fPIC', source, '-o', library])
                self.assertEqual(compilation['returncode'], 0, compilation['stderr'])
                libraries.append(str(library))
            job = directory / 'worker-input.json'
            job.write_text(json.dumps({'function': 'slideArray', 'original_library': libraries[0],
                                       'recovered_library': libraries[1],
                                       'cases': [{'array': [1, 1, 0, 0], 'score': 0}]}))
            execution = differential._command([sys.executable, differential.__file__, '--trusted', '--worker', job])
            self.assertEqual(execution['returncode'], 0, execution['stderr'])
            result = json.loads(execution['stdout'])
            self.assertEqual(result['status'], 'MISMATCH')
            self.assertEqual(result['mismatches'], 1)
            self.assertEqual(result['mismatch_examples'][0]['original']['score'], 4)

    @unittest.skipUnless(shutil.which('gcc'), 'gcc richiesto per fixture nativa nostra')
    def test_native_worker_detects_overwrites_beyond_array_and_uint32_score(self):
        body = 'a[0]=2; a[1]=0; *s+=4; return 1;'
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            original = directory / 'original.so'
            source = directory / 'original.c'
            source.write_text('unsigned char slideArray(unsigned char *a, unsigned int *s) {' + body + '}')
            compilation = differential._command(['gcc', '-shared', '-fPIC', source, '-o', original])
            self.assertEqual(compilation['returncode'], 0, compilation['stderr'])
            for label, overwrite in [('memory', 'a[4]=0;'), ('score', 's[1]=0;')]:
                with self.subTest(overwrite=label):
                    recovered = directory / (label + '.so')
                    source = directory / (label + '.c')
                    source.write_text('unsigned char slideArray(unsigned char *a, unsigned int *s) {' +
                                      body.replace('return 1;', overwrite + 'return 1;') + '}')
                    compilation = differential._command(['gcc', '-shared', '-fPIC', source, '-o', recovered])
                    self.assertEqual(compilation['returncode'], 0, compilation['stderr'])
                    job = directory / (label + '.json')
                    job.write_text(json.dumps({'function': 'slideArray', 'original_library': str(original),
                                               'recovered_library': str(recovered),
                                               'cases': [{'array': [1, 1, 0, 0], 'score': 0}]}))
                    execution = differential._command([sys.executable, differential.__file__, '--trusted', '--worker', job])
                    self.assertEqual(execution['returncode'], 0, execution['stderr'])
                    result = json.loads(execution['stdout'])
                    self.assertEqual(result['status'], 'MISMATCH')
                    example = result['mismatch_examples'][0]
                    for field in ('return', 'memory', 'score'):
                        self.assertEqual(example['original'][field], example['recovered'][field])
                    self.assertTrue(example['original']['guards'][label + '_intact'])
                    self.assertFalse(example['recovered']['guards'][label + '_intact'])
