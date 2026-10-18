import hashlib
import io
import json
from pathlib import Path
import fnmatch
import tempfile
import unittest
from unittest.mock import patch

from benchmarks import llm_real_game as benchmark
from benchmarks.real_game_differential import SPECS


class ExpandedLLMBenchmarkTests(unittest.TestCase):
    def test_fixed_sample_covers_all_functions_and_variants(self):
        pairs = benchmark.EXPANDED
        self.assertEqual(len(pairs), 22)
        self.assertEqual(len(set(pairs)), 22)
        self.assertEqual({name for _, _, name in pairs}, set(SPECS))
        self.assertTrue(all(sum(name == item[2] for item in pairs) == 2 for name in SPECS))
        self.assertEqual(len({variant for _, variant, _ in pairs}), 12)
        self.assertEqual(len(benchmark.TARGETED), 3)

    def test_exact_pattern_handles_metacharacters_and_prefix_collisions(self):
        pattern = benchmark.exact_function_pattern('FUN_x[4]+')
        self.assertTrue(fnmatch.fnmatchcase('FUN_x[4]+', pattern))
        self.assertFalse(fnmatch.fnmatchcase('FUN_x[4]+_helper', pattern))
        self.assertFalse(fnmatch.fnmatchcase('prefix_FUN_x[4]+', pattern))
        self.assertFalse(fnmatch.fnmatchcase('FUN_x[4]+\n', pattern))
        for name in ('fn*?', 'fn[0]', 'fn]', 'fn[['):
            exact = benchmark.exact_function_pattern(name)
            self.assertTrue(fnmatch.fnmatchcase(name, exact))
            self.assertFalse(fnmatch.fnmatchcase(name + '_helper', exact))

    def test_exact_target_does_not_take_first_function(self):
        report = {'functions': [{'address': 1, 'name': 'other'}, {'address': 2, 'name': 'target'}]}
        self.assertEqual(benchmark._exact_record(report, 2, 'target')['address'], 2)
        with self.assertRaises(ValueError):
            benchmark._exact_record(report, 2, 'wrong')
        report['functions'].append({'address': 2, 'name': 'target'})
        with self.assertRaises(ValueError):
            benchmark._exact_record(report, 2, 'target')

    def test_ai_dependency_never_counts_as_target(self):
        row = {'status': 'MATCHED_FINITE_CASES', 'tested_cases': 100, 'artifacts': [{'original_function': 'rotateBoard', 'source_selection': 'llm_reconstruction'},
                             {'original_function': 'moveLeft', 'source_selection': 'conservative_baseline'}]}
        result = benchmark._attribution(row, 'moveLeft')
        self.assertFalse(result['llm_target_used'])
        self.assertFalse(result['llm_used'])
        self.assertEqual(result['llm_dependency_functions'], ['rotateBoard'])
        self.assertTrue(benchmark._attribution(row, 'rotateBoard')['llm_target_used'])
        failed = dict(row, status='UNKNOWN', tested_cases=0)
        self.assertFalse(benchmark._attribution(failed, 'rotateBoard')['llm_target_used'])
        self.assertEqual(benchmark._attribution(failed, 'rotateBoard')['target_source_selection'], 'llm_reconstruction')
        self.assertFalse(benchmark._attribution({'artifacts': []}, 'moveLeft')['llm_used'])

    def test_summary_keeps_errors_and_unknown_in_denominator(self):
        rows = [{'status': 'MATCHED_FINITE_CASES', 'llm_target_used': True, 'tested_cases': 100,
                 'mismatches': 0, 'candidate_usage': {'prompt_tokens': 7}},
                {'status': 'UNKNOWN', 'llm_target_used': False},
                {'status': 'ERROR', 'error_type': 'TimeoutError'}]
        result = benchmark.summarize(rows, 22)
        self.assertEqual(result['planned_targets'], 22)
        self.assertEqual(result['completed_targets'], 3)
        self.assertEqual(result['llm_targets_matched'], 1)
        self.assertEqual(result['status_counts'], {'MATCHED_FINITE_CASES': 1, 'UNKNOWN': 1, 'ERROR': 1})
        self.assertEqual(result['candidate_usage'], {'prompt_tokens': 7})
        self.assertFalse(result['usage_complete'])

    def _fixture(self, root):
        files = {'2048.c': b'original fixture, evaluator only', 'LICENSE': b'MIT fixture'}
        manifests = []
        for group in ('normal', 'stress'):
            directory = root / group
            (directory / 'source').mkdir(parents=True)
            for filename, data in files.items():
                (directory / 'source' / filename).write_bytes(data)
            builds = []
            for variant in sorted({variant for g, variant, _ in benchmark.EXPANDED if g == group}):
                folder = directory / variant
                folder.mkdir()
                binary = folder / 'binary'
                binary.write_bytes(b'fixture binary ' + variant.encode())
                (folder / 'symbols-ground-truth.txt').write_text('evaluator-only symbols')
                report = folder / 'report.json'
                report.write_text(json.dumps({'functions': [
                    {'address': index, 'name': 'FUN_' + str(index), 'compilation': {'status': 'UNKNOWN'}}
                    for index, _ in enumerate(SPECS, 1)]}))
                builds.append({'variant': variant, 'binary': str(binary),
                               'binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(),
                               'runs': [{'report': str(report)}]})
            manifest = directory / 'benchmark.json'
            manifest.write_text(json.dumps({'builds': builds, 'authored_functions': list(SPECS)}))
            manifests.append(manifest)
        return manifests, {name: hashlib.sha256(data).hexdigest() for name, data in files.items()}

    def test_plan_only_never_asks_key_or_calls_provider_and_seals_inputs(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            paths, hashes = self._fixture(root)
            addresses = {name: index for index, name in enumerate(SPECS, 1)}
            with patch.object(benchmark, 'FILES', hashes), patch.object(benchmark, 'mapped_symbol_addresses', return_value=(addresses, 0)), \
                 patch.object(benchmark.getpass, 'getpass', side_effect=AssertionError('credential read')), \
                 patch.object(benchmark.urllib.request, 'build_opener', side_effect=AssertionError('network')), \
                 patch.object(benchmark, 'run_analysis', side_effect=AssertionError('inference')):
                plan = benchmark.run(*paths, root / 'out', None, profile='expanded', plan_only=True)
            self.assertEqual(len(plan['targets']), 22)
            self.assertTrue((root / 'out/plan.json').is_file())
            target = plan['targets'][0]
            provenance = plan['provenance'][target['group']]
            benchmark._verify_target_inputs(target, provenance)
            Path(target['baseline_report']).write_text('{}')
            with self.assertRaisesRegex(ValueError, 'provenance changed'):
                benchmark._verify_target_inputs(target, provenance)

    def test_plan_retains_missing_entries(self):
        with tempfile.TemporaryDirectory() as tmp:
            paths, hashes = self._fixture(Path(tmp))
            with patch.object(benchmark, 'FILES', hashes), patch.object(benchmark, 'mapped_symbol_addresses', return_value=({}, 0)):
                plan = benchmark.build_plan(*paths, profile='expanded')
            self.assertEqual(len(plan['targets']), 22)
            self.assertTrue(all(row['entry_status'] == 'NOT_DISCOVERED' for row in plan['targets']))

    def test_inference_errors_keep_full_sample_and_plan_precedes_requests(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            paths, hashes = self._fixture(root)
            addresses = {name: index for index, name in enumerate(SPECS, 1)}
            class Opener:
                def open(self, request, timeout):
                    self_test.assertTrue((root / 'out/plan.json').is_file())
                    return io.BytesIO(b'{"data":[{"id":"test-model"}]}')
            self_test = self
            with patch.object(benchmark, 'FILES', hashes), patch.object(benchmark, 'mapped_symbol_addresses', return_value=(addresses, 0)), \
                 patch.object(benchmark.urllib.request, 'build_opener', return_value=Opener()), \
                 patch.object(benchmark, 'run_analysis', side_effect=TimeoutError('hidden transport data')) as analysis, \
                 patch.object(benchmark, 'evaluate_report', side_effect=AssertionError('no candidate')):
                result = benchmark.run(*paths, root / 'out', None, profile='expanded', key='fixture-secret', model='test-model')
            self.assertEqual(analysis.call_count, 22)
            self.assertEqual(result['summary']['status_counts'], {'ERROR': 22})
            self.assertEqual(result['summary']['planned_targets'], 22)
            self.assertEqual(result['summary']['completed_targets'], 22)
            self.assertEqual(result['summary']['llm_target_used'], 0)
            self.assertFalse((root / 'out/verification.partial.json').exists())
            report = (root / 'out/verification.json').read_text()
            self.assertNotIn('fixture-secret', report)
            self.assertNotIn('hidden transport data', report)

    def test_random_case_bounds(self):
        for value in (-1, 4097, True, 3.5):
            with self.subTest(value=value), self.assertRaises(ValueError):
                benchmark.build_plan(Path('absent'), Path('absent'), random_cases=value)


if __name__ == '__main__':
    unittest.main()
