"""Repair validation against trusted, locally authored native oracle fixtures."""
import copy
import hashlib
import inspect
import json
from pathlib import Path
import shutil
import tempfile
import time
import unittest
from unittest import mock

from benchmarks import real_game_differential as differential
try:
    from benchmarks import repair_llm as repair
except ImportError:
    repair = None


def sha(data):
    return hashlib.sha256(data if isinstance(data, bytes) else data.encode()).hexdigest()


class HeldoutCaseTests(unittest.TestCase):
    def test_unseen_audit_binds_selected_source_and_binary_before_execution(self):
        from benchmarks.repair_unseen import _bound_record
        target = {'address': 1, 'observed_name': 'fn', 'binary_sha256': 'binary'}
        source = 'int fn(void){return 1;}'
        report = {'input': {'sha256': 'binary'}, 'functions': [
            {'address': 1, 'name': 'fn', 'candidate': {'source': source, 'source_sha256': sha(source)}}]}
        self.assertEqual(_bound_record(report, target, sha(source))['name'], 'fn')
        with self.assertRaises(ValueError):
            _bound_record(report, target, sha('different selected body'))
        report['functions'][0]['candidate']['source'] = 'int fn(void){return 2;}'
        with self.assertRaises(ValueError):
            _bound_record(report, target, sha(source))
        report['input']['sha256'] = 'different binary'
        with self.assertRaises(ValueError):
            _bound_record(report, target, sha(source))

    def test_usage_counts_rejected_attempts_and_marks_missing_accounting(self):
        rows = [{'status': 'TESTED', 'attempts': [
            {'status': 'REJECTED', 'usage': {'prompt_tokens': 10, 'completion_tokens': 4, 'total_tokens': 14}},
            {'status': 'COMPILED', 'usage': {'prompt_tokens': 20, 'completion_tokens': 6, 'total_tokens': 26}}]}]
        summary = repair._usage_summary(rows)
        self.assertEqual(summary['total_tokens'], 40)
        self.assertTrue(summary['complete'])
        rows[0]['attempts'].append({'status': 'UNKNOWN', 'usage': {}})
        self.assertFalse(repair._usage_summary(rows)['complete'])
        self.assertEqual(repair._usage_summary(rows)['attempts_without_full_usage'], 1)

    def test_seed_extension_preserves_all_legacy_default_inputs(self):
        self.assertIn('seed', inspect.signature(differential.function_cases).parameters,
                      'Independent held-out seeds are not implemented')
        expected = {
            'getDigitCount': 'ffc73cef53c00bf3f77c0b412154735c9d82e1fe704ebebf305177a25dd36383',
            'findTarget': '334655124cd328970bfd3f6bfe8bb1a4337e6aa6036f82ab271653ed25e1d1df',
            'slideArray': 'b82a2b86cdc41ad9b9ea3f70493b122471b51e6cba0c58a87ed058e1ae38f4d1',
            'rotateBoard': 'be1bcacaf6b9dc3b2a240b3c9dc808708ba81929c7ff2c43940275d6f5ea66fa',
            'moveUp': '5b8f0fac4b55bbb5f8f4b8f316ade8c0a95b2b7dc63f735f18149148fcfca909',
            'moveLeft': '5b8f0fac4b55bbb5f8f4b8f316ade8c0a95b2b7dc63f735f18149148fcfca909',
            'moveDown': '5b8f0fac4b55bbb5f8f4b8f316ade8c0a95b2b7dc63f735f18149148fcfca909',
            'moveRight': '5b8f0fac4b55bbb5f8f4b8f316ade8c0a95b2b7dc63f735f18149148fcfca909',
            'findPairDown': 'eec9a070da9d51efcf66e161e59ca65400cc7ce236176b7c542500c7e6cc9850',
            'countEmpty': 'eec9a070da9d51efcf66e161e59ca65400cc7ce236176b7c542500c7e6cc9850',
            'gameEnded': 'eec9a070da9d51efcf66e161e59ca65400cc7ce236176b7c542500c7e6cc9850',
        }
        for name, wanted in expected.items():
            with self.subTest(name=name):
                cases = differential.function_cases(name, random_cases=8)
                self.assertEqual(sha(json.dumps(cases, sort_keys=True)), wanted)
        small = differential.function_cases('getDigitCount', random_cases=128, seed=2048)
        heldout = differential.function_cases('getDigitCount', random_cases=4096, seed=5741)
        self.assertNotEqual(small[-8:], heldout[-8:])
        self.assertIn({'number': 4294967295}, small)
        self.assertIn({'number': 4294967295}, heldout)
        self.assertEqual(differential.SEED, 2048)

    def test_seed_validation_never_mutates_default_generator(self):
        self.assertIn('seed', inspect.signature(differential.function_cases).parameters)
        before = differential.function_cases('rotateBoard', random_cases=8)
        for value in (True, -1, 2**64, '5741'):
            with self.subTest(seed=value), self.assertRaises(ValueError):
                differential.function_cases('rotateBoard', random_cases=8, seed=value)
        differential.function_cases('rotateBoard', random_cases=8, seed=5741)
        self.assertEqual(before, differential.function_cases('rotateBoard', random_cases=8))


@unittest.skipUnless(shutil.which('gcc'), 'gcc needed for our native fixture')
class TrustedRepairValidatorTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(repair, 'Trusted game repair benchmark not implemented')
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        source = '#include <stdint.h>\n#include <stdbool.h>\n#define SIZE 4\n'
        for name, (signature, _) in differential.SPECS.items():
            body = ('uint8_t n=1; while(number>=10){number/=10;n++;} return n;'
                    if name == 'getDigitCount' else '' if name == 'rotateBoard' else 'return 0;')
            source += signature + '{' + body + '}\n'
        source_dir = self.root / 'source'
        source_dir.mkdir()
        self.source = source_dir / '2048.c'
        self.source.write_text(source)
        (source_dir / 'LICENSE').write_text('Locally authored test fixture')
        self.trust = mock.patch.object(repair, 'FILES', {'2048.c': sha(source),
            'LICENSE': sha('Locally authored test fixture')})
        self.trust.start()
        self.addCleanup(self.trust.stop)
        self.binary = self.root / 'binary'
        self.binary.write_bytes(b'non-executed fixture binary')
        self.symbols = self.root / 'symbols-ground-truth.txt'
        self.symbols.write_text('getDigitCount T 1 1\n')
        self.baseline_source = 'unsigned char observed_fn(unsigned int value){return 0;}'
        self.record = {'id': 'fn:1', 'name': 'observed_fn', 'address': 1, 'source': self.baseline_source,
            'metadata': {'compile_preamble': '', 'compile_preamble_status': 'AVAILABLE'},
            'instructions': [], 'calls': [], 'diagnostics': []}
        self.report_path = self.root / 'baseline-report.json'
        self.report_path.write_text(json.dumps({'input': {'sha256': sha(self.binary.read_bytes())},
            'functions': [self.record], 'metadata': {}}))
        self.manifest_path = self.root / 'benchmark.json'
        self.manifest_path.write_text(json.dumps({'authored_functions': list(differential.SPECS)}))
        self.target = {'group': 'normal', 'variant': 'fixture', 'function': 'getDigitCount',
            'binary': str(self.binary), 'binary_sha256': sha(self.binary.read_bytes()),
            'baseline_report': str(self.report_path), 'baseline_report_sha256': sha(self.report_path.read_bytes()),
            'symbols': str(self.symbols), 'symbols_sha256': sha(self.symbols.read_bytes()),
            'compiler': shutil.which('gcc'), 'address': 1, 'observed_name': 'observed_fn'}
        self.provenance = {'manifest': str(self.manifest_path), 'manifest_sha256': sha(self.manifest_path.read_bytes()),
            'source': str(self.source), 'source_sha256': sha(source),
            'license_sha256': sha('Locally authored test fixture')}
        self.validator = repair.TrustedGameValidator(self.target, self.provenance, self.root / 'validation')

    def test_final_heldout_excludes_every_seen_input_and_duplicate(self):
        seen = differential.function_cases('getDigitCount', random_cases=128, seed=2048)
        validator = repair.TrustedGameValidator(self.target, self.provenance,
            self.root / 'unseen', random_cases=4096, seed=89123, scope='heldout', exclude_cases=seen)
        canonical = lambda cases: {json.dumps(case, sort_keys=True) for case in cases}
        self.assertFalse(canonical(seen) & canonical(validator.cases))
        self.assertEqual(len(validator.cases), len(canonical(validator.cases)))
        self.assertGreater(len(validator.cases), 0)

    def candidate(self, body):
        source = 'unsigned char observed_fn(unsigned int value){' + body + '}'
        return {'source': source, 'source_sha256': sha(source), 'baseline_sha256': sha(self.baseline_source),
            'compilation': {'status': 'COMPILED', 'abi_check': 'COMPILER_ABI_SHAPE'},
            'compile_support': '', 'selection_eligible': False}

    def test_repair_plan_keeps_fixed_targets_and_freezes_before_any_api(self):
        self.assertTrue(callable(getattr(repair, 'build_repair_plan', None)), 'Repair plan not implemented')
        from benchmarks.llm_real_game import EXPANDED
        targets = [dict(self.target, group=group, variant=variant, function=name)
                   for group, variant, name in EXPANDED]
        plan_path = self.root / 'expanded-plan.json'
        plan_path.write_text(json.dumps({'profile': 'expanded', 'targets': targets,
            'provenance': {'normal': self.provenance, 'stress': self.provenance}}))
        previous = self.root / 'verification.json'
        previous.write_text(json.dumps({'profile': 'expanded', 'plan_sha256': sha(plan_path.read_bytes()),
            'api_key_persisted': False, 'results': [
                {'variant': target['variant'], 'function': target['function'], 'status': 'UNKNOWN'}
                for target in targets]}))
        plan = repair.build_repair_plan(plan_path, previous, target_limit=4)
        self.assertEqual([(row['variant'], row['function']) for row in plan['targets']], [
            ('clang-O2-debug', 'findTarget'), ('clang-O2-stripped', 'getDigitCount'),
            ('gcc-O2-stripped', 'moveRight'), ('gcc-O0-stripped', 'countEmpty')])
        self.assertEqual(plan['training']['random_seed'], 2048)
        self.assertEqual(plan['heldout']['random_seed'], 5741)
        with mock.patch.object(repair.getpass, 'getpass', side_effect=AssertionError('credential read')), \
             mock.patch.object(repair.urllib.request, 'build_opener', side_effect=AssertionError('network')):
            frozen = repair.run(plan_path, previous, self.root / 'plan-only', None, plan_only=True, target_limit=1)
        self.assertEqual(len(frozen['targets']), 1)
        self.assertTrue((self.root / 'plan-only/plan.json').is_file())
        previous.write_text('{}')
        with self.assertRaises(ValueError):
            repair.build_repair_plan(plan_path, previous)

    def test_repair_target_limit_is_bounded_before_file_access(self):
        self.assertTrue(callable(getattr(repair, 'build_repair_plan', None)), 'Repair plan not implemented')
        for invalid in (0, 5, True, 1.5):
            with self.subTest(limit=invalid), self.assertRaises(ValueError):
                repair.build_repair_plan(Path('absent'), Path('absent'), target_limit=invalid)

    def test_wrong_compilable_body_is_disproved_with_one_bound_counterexample(self):
        candidate = self.candidate('return 0;')
        result = self.validator(self.record, candidate, timeout=10)
        self.assertEqual(result['status'], 'DISPROVED', result)
        self.assertGreater(result['mismatches'], 0)
        self.assertEqual(result['candidate_source_sha256'], candidate['source_sha256'])
        self.assertEqual(result['counterexample']['input'], {'number': 0})
        self.assertEqual(result['counterexample']['original']['return'], 1)
        self.assertEqual(result['counterexample']['recovered']['return'], 0)
        self.assertNotIn('source', result)
        self.assertLess(len(json.dumps(result).encode()), 16384)
        paths = list((self.root / 'validation').glob('*/verification.json'))
        self.assertEqual(len(paths), 1)
        saved = json.loads(paths[0].read_text())
        self.assertEqual(saved['unit_compilation']['artifacts'][0]['source_selection'], 'llm_validation_probe')

    def test_correct_body_passes_training_and_independent_heldout_without_fallback(self):
        candidate = self.candidate('unsigned char n=1;while(value>=10){value/=10;n++;}return n;')
        training = self.validator(self.record, candidate, timeout=10)
        self.assertEqual(training['status'], 'TESTED', training)
        self.assertEqual(training['mismatches'], 0)
        heldout = repair.TrustedGameValidator(self.target, self.provenance, self.root / 'heldout',
                                              random_cases=4096, seed=5741, scope='heldout')
        candidate.update(selection_eligible=True, semantic_status='TESTED', semantic_validation=training)
        result = heldout.evaluate(self.record, candidate, timeout=10, probe=False)
        self.assertEqual(result['status'], 'TESTED', result)
        self.assertGreater(result['cases_checked'], training['cases_checked'])
        self.assertNotEqual(result['cases_sha256'], training['cases_sha256'])
        self.assertNotIn('counterexample', result)
        self.assertEqual(result['random_seed'], 5741)

    def test_forged_hash_or_function_identity_never_reaches_execution(self):
        for alteration in ('hash', 'address', 'baseline'):
            candidate = self.candidate('return 0;')
            record = copy.deepcopy(self.record)
            if alteration == 'hash': candidate['source_sha256'] = 'forged'
            if alteration == 'address': record['address'] = 2
            if alteration == 'baseline': record['source'] += '/*changed*/'
            with self.subTest(alteration=alteration):
                result = self.validator(record, candidate, timeout=10)
                self.assertEqual(result['status'], 'UNKNOWN', result)
                self.assertEqual(result['cases_checked'], 0)
        self.assertFalse(any((self.root / 'validation').glob('*/original.so')))

    def test_required_external_helpers_are_unknown_without_baseline_linkage(self):
        candidate = self.candidate('extern unsigned char missing_helper(unsigned int);return missing_helper(value);')
        result = self.validator(self.record, candidate, timeout=10)
        self.assertEqual(result['status'], 'UNKNOWN', result)
        self.assertEqual(result['cases_checked'], 0)
        self.assertNotIn('counterexample', result)

    def test_total_timeout_bounds_a_nonterminating_candidate(self):
        candidate = self.candidate('for(;;){}')
        start = time.monotonic()
        result = self.validator(self.record, candidate, timeout=0.8)
        self.assertEqual(result['status'], 'UNKNOWN', result)
        self.assertLess(time.monotonic() - start, 2.5)
        self.assertEqual(result['cases_checked'], 0)

    def test_changed_pinned_oracle_is_rejected_before_execution(self):
        self.source.write_text(self.source.read_text() + '/*changed*/')
        result = self.validator(self.record, self.candidate('return 0;'), timeout=10)
        self.assertEqual(result['status'], 'UNKNOWN', result)
        self.assertEqual(result['cases_checked'], 0)


if __name__ == '__main__':
    unittest.main()
