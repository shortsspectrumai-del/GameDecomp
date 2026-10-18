"""Keep fresh held-out audit streams distinct from every declared prior stream."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from benchmarks import repair_unseen as audit
from benchmarks.real_game_differential import function_cases


class UnseenAuditSeedTests(unittest.TestCase):
    def test_default_stream_metadata_remains_legacy_compatible(self):
        self.assertEqual(audit._excluded_streams(89123, ()), [
            {'seed': 2048, 'random_cases': 128},
            {'seed': 2048, 'random_cases': 4096},
            {'seed': 5741, 'random_cases': 4096}])

    def test_extra_seeds_are_unique_and_preserve_explicit_order(self):
        self.assertEqual(audit._excluded_streams(20261018, (89123, 89123, 5741, 123)), [
            {'seed': 2048, 'random_cases': 128},
            {'seed': 2048, 'random_cases': 4096},
            {'seed': 5741, 'random_cases': 4096},
            {'seed': 89123, 'random_cases': 4096},
            {'seed': 123, 'random_cases': 4096}])

    def test_unsigned_seed_boundaries_are_accepted(self):
        self.assertEqual(audit._excluded_streams(0, (2**64 - 1,))[-1],
                         {'seed': 2**64 - 1, 'random_cases': 4096})
        self.assertEqual(audit._excluded_streams(2**64 - 1, (0,))[-1],
                         {'seed': 0, 'random_cases': 4096})

    def test_invalid_seeds_fail_before_any_provenance_read(self):
        invalid = (True, False, -1, 2**64, '89123', 12.5, None)
        with mock.patch.object(audit, '_read', side_effect=AssertionError('file read')):
            for value in invalid:
                with self.subTest(seed=value), self.assertRaises(ValueError):
                    audit.run('absent', 'absent', 'absent', seed=value)
                with self.subTest(excluded=value), self.assertRaises(ValueError):
                    audit.run('absent', 'absent', 'absent', exclude_seeds=(value,))
            for seed, extra in ((89123, (89123,)), (2048, ()), (5741, ())):
                with self.subTest(seed=seed, extra=extra), self.assertRaises(ValueError):
                    audit.run('absent', 'absent', 'absent', seed=seed, exclude_seeds=extra)

    def test_new_stream_excludes_old_audit_and_all_training_inputs(self):
        streams = audit._excluded_streams(20261018, (89123,))
        excluded = {json.dumps(case, sort_keys=True)
                    for stream in streams
                    for case in function_cases('getDigitCount', random_cases=stream['random_cases'],
                                               seed=stream['seed'])}
        fresh = function_cases('getDigitCount', random_cases=4096, seed=20261018)
        remaining = {json.dumps(case, sort_keys=True) for case in fresh} - excluded
        self.assertGreater(len(remaining), 0)
        self.assertFalse(remaining & excluded)
        old = {json.dumps(case, sort_keys=True)
               for case in function_cases('getDigitCount', random_cases=4096, seed=89123)}
        self.assertFalse(remaining & old)

    def test_run_records_requested_seed_and_exclusion_provenance(self):
        target = {'variant': 'fixture', 'function': 'getDigitCount', 'group': 'fixture'}
        plan = {'targets': [target], 'provenance': {'fixture': {}}}
        verified = {'plan_sha256': 'sealed', 'results': [
            {'variant': 'fixture', 'function': 'getDigitCount', 'candidate_source_sha256': 'body'}]}
        record = {'candidate': {'compilation': {'status': 'COMPILED'}}}
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            validator = mock.Mock()
            validator.cases = [{'number': 8675309}]
            validator.evaluate.return_value = {'status': 'TESTED', 'cases_checked': 1, 'mismatches': 0}
            with mock.patch.object(audit, 'ROOT', root), \
                 mock.patch.object(audit, '_digest', return_value='sealed'), \
                 mock.patch.object(audit, '_read', side_effect=[plan, verified, verified, {}]), \
                 mock.patch.object(audit, '_bound_record', return_value=record), \
                 mock.patch.object(audit, 'TrustedGameValidator', return_value=validator) as factory, \
                 mock.patch('builtins.print'):
                result = audit.run(root/'experiment', root/'seeded', root/'output',
                                   seed=20261018, exclude_seeds=(89123,))
            self.assertEqual(result['random_seed'], 20261018)
            self.assertIn({'seed': 89123, 'random_cases': 4096}, result['excluded_streams'])
            self.assertEqual(factory.call_args.kwargs['seed'], 20261018)
            exclusions = factory.call_args.kwargs['exclude_cases']
            old = function_cases('getDigitCount', random_cases=4096, seed=89123)
            observed = {json.dumps(case, sort_keys=True) for case in exclusions}
            self.assertTrue(all(json.dumps(case, sort_keys=True) in observed for case in old))
            self.assertEqual(result['provider_calls'], 0)

    def test_duplicate_conflicting_selection_is_rejected_before_output_or_execution(self):
        target = {'variant': 'fixture', 'function': 'getDigitCount', 'group': 'fixture'}
        plan = {'targets': [target], 'provenance': {'fixture': {}}}
        verified = {'plan_sha256': 'sealed', 'results': [
            {'variant': 'fixture', 'function': 'getDigitCount', 'candidate_source_sha256': 'first'},
            {'variant': 'fixture', 'function': 'getDigitCount', 'candidate_source_sha256': 'replacement'}]}
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with mock.patch.object(audit, 'ROOT', root), \
                 mock.patch.object(audit, '_digest', return_value='sealed'), \
                 mock.patch.object(audit, '_read', side_effect=[plan, verified, verified, {}]), \
                 mock.patch.object(audit, '_bound_record', return_value={'candidate': {}}), \
                 mock.patch.object(audit, 'TrustedGameValidator') as factory, \
                 mock.patch('builtins.print'):
                with self.assertRaises(ValueError):
                    audit.run(root/'experiment', root/'seeded', root/'output')
                factory.assert_not_called()
                self.assertFalse((root/'output').exists())


if __name__ == '__main__':
    unittest.main()
