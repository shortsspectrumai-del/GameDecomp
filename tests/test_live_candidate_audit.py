"""Independent live-candidate audit keeps identity, denominator and unseen inputs."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from benchmarks import repair_llm
try:
    from benchmarks import audit_repair_candidates as audit
except ImportError:
    audit = None


def sha(data):
    return hashlib.sha256(data.encode()).hexdigest()


class LiveCandidateAuditTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(audit, 'Current-candidate audit is not implemented')
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.experiment = self.root/'live'
        self.experiment.mkdir()
        self.protocol = {'schema_version': 1, 'random_seed': 20261019, 'random_cases': 4096,
            'excluded_streams': [{'seed': 2048, 'random_cases': 128},
                {'seed': 2048, 'random_cases': 4096}, {'seed': 5741, 'random_cases': 4096},
                {'seed': 89123, 'random_cases': 4096}, {'seed': 20261018, 'random_cases': 4096}],
            'targets': [list(pair) for pair in repair_llm.REPAIR_TARGETS], 'feedback_to_model': False}
        self.protocol_path = self.root/'audit-plan.json'
        self.protocol_path.write_text(json.dumps(self.protocol))
        targets, results = [], []
        self.reports = []
        for index, (variant, name) in enumerate(repair_llm.REPAIR_TARGETS):
            source = f'int fn{index}(void){{return 0;}}'
            target = {'variant': variant, 'function': name, 'group': 'fixture', 'address': index,
                      'observed_name': f'fn{index}', 'binary_sha256': 'binary'}
            report = {'input': {'sha256': 'binary'}, 'functions': [{'address': index,
                'name': f'fn{index}', 'source': 'immutable baseline', 'candidate': {
                    'source': source, 'source_sha256': sha(source),
                    'compilation': {'status': 'COMPILED'}, 'selection_eligible': True}}]}
            path = self.experiment/(variant+'-'+name)/'analysis/report.json'
            path.parent.mkdir(parents=True)
            path.write_text(json.dumps(report))
            self.reports.append(path)
            targets.append(target)
            results.append({'variant': variant, 'function': name, 'status': 'TESTED',
                            'candidate_source_sha256': sha(source), 'analysis_report': str(path)})
        self.plan = {'targets': targets, 'provenance': {'fixture': {}}}
        self.plan_path = self.experiment/'plan.json'
        self.plan_path.write_text(json.dumps(self.plan))
        self.verification = {'plan_sha256': sha(self.plan_path.read_text()), 'results': results}
        self.verification_path = self.experiment/'verification.json'
        self.verification_path.write_text(json.dumps(self.verification))

    def execute(self, validator=None):
        validator = validator or mock.Mock(cases=[{'new': 'input'}])
        validator.evaluate.return_value = {'status': 'TESTED', 'cases_checked': 1, 'mismatches': 0}
        with mock.patch.object(audit, 'ROOT', self.root), \
             mock.patch.object(audit, '_verify_inputs'), \
             mock.patch.object(audit, 'function_cases', return_value=[{'prior': 'input'}]), \
             mock.patch.object(audit, 'TrustedGameValidator', return_value=validator) as factory:
            result = audit.run(self.experiment, self.root/'audit', self.protocol_path)
        return result, factory, validator

    def test_selected_candidates_and_protocol_hash_are_bound_before_execution(self):
        result, factory, validator = self.execute()
        self.assertEqual(result['summary']['planned_targets'], 4)
        self.assertEqual(result['summary']['status_counts'], {'TESTED': 4})
        self.assertEqual(result['provider_calls'], 0)
        self.assertEqual(result['audit_plan_sha256'], sha(self.protocol_path.read_text()))
        self.assertEqual(factory.call_args.kwargs['seed'], 20261019)
        self.assertFalse(validator.evaluate.call_args.kwargs['probe'])
        self.assertTrue(all(row.get('candidate_source_sha256') and row.get('analysis_report_sha256')
                            for row in result['results']))

    def test_substituted_candidate_and_binary_preserve_error_denominator(self):
        for index in (0, 1):
            path = self.reports[index]
            report = json.loads(path.read_text())
            if index == 0:
                report['functions'][0]['candidate']['source'] += ' changed'
            else:
                report['input']['sha256'] = 'changed'
            path.write_text(json.dumps(report))
        result, factory, _ = self.execute()
        self.assertEqual(result['summary']['planned_targets'], 4)
        self.assertEqual(result['summary']['status_counts'], {'ERROR': 2, 'TESTED': 2})
        self.assertEqual(factory.call_count, 2)

    def test_support_only_tampering_never_executes_unbound_generated_code(self):
        for index, support in enumerate(('int unbound_helper(void){return 1;}', None, 12)):
            path = self.reports[index]
            report = json.loads(path.read_text())
            report['functions'][0]['candidate']['compile_support'] = support
            path.write_text(json.dumps(report))
        result, factory, _ = self.execute()
        self.assertEqual(result['summary']['status_counts'], {'ERROR': 3, 'TESTED': 1})
        self.assertEqual(factory.call_count, 1)

    def test_ineligible_and_missing_candidate_do_not_execute_or_use_baseline(self):
        for index in (0, 1):
            path = self.reports[index]
            report = json.loads(path.read_text())
            if index == 0:
                report['functions'][0]['candidate']['selection_eligible'] = False
            else:
                report['functions'][0]['candidate'] = None
                self.verification['results'][index]['candidate_source_sha256'] = None
            path.write_text(json.dumps(report))
        self.verification_path.write_text(json.dumps(self.verification))
        result, factory, _ = self.execute()
        self.assertEqual(result['summary']['status_counts'], {'UNKNOWN': 2, 'TESTED': 2})
        self.assertEqual(factory.call_count, 2)
        self.assertTrue(all(row['validation']['cases_checked'] == 0 for row in result['results'][:2]))

    def test_duplicate_result_target_or_changed_plan_fails_before_native_execution(self):
        self.verification['results'][-1] = self.verification['results'][0]
        self.verification_path.write_text(json.dumps(self.verification))
        with mock.patch.object(audit, 'TrustedGameValidator') as factory:
            with self.assertRaises(ValueError):
                audit.run(self.experiment, self.root/'audit', self.protocol_path)
            factory.assert_not_called()
        self.verification['results'][-1] = {'variant': 'gcc-O0-stripped', 'function': 'countEmpty'}
        self.verification_path.write_text(json.dumps(self.verification))
        self.plan_path.write_text(self.plan_path.read_text()+' ')
        with self.assertRaises(ValueError):
            audit.run(self.experiment, self.root/'audit', self.protocol_path)

    def test_changed_predeclared_protocol_fails_before_execution(self):
        self.protocol['feedback_to_model'] = True
        self.protocol_path.write_text(json.dumps(self.protocol))
        with mock.patch.object(audit, 'TrustedGameValidator') as factory:
            with self.assertRaises(ValueError):
                audit.run(self.experiment, self.root/'audit', self.protocol_path)
            factory.assert_not_called()

    def test_protocol_mutation_during_last_validation_cannot_be_tested(self):
        validator = mock.Mock(cases=[{'new': 'input'}])
        calls = []
        def evaluate(*args, **kwargs):
            calls.append(1)
            if len(calls) == 4:
                self.protocol_path.write_text(self.protocol_path.read_text()+' ')
            return {'status': 'TESTED', 'cases_checked': 1, 'mismatches': 0}
        validator.evaluate.side_effect = evaluate
        result, _, _ = self.execute(validator)
        self.assertEqual(result['summary']['status_counts'], {'TESTED': 3, 'ERROR': 1})

    def test_report_mutation_during_last_validation_cannot_be_tested(self):
        validator = mock.Mock(cases=[{'new': 'input'}])
        original_hash = sha(self.reports[-1].read_text())
        calls = []
        def evaluate(*args, **kwargs):
            calls.append(1)
            if len(calls) == 4:
                self.reports[-1].write_text(self.reports[-1].read_text()+' ')
            return {'status': 'TESTED', 'cases_checked': 1, 'mismatches': 0}
        validator.evaluate.side_effect = evaluate
        result, _, _ = self.execute(validator)
        self.assertEqual(result['summary']['status_counts'], {'TESTED': 3, 'ERROR': 1})
        self.assertEqual(result['results'][-1]['analysis_report_sha256'], original_hash)

    def test_decoded_report_and_recorded_hash_use_the_same_read_bytes(self):
        data = b'{"input":{"sha256":"fixture"}}\n'
        path = self.root/'bound.json'
        path.write_bytes(data)
        decoded, digest, raw = audit._bound_json(path)
        self.assertEqual(decoded, json.loads(data))
        self.assertEqual(raw, data)
        self.assertEqual(digest, hashlib.sha256(data).hexdigest())

    def test_duplicate_or_previously_seen_validator_inputs_are_rejected(self):
        for cases in ([{'prior': 'input'}], [{'new': 'input'}, {'new': 'input'}]):
            output = self.root/'audit'
            if output.exists():
                import shutil
                shutil.rmtree(output)
            validator = mock.Mock(cases=cases)
            result, _, validator = self.execute(validator)
            self.assertEqual(result['summary']['status_counts'], {'ERROR': 4})
            validator.evaluate.assert_not_called()

    def test_new_protocol_stream_excludes_every_previous_declared_case(self):
        previous = audit._prior_cases('getDigitCount', self.protocol)
        observed = {json.dumps(case, sort_keys=True) for case in previous}
        cases = audit.function_cases('getDigitCount', random_cases=4096, seed=20261019)
        unseen = {json.dumps(case, sort_keys=True) for case in cases} - observed
        self.assertGreater(len(unseen), 0)
        for seed in (2048, 5741, 89123, 20261018):
            prior = audit.function_cases('getDigitCount', random_cases=4096, seed=seed)
            self.assertFalse(unseen & {json.dumps(case, sort_keys=True) for case in prior})


if __name__ == '__main__':
    unittest.main()
