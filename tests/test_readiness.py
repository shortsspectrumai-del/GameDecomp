"""Actionable readiness must not confuse installed tools with semantic accuracy."""
import unittest
from gamedecomp.readiness import readiness


class ReadinessTests(unittest.TestCase):
    def test_missing_backends_offer_actions_without_claiming_ready(self):
        result = readiness({'backends': {}, 'tools': {}})
        self.assertEqual(result['status'], 'NEEDS_SETUP')
        self.assertTrue(all(item['next_step'] for item in result['checks']))
        self.assertEqual(result['execution'], 'NOT_PERFORMED')
        self.assertEqual(result['model_connection'], 'NOT_TESTED')

    def test_ready_static_workflow_does_not_claim_proof_or_model_connection(self):
        result = readiness({'backends': {'wasm': {'available': True}}, 'tools': {'gcc': '/usr/bin/gcc'}})
        self.assertEqual(result['status'], 'STATIC_READY')
        self.assertEqual(result['semantic_equivalence'], 'NOT_PROVED')
        self.assertEqual(result['model_connection'], 'NOT_TESTED')
        self.assertEqual(next(x for x in result['checks'] if x['id']=='compilation')['status'], 'AVAILABLE')

    def test_known_tools_do_not_imply_other_backends_available(self):
        result = readiness({'backends': {'native': {'available': True}}, 'tools': {'gcc': '/usr/bin/gcc'}})
        self.assertEqual(next(x for x in result['checks'] if x['id']=='ghidra')['status'], 'UNAVAILABLE')
        self.assertNotIn('/usr/bin/gcc', str(result))
