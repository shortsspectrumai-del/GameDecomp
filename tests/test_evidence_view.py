"""Bounded evidence delivery preserves identity and makes omissions explicit."""
import json
import unittest
from gamedecomp.evidence_view import evidence_view


class EvidenceViewTests(unittest.TestCase):
    def report(self):
        return {'snapshot_id':'snapshot', 'input':{'sha256':'a'*64}, 'summary':{'total':3},
                'functions':[{'id':str(i),'name':'fn'+str(i), 'semantic_status':'UNKNOWN',
                              'compilation':{'status':'COMPILED'}, 'diagnostics':['missing memory'],
                              'source':'x'*200000} for i in range(3)]}

    def test_stable_pages_preserve_identity_and_do_not_deliver_source(self):
        report=self.report(); first=evidence_view(report,offset=0,limit=2); second=evidence_view(report,offset=2,limit=2)
        self.assertEqual(first['next_offset'],2);self.assertIsNone(second['next_offset'])
        self.assertEqual(first['binary_sha256'],'a'*64)
        self.assertEqual(first['snapshot_id'],second['snapshot_id'])
        self.assertEqual([x['id'] for x in first['items']+second['items']],['0','1','2'])
        self.assertNotIn('source',first['items'][0]);self.assertEqual(first['omitted_units'],1)
        self.assertEqual(first['items'][0]['next_step'],'Behavior remains unverified; use a trusted validator where supported.')
        self.assertLess(len(json.dumps(first).encode()),65536)

    def test_disproved_candidate_surfaces_even_when_it_compiles(self):
        report=self.report();report['functions'][0]['candidate']={'semantic_status':'DISPROVED','compilation':{'status':'COMPILED'}}
        result=evidence_view(report,limit=1)['items'][0]
        self.assertEqual(result['candidate_status'],'DISPROVED')
        self.assertIn('counterexample',result['next_step'])

    def test_invalid_offsets_limits_and_booleans_are_rejected(self):
        for kwargs in ({'offset':-1},{'offset':True},{'limit':0},{'limit':129},{'limit':True}):
            with self.subTest(kwargs=kwargs),self.assertRaises(ValueError):evidence_view(self.report(),**kwargs)

    def test_large_untrusted_labels_are_bounded_and_omissions_explicit(self):
        report=self.report();report['functions'][0]['name']='é'*10000
        report['functions'][0]['diagnostics']=['é'*10000]*100
        result=evidence_view(report,limit=1)
        self.assertTrue(result['items'][0]['details_omitted'])
        self.assertLess(len(json.dumps(result).encode()),65536)
        self.assertEqual(report['functions'][0]['name'],'é'*10000)
