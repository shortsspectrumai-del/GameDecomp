"""Keep machine semantics represented when references crowd a bounded prompt."""
import copy
import json
import unittest

from gamedecomp.ai_engine import recovery_context, recovery_issues
from gamedecomp.evidence import function_context, known_evidence_ids
from gamedecomp.models import Function, Instruction


def dense_context(*, reference_text='x' * 1024):
    instructions = [Instruction(index, 'ret' if index == 199 else
        'jz' if index % 40 == 39 else 'add', 'eax, 1') for index in range(200)]
    references = [dict(kind='string_reference', from_address=0, to_address=4096 + index,
        to_address_space='ram', operand_index=0, reference_type='DATA',
        value=reference_text, text_truncated=False,
        original_text_bytes=len(reference_text.encode())) for index in range(256)]
    function = Function('f', 'f', 0, instructions, metadata={
        'export_name':'f', 'return_bits':32, 'parameter_bits':[],
        'pcode':['INT_ADD ' + 'a' * 256 for _ in range(200)],
        'binary_references':references})
    return function_context(function, 'binary', {})


class ContextBalanceTests(unittest.TestCase):
    def test_dense_references_preserve_first_last_and_control_flow_evidence(self):
        compact, summary = recovery_context(dense_context(), {'status':'COMPILED'}, budget=16384)
        instructions = {fact['id'] for fact in compact['evidence'] if fact['kind']=='instruction'}
        self.assertIn('i:0', instructions)
        self.assertIn('i:c7', instructions)
        self.assertTrue(any(fact['mnemonic']=='jz' for fact in compact['evidence']
                            if fact['kind']=='instruction'))
        self.assertGreater(summary['reference_included'], 0)
        self.assertGreater(summary['pcode_included'], 0)

    def test_dense_references_preserve_pcode_endpoints_and_instruction_body(self):
        compact, _ = recovery_context(dense_context(), {'status':'COMPILED'}, budget=16384)
        identities = {fact['id'] for fact in compact['evidence']}
        self.assertIn('pcode:f:0', identities)
        self.assertIn('pcode:f:199', identities)
        self.assertIn('i:1', identities)

    def test_omitted_ids_remain_uncitable_and_counts_match_actual_selection(self):
        context = dense_context()
        compact, summary = recovery_context(context, {'status':'COMPILE_FAILED'}, budget=16384)
        known = known_evidence_ids(compact)
        selected = {fact['id'] for fact in compact['evidence']}
        omitted = {fact['id'] for fact in context['evidence']} - selected
        self.assertTrue(omitted)
        self.assertTrue(omitted.isdisjoint(known))
        self.assertTrue(recovery_issues({'types':[{'name':'Actor',
            'evidence_ids':[sorted(omitted)[0]]}]}, compact))
        for kind, key in [('instruction','instruction_included'), ('pcode','pcode_included'),
                          ('string_reference','reference_included')]:
            self.assertEqual(summary[key], sum(fact['kind']==kind for fact in compact['evidence']))
        self.assertEqual(summary['reference_omitted'], 256-summary['reference_included'])
        self.assertFalse(summary['complete'])

    def test_utf8_budget_abi_and_input_are_unchanged_and_selection_is_deterministic(self):
        context = dense_context(reference_text='\u00e8' * 512)
        before = copy.deepcopy(context)
        first, summary = recovery_context(context, {'status':'COMPILED'}, budget=16384)
        second, _ = recovery_context(context, {'status':'COMPILED'}, budget=16384)
        encoded = json.dumps(first, ensure_ascii=False, allow_nan=False, separators=(',', ':')).encode()
        self.assertLessEqual(len(encoded), 16384)
        self.assertEqual(len(encoded), summary['bytes'])
        self.assertEqual(first, second)
        self.assertEqual(context, before)
        self.assertEqual(first['validator_contract']['declaration'], 'uint32_t f(void);')
        self.assertEqual(first['evidence'][-1]['id'], 'signature:f')

    def test_empty_evidence_families_do_not_stop_remaining_selection(self):
        context = dense_context()
        context['evidence'] = [fact for fact in context['evidence']
                               if fact['kind'] in ('signature', 'instruction')]
        context['evidence'][-1]['metadata']['pcode'] = []
        compact, summary = recovery_context(context, {'status':'COMPILED'}, budget=65536)
        self.assertEqual(summary['instruction_included'], 200)
        self.assertEqual(summary['pcode_included'], 0)
        self.assertEqual(summary['reference_included'], 0)
        self.assertEqual(len({fact['id'] for fact in compact['evidence']}), len(compact['evidence']))

    def test_ample_budget_keeps_every_accepted_fact(self):
        context = dense_context()
        _, summary = recovery_context(context, {'status':'COMPILED'}, budget=262144)
        self.assertEqual(summary['instruction_included'], 200)
        self.assertEqual(summary['pcode_included'], 200)
        accepted = sum(fact['kind']=='string_reference' for fact in context['evidence'])
        self.assertEqual(summary['reference_included'], accepted)


if __name__ == '__main__':
    unittest.main()
