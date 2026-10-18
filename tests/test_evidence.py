import unittest

from gamedecomp.models import Function, Instruction


class EvidenceTests(unittest.TestCase):
    def context(self):
        from gamedecomp.evidence import function_context
        return function_context(Function('native:10', 'f', 16, [Instruction(16, 'ret', '')],
            metadata={'export_name': 'gd_f', 'parameter_bits': [32], 'return_bits': 32}), 'hash', {})

    def test_known_headers_allowed_but_arbitrary_directives_rejected(self):
        from gamedecomp.evidence import candidate_issues
        context = self.context()
        source = '#include <stdint.h>\nuint32_t gd_f(uint32_t p) { return p; }'
        self.assertEqual(candidate_issues(source, context, ['i:10']), [])
        self.assertTrue(candidate_issues(source.replace('<stdint.h>', '"/tmp/private"'), context, ['i:10']))

    def test_wrong_signature_and_fabricated_evidence_rejected(self):
        from gamedecomp.evidence import candidate_issues
        context = self.context()
        self.assertTrue(candidate_issues('uint64_t gd_f(uint32_t p) { return p; }', context, ['i:10']))
        self.assertTrue(candidate_issues('uint32_t gd_f(uint64_t p) { return p; }', context, ['i:10']))
        self.assertTrue(candidate_issues('uint32_t gd_f(uint32_t p) { return p; }', context, ['invented']))

    def test_nested_type_evidence_is_citable_but_unprovided_references_are_not(self):
        from gamedecomp.evidence import candidate_issues
        context = self.context()
        context['evidence'].insert(0, {'id': 'types:f', 'kind': 'type_metadata', 'data': {
            'signature': {'return_type': 'dwarf:absent',
                          'evidence': [{'id': 'dwarf:10:evidence', 'source': 'DWARF'}]}}})
        source = 'uint32_t gd_f(uint32_t p) { return p; }'
        self.assertEqual(candidate_issues(source, context, ['dwarf:10:evidence']), [])
        self.assertTrue(candidate_issues(source, context, ['dwarf:absent']))

    def test_cfg_dominators_natural_loops_and_ssa_dataflow(self):
        from gamedecomp.evidence import function_context, candidate_issues
        # Function with entry (0x10), loop header (0x20), diamond inside loop (0x30 / 0x40 -> 0x50),
        # loop exit (0x60), and an unreachable dead block after ret (0x70).
        instructions = [
            Instruction(0x10, 'xor', 'eax, eax'),          # b:10 defs rax (idiomatic zeroing), falls through to b:20
            Instruction(0x14, 'test', 'edi, edi'),         # b:10 uses rdi
            Instruction(0x18, 'jle', '0x60'),              # b:10 -> b:60 or b:20
            Instruction(0x20, 'cmp', 'esi, 0'),            # b:20 (loop header) uses rsi
            Instruction(0x24, 'je', '0x40'),               # b:20 -> b:40 or b:30
            Instruction(0x30, 'add', 'eax, edi'),          # b:30 uses/defs rax, uses rdi
            Instruction(0x34, 'jmp', '0x50'),              # b:30 -> b:50
            Instruction(0x40, 'sub', 'eax, 1'),            # b:40 uses/defs rax
            Instruction(0x50, 'dec', 'edi'),               # b:50 (diamond join & backedge source) uses/defs rdi
            Instruction(0x54, 'jne', '0x20'),              # b:50 -> b:20 (backedge) or b:60 (exit)
            Instruction(0x60, 'ret', ''),                  # b:60 uses rax, returns
            Instruction(0x70, 'mov', 'eax, 99'),           # b:70 unreachable after ret
            Instruction(0x74, 'ret', ''),
        ]
        fn = Function('native:10', 'loop_fn', 0x10, instructions,
                      metadata={'export_name': 'gd_loop_fn', 'parameter_bits': [32, 32], 'return_bits': 32})
        ctx = function_context(fn, 'hash', {})
        cfg = ctx['cfg']
        df = ctx['dataflow']
        self.assertEqual(cfg['entry'], 'b:10')
        self.assertIn('b:60', cfg['exits'])
        self.assertEqual(cfg['unreachable'], ['b:70'])
        self.assertTrue(cfg['is_reducible'])
        # Dominators: b:10 dominates b:20 and b:60; b:20 dominates b:30, b:40, b:50
        self.assertIsNone(cfg['idom']['b:10'])
        self.assertEqual(cfg['idom']['b:20'], 'b:10')
        self.assertEqual(cfg['idom']['b:30'], 'b:20')
        self.assertEqual(cfg['idom']['b:40'], 'b:20')
        self.assertEqual(cfg['idom']['b:50'], 'b:20')
        self.assertEqual(cfg['idom']['b:60'], 'b:10')
        # Post-dominators: b:50 post-dominates b:30 and b:40; b:60 post-dominates b:50 and b:10
        self.assertEqual(cfg['ipdom']['b:30'], 'b:50')
        self.assertEqual(cfg['ipdom']['b:40'], 'b:50')
        self.assertEqual(cfg['ipdom']['b:50'], 'b:60')
        # Dominance frontiers: b:30 and b:40 merge at b:50
        self.assertIn('b:50', cfg['dominance_frontiers']['b:30'])
        self.assertIn('b:50', cfg['dominance_frontiers']['b:40'])
        # Natural loop detection
        self.assertEqual(len(cfg['loops']), 1)
        loop = cfg['loops'][0]
        self.assertEqual(loop['header'], 'b:20')
        self.assertEqual(loop['backedges'], ['b:50'])
        self.assertEqual(set(loop['body']), {'b:20', 'b:30', 'b:40', 'b:50'})
        self.assertEqual(loop['exits'], ['b:50'])
        # Dataflow & SSA phi candidates: rdi and rsi are entry-live, rax is NOT entry-live (zeroed by xor eax, eax)
        self.assertEqual(df['entry_live_registers'], ['rdi', 'rsi'])
        self.assertIn('rax', df['phi_candidates'].get('b:50', []))
        self.assertIn('rax', df['phi_candidates'].get('b:20', []))
        self.assertIn('rdi', df['phi_candidates'].get('b:20', []))
        # Citable CFG and dataflow evidence IDs
        source = 'uint32_t gd_loop_fn(uint32_t a, uint32_t b) { return a + b; }'
        self.assertEqual(candidate_issues(source, ctx, ['cfg:native:10', 'dataflow:native:10']), [])

    def test_irreducible_cfg_is_detected(self):
        from gamedecomp.evidence import function_context
        # Classic irreducible 2-entry loop: b:10 branches to either b:20 or b:30, and b:20 <-> b:30 cycle.
        instructions = [
            Instruction(0x10, 'test', 'edi, edi'),
            Instruction(0x14, 'jne', '0x30'),
            Instruction(0x20, 'inc', 'eax'),
            Instruction(0x24, 'jmp', '0x30'),
            Instruction(0x30, 'dec', 'edi'),
            Instruction(0x34, 'jne', '0x20'),
            Instruction(0x40, 'ret', ''),
        ]
        fn = Function('native:10', 'irred', 0x10, instructions, metadata={'export_name': 'gd_irred'})
        ctx = function_context(fn, 'hash', {})
        self.assertFalse(ctx['cfg']['is_reducible'])

