import unittest


class ModelTests(unittest.TestCase):
    def test_analysis_roundtrip(self):
        from gamedecomp.models import Analysis, Function, Instruction
        original = Analysis('abc', 'ELF', 'x86_64', 'native', [
            Function('f1', 'add', 16, [Instruction(16, 'ret', '')])
        ])
        rebuilt = Analysis.from_dict(original.to_dict())
        self.assertEqual(rebuilt, original)
        self.assertIsInstance(rebuilt.functions[0].instructions[0], Instruction)

    def test_defaults_are_not_shared(self):
        from gamedecomp.models import Function
        first, second = Function('a', 'a', 0), Function('b', 'b', 1)
        first.diagnostics.append('uncertain')
        self.assertEqual(second.diagnostics, [])
