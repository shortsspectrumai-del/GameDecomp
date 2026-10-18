"""Byte-bounded feedback preserves complete Unicode validator counterexamples."""
import json
import unittest

from gamedecomp.llm import _string_list
from gamedecomp.semantic import normalize_validation, semantic_feedback


class UnicodeSemanticFeedbackTests(unittest.TestCase):
    source_hash = 'a' * 64

    def result(self, counterexample, scope='Trusted finite fixture comparison.'):
        return {'status': 'DISPROVED', 'candidate_source_sha256': self.source_hash,
                'scope': scope, 'cases_checked': 3, 'mismatches': 1,
                'counterexample': counterexample}

    def assert_feedback_preserves(self, result):
        normalized = normalize_validation(result, self.source_hash)
        self.assertEqual(normalized['status'], 'DISPROVED')
        messages = semantic_feedback(normalized)
        self.assertEqual(_string_list(messages, 'feedback'), messages)
        self.assertTrue(all(len(message.encode('utf-8')) <= 2048 for message in messages))
        chunks = [message.split(': ', 1)[1] for message in messages
                  if message.startswith('Counterexample JSON chunk ')]
        self.assertTrue(all(len(chunk.encode('utf-8')) <= 1600 for chunk in chunks))
        self.assertEqual([message.split(': ', 1)[0] for message in messages[1:]],
                         [f'Counterexample JSON chunk {index + 1}/{len(chunks)}'
                          for index in range(len(chunks))])
        expected = {key: normalized[key] for key in
                    ('scope', 'cases_checked', 'mismatches', 'counterexample')}
        serialized = json.dumps(expected, ensure_ascii=False, allow_nan=False, separators=(',', ':'))
        self.assertEqual(''.join(chunks), serialized)
        self.assertEqual(json.loads(''.join(chunks)), expected)

    def test_cjk_counterexample_and_scope_preserve_bytes_and_order(self):
        self.assert_feedback_preserves(self.result({'input': '漢字語' * 800}, scope='比較範囲' * 120))

    def test_emoji_counterexample_preserves_whole_codepoints(self):
        self.assert_feedback_preserves(self.result({'input': '🕹🎮🚀' * 650}))

    def test_mixed_json_escapes_are_reassembled_exactly(self):
        self.assert_feedback_preserves(self.result({'input': '漢🕹"\\\n\t\r\b\f' * 240,
                                                    'expected': ['a', 42, None, True]}))

    def test_exact_8kib_counterexample_limit_is_preserved_without_truncation(self):
        # The validator contract measures the default JSON serialization.
        overhead = len(json.dumps({'input': ''}, ensure_ascii=False).encode('utf-8'))
        budget = 8192 - overhead
        value = '🎮' * (budget // 4) + 'x' * (budget % 4)
        example = {'input': value}
        self.assertEqual(len(json.dumps(example, ensure_ascii=False).encode('utf-8')), 8192)
        self.assert_feedback_preserves(self.result(example))
        invalid = normalize_validation(self.result({'input': value + 'x'}), self.source_hash)
        self.assertEqual(invalid['status'], 'UNKNOWN')
        self.assertEqual(semantic_feedback(invalid), [])


if __name__ == '__main__':
    unittest.main()
