import unittest
from unittest.mock import patch


class ProviderTests(unittest.TestCase):
    def test_anthropic_preset_uses_native_messages_and_private_environment_key(self):
        from gamedecomp.cli import build_parser, _config
        args = build_parser().parse_args(['analyze', 'input.so', '-o', 'out',
                                         '--llm-provider', 'anthropic', '--llm-model', 'chosen-claude'])
        with patch.dict('os.environ', {'ANTHROPIC_API_KEY': 'unit-anthropic-key'}, clear=True):
            config = _config(args)
        self.assertEqual(config.llm_endpoint, 'https://api.anthropic.com/v1')
        self.assertEqual(config.llm_api_format, 'anthropic')
        self.assertEqual(config.llm_api_key, 'unit-anthropic-key')
        self.assertNotIn('unit-anthropic-key', repr(config))

    def test_custom_native_format_is_explicit_and_presets_cannot_be_overridden(self):
        from gamedecomp.cli import build_parser, _config
        custom = build_parser().parse_args(['analyze', 'input.so', '-o', 'out',
            '--llm-url', 'http://localhost:8000/v1/messages', '--llm-model', 'local',
            '--llm-api-format', 'anthropic'])
        self.assertEqual(_config(custom).llm_api_format, 'anthropic')
        for provider, selected in (('anthropic', 'openai'), ('deepseek', 'anthropic')):
            args = build_parser().parse_args(['analyze', 'input.so', '-o', 'out',
                '--llm-provider', provider, '--llm-model', 'example', '--llm-api-format', selected])
            with self.assertRaisesRegex(ValueError, 'API format'):
                _config(args)

    def test_anthropic_configuration_rejects_unsupported_reasoning_and_temperature(self):
        from gamedecomp.pipeline import AnalysisConfig
        for options in ({'llm_api_format': 'invalid'},
                        {'llm_api_format': 'anthropic', 'llm_reasoning_effort': 'high'},
                        {'llm_api_format': 'anthropic', 'llm_temperature': 1.5}):
            with self.subTest(options=options), self.assertRaises(ValueError):
                AnalysisConfig(**options)

    def test_studio_worker_passes_native_format_to_analysis_without_serializing_key(self):
        import io
        import tempfile
        from pathlib import Path
        from gamedecomp.ui_worker import run
        captured = []
        def analyze(source, destination, config, **kwargs):
            captured.append(config)
            return {'summary': {'functions': 1}}
        with tempfile.TemporaryDirectory() as directory, patch('gamedecomp.pipeline.run_analysis', side_effect=analyze), patch('sys.stdout', new_callable=io.StringIO) as output:
            run({'kind': 'analyze', 'directory': directory, 'source': str(Path(directory) / 'input'),
                 'options': {'llm': {'url': 'https://api.anthropic.com/v1', 'model': 'claude-test', 'api_format': 'anthropic'}}})
        self.assertEqual(captured[0].llm_api_format, 'anthropic')
        self.assertNotIn('claude-test', output.getvalue())

    def test_deepseek_preset_keeps_user_model_and_reads_provider_key(self):
        from gamedecomp.cli import build_parser, _config
        args = build_parser().parse_args(['analyze', 'input.so', '-o', 'out',
                                         '--llm-provider', 'deepseek', '--llm-model', 'chosen-model'])
        with patch.dict('os.environ', {'DEEPSEEK_API_KEY': 'unit-test-key'}, clear=True):
            config = _config(args)
        self.assertEqual(config.llm_endpoint, 'https://api.deepseek.com')
        self.assertEqual(config.llm_model, 'chosen-model')
        self.assertEqual(config.llm_api_key, 'unit-test-key')

    def test_custom_provider_and_interactive_key_are_supported_without_storage(self):
        from gamedecomp.cli import build_parser, _config
        args = build_parser().parse_args(['analyze', 'input.so', '-o', 'out',
                                         '--llm-url', 'http://localhost:8000/v1',
                                         '--llm-model', 'my-local-model', '--llm-key-prompt'])
        with patch('gamedecomp.cli.getpass.getpass', return_value='typed-key'):
            config = _config(args)
        self.assertEqual(config.llm_api_key, 'typed-key')
        self.assertEqual(config.llm_endpoint, 'http://localhost:8000/v1')

    def test_key_prompt_without_model_does_not_request_a_secret(self):
        from gamedecomp.cli import build_parser, _config
        args = build_parser().parse_args(['analyze', 'input.so', '-o', 'out', '--llm-key-prompt'])
        with patch('gamedecomp.cli.getpass.getpass') as prompt:
            with self.assertRaises(ValueError):
                _config(args)
            prompt.assert_not_called()

    def test_provider_requires_a_model_and_url_cannot_override_preset(self):
        from gamedecomp.cli import build_parser, _config
        for options in (['--llm-provider', 'deepseek'],
                        ['--llm-provider', 'deepseek', '--llm-model', 'x',
                         '--llm-url', 'http://other.example/v1']):
            args = build_parser().parse_args(['analyze', 'input.so', '-o', 'out', *options])
            with self.assertRaises(ValueError):
                _config(args)
