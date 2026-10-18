"""Explicit, bounded model discovery. No inference requests or credential storage."""
import os
import time
import urllib.error
import urllib.parse
import urllib.request

from gamedecomp.llm import LLMClient, _NoRedirect, _decode_json


LOOPBACK = frozenset(('localhost', '127.0.0.1', '::1'))
LOCAL_PROVIDERS = frozenset(('ollama', 'lmstudio'))


def resolve_api_format(value):
    """Choose a native wire protocol without guessing from model names."""
    from gamedecomp.cli import LLM_PROVIDERS
    if not isinstance(value, dict):
        raise ValueError('Invalid model connection')
    provider = value.get('provider', 'custom')
    if not isinstance(provider, str) or provider not in (*LLM_PROVIDERS, 'custom'):
        raise ValueError('Unknown model provider')
    expected = 'anthropic' if provider == 'anthropic' else 'openai'
    api_format = value.get('api_format', expected)
    if not isinstance(api_format, str) or api_format not in ('openai', 'anthropic'):
        raise ValueError('API format must be openai or anthropic')
    if provider != 'custom' and api_format != expected:
        raise ValueError('API format does not match the selected provider')
    return api_format


def resolve_connection(value):
    from gamedecomp.cli import LLM_PROVIDERS
    if not isinstance(value, dict):
        raise ValueError('Invalid model connection')
    api_format = resolve_api_format(value)
    provider = value.get('provider', 'custom')
    if provider not in (*LLM_PROVIDERS, 'custom'):
        raise ValueError('Unknown model provider')
    endpoint, environment = LLM_PROVIDERS.get(provider, (value.get('url'), 'GAMEDECOMP_API_KEY'))
    if provider in LOCAL_PROVIDERS:
        endpoint = value.get('url') or endpoint
        if not isinstance(endpoint, str) or urllib.parse.urlsplit(endpoint).hostname not in LOOPBACK:
            raise ValueError('Local presets require a loopback endpoint; choose Custom for a remote server')
    if not isinstance(endpoint, str) or len(endpoint) > 2048:
        raise ValueError('Invalid API endpoint')
    key = value.get('key') or os.environ.get(environment)
    if key is not None and (not isinstance(key, str) or len(key) > 4096 or '\n' in key or '\r' in key):
        raise ValueError('Invalid API key')
    if provider in ('deepseek', 'openai', 'anthropic') and not key:
        raise ValueError('An API key is required for this provider')
    if key and key in endpoint:
        raise ValueError('The API key cannot appear in the endpoint')
    # The shared client rejects userinfo, queries and unsafe transport options.
    client = LLMClient(endpoint, '__model_catalog__', api_key=key, timeout=5, api_format=api_format)
    return client.endpoint, key


def fetch_models(value):
    api_format = resolve_api_format(value)
    endpoint, key = resolve_connection(value)
    location = 'LOCAL' if urllib.parse.urlsplit(endpoint).hostname in LOOPBACK else 'REMOTE'
    unavailable = {'status': 'UNAVAILABLE', 'models': [], 'location': location}
    headers = {'Accept': 'application/json'}
    if api_format == 'anthropic':
        headers['anthropic-version'] = '2023-06-01'
        if key:
            headers['X-Api-Key'] = key
    elif key:
        headers['Authorization'] = 'Bearer ' + key
    suffix = '/messages' if api_format == 'anthropic' else '/chat/completions'
    request = urllib.request.Request(endpoint.removesuffix(suffix) + '/models', headers=headers)
    try:
        deadline = time.monotonic() + 5
        with urllib.request.build_opener(_NoRedirect()).open(request, timeout=5) as response:
            raw = bytearray()
            while len(raw) <= 1048576:
                if time.monotonic() >= deadline:
                    return unavailable
                chunk = response.read1(min(65536, 1048577-len(raw)))
                if not chunk:
                    break
                raw.extend(chunk)
        if len(raw) > 1048576:
            return unavailable
        data = _decode_json(raw)
        if not isinstance(data, dict) or not isinstance(data.get('data'), list):
            return unavailable
        models, seen = [], set()
        for entry in data['data']:
            if not isinstance(entry, dict):
                continue
            name = entry.get('id')
            if (not isinstance(name, str) or not name.strip() or len(name.encode()) > 256
                    or any(ord(char) < 32 for char in name) or name in seen or key and key in name):
                continue
            record = {'id': name}
            fields = (('context_window', 'max_input_tokens'), ('max_output_tokens', 'max_tokens')) if api_format == 'anthropic' else (
                ('context_window', 'context_window'), ('max_output_tokens', 'max_output_tokens'))
            for field, provider_field in fields:
                limit = entry.get(provider_field)
                if type(limit) is int and 256 <= limit <= 100000000:
                    record[field] = limit
            models.append(record); seen.add(name)
            if len(models) == 128:
                break
        return {'status': 'AVAILABLE', 'models': models, 'location': location,
                'truncated': data.get('has_more') is True or len(data['data']) > 128}
    except urllib.error.HTTPError as error:
        error.close()
    except Exception:
        # Never reflect provider responses, exception text, endpoints or keys.
        pass
    return unavailable
