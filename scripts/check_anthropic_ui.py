"""Browser check of native Anthropic settings and a loopback Messages fixture.

Never contacts Anthropic or executes an uploaded binary. The provider fixture
returns the static source seed; it does not measure model reconstruction quality.
"""
import argparse
import json
from pathlib import Path
import secrets
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from scripts.check_studio_ui import local_url, wasm_addition


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--url', type=local_url, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve(); output.mkdir(parents=True, exist_ok=False)
    credential = secrets.token_urlsafe(32)
    requests, errors = [], []
    class Provider(BaseHTTPRequestHandler):
        def send(self, value):
            raw = json.dumps(value).encode()
            self.send_response(200); self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(raw))); self.end_headers(); self.wfile.write(raw)
        def do_GET(self):
            model = {'type': 'model', 'id': 'claude-local-fixture', 'max_input_tokens': 200000, 'max_tokens': 4096}
            self.send(model if self.path.endswith('/claude-local-fixture') else {'data': [model], 'has_more': False})
        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
            assert self.path == '/v1/messages' and self.headers.get('x-api-key') == credential
            assert self.headers.get('anthropic-version') == '2023-06-01'
            assert self.headers.get('Authorization') is None
            assert 'system' in body and 'response_format' not in body and 'reasoning_effort' not in body
            data = json.loads(body['messages'][0]['content'])
            requests.append({'path': self.path, 'max_tokens': body['max_tokens']})
            result = {'source': data['source']+'\n/* '+credential+' */',
                      'evidence_ids': [data['context']['evidence'][0]['id']], 'assumptions': []}
            self.send({'type': 'message', 'role': 'assistant', 'stop_reason': 'end_turn',
                'content': [{'type': 'text', 'text': json.dumps(result)}],
                'usage': {'input_tokens': 20, 'output_tokens': 10, 'cache_read_input_tokens': 5}})
        def log_message(self, *args):
            pass
    provider = ThreadingHTTPServer(('127.0.0.1', 0), Provider)
    thread = threading.Thread(target=provider.serve_forever, daemon=True); thread.start()
    from playwright.sync_api import sync_playwright, expect
    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)
            try:
                page = browser.new_page(viewport={'width': 3840, 'height': 2160})
                page.on('pageerror', lambda error: errors.append(str(error)))
                page.goto(args.url + '/#settings', wait_until='networkidle')
                version = page.request.get(args.url + '/api/bootstrap').json()['version']
                page.locator('#provider').select_option('anthropic')
                expect(page.locator('#llm-url')).to_have_value('https://api.anthropic.com/v1')
                expect(page.locator('#llm-api-format')).to_have_value('anthropic')
                expect(page.locator('#llm-api-format')).to_be_disabled()
                expect(page.locator('#llm-reasoning-effort')).to_be_disabled()
                expect(page.locator('#llm-json-mode')).to_have_value('prompt')
                page.screenshot(path=str(output/'anthropic-settings-4k.png'), full_page=True)
                page.locator('#provider').select_option('custom')
                page.locator('#llm-api-format').select_option('anthropic')
                page.locator('#llm-url').fill(f'http://127.0.0.1:{provider.server_port}/v1')
                page.locator('#llm-key').fill(credential)
                page.locator('#refresh-llm-models').click()
                expect(page.locator('#llm-connection-status')).to_contain_text('Server responded')
                page.locator('#llm-model').fill('claude-local-fixture')
                page.locator('[data-view="workspace"]').click()
                with page.expect_response(lambda r: '/api/upload?' in r.url and r.request.method == 'POST') as uploaded:
                    page.locator('#binary-file').set_input_files({'name': 'native.wasm',
                        'mimeType': 'application/wasm', 'buffer': wasm_addition('native_add')})
                assert uploaded.value.status == 201
                with page.expect_response(lambda r: r.url == args.url + '/api/jobs' and r.request.method == 'POST') as submitted:
                    page.locator('#analyze-button').click()
                assert submitted.value.status == 202
                job = submitted.value.json()['job']
                expect(page.locator('#report-link')).to_have_attribute('href', f'/api/jobs/{job["id"]}/report.html', timeout=60000)
                report = page.request.get(args.url + f'/api/jobs/{job["id"]}/report').json()
                assert requests and report['engine']['api_format'] == 'anthropic'
                assert report['summary']['ai_candidates'] == 1
                candidate = report['functions'][0]['candidate']
                preflight = report['functions'][0]['ai_context']['prompt_preflight']
                assert preflight['status'] == 'WITHIN_CONSERVATIVE_BUDGET'
                assert preflight['serialized_request_bytes'] <= preflight['conservative_budget_bytes']
                assert candidate['compilation']['status'] == 'COMPILED' and candidate['semantic_status'] == 'UNKNOWN'
                assert candidate['usage']['total_tokens'] == 35
                assert credential not in json.dumps(report) and '[REDACTED]' in candidate['source']
                assert not errors, errors
                (output/'verification.json').write_text(json.dumps({'status': 'PASS', 'version': version,
                    'job': job['id'], 'prompt_preflight': preflight,
                    'provider_requests': requests, 'candidate_compilation': 'COMPILED', 'semantic_status': 'UNKNOWN',
                    'usage': candidate['usage'], 'page_errors': errors,
                    'scope': 'Browser and native wire protocol against a local scripted provider; no Claude inference.'}, indent=2)+'\n')
                print('PASS: Anthropic preset, native catalog, Messages job, usage, validation and credential redaction')
            finally:
                browser.close()
    finally:
        provider.shutdown(); provider.server_close(); thread.join(3)


if __name__ == '__main__':
    main()
