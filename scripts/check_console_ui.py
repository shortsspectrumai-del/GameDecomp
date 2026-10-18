"""Verify console profile selection and a real static NES job in local Studio.

Requires a running Studio with Ghidra and Playwright/Chromium. No provider calls
or ROM execution are performed. Only synthetic CPU instructions are uploaded.
"""
import argparse
import json
from pathlib import Path

from gamedecomp.console_support import CONSOLE_PROFILES
from scripts.check_studio_ui import local_url
from tests.test_nes_format import nrom_image


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--url', type=local_url, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    from playwright.sync_api import sync_playwright, expect
    errors = []
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        try:
            page = browser.new_page(viewport={'width': 3840, 'height': 2160})
            page.on('pageerror', lambda error: errors.append(str(error)))
            page.on('console', lambda message: errors.append(message.text) if message.type == 'error' else None)
            page.goto(args.url + '/#workspace', wait_until='networkidle')
            profiles = page.locator('#console-profile option').evaluate_all('(items) => items.map(item => item.value)')
            assert set(profiles) == {'', *CONSOLE_PROFILES}, profiles
            page.locator('#console-profile').select_option('nes-nrom-6502')
            image = bytearray(nrom_image(reset=0x8000)); image[16:19] = bytes.fromhex('a92a60')
            with page.expect_response(lambda r: '/api/upload?' in r.url and r.request.method == 'POST') as uploaded:
                page.locator('#binary-file').set_input_files({'name': 'synthetic-nrom.nes',
                    'mimeType': 'application/octet-stream', 'buffer': bytes(image)})
            assert uploaded.value.status == 201
            expect(page.locator('#analyze-button')).to_be_enabled()
            page.locator('#console-profile').select_option('')
            expect(page.locator('#analyze-button')).to_be_disabled()
            page.locator('#console-profile').select_option('nes-nrom-6502')
            page.locator('#timeout').fill('120')
            with page.expect_response(lambda r: r.url == args.url + '/api/jobs' and r.request.method == 'POST') as submitted:
                page.locator('#analyze-button').click()
            assert submitted.value.status == 202
            job = submitted.value.json()['job']
            expect(page.locator('#report-link')).to_have_attribute('href', f'/api/jobs/{job["id"]}/report.html', timeout=120000)
            response = page.request.get(args.url + f'/api/jobs/{job["id"]}/report')
            assert response.status == 200
            report = response.json()
            assert report['input']['format'] == 'NES'
            assert report['functions'] and all(f['compilation']['status'] == 'UNKNOWN' for f in report['functions'])
            assert not report['metadata']['console_import']['executable_run']
            job_result = page.request.get(args.url + f'/api/jobs/{job["id"]}').json()['job']
            assert job_result['status'] == 'SUCCEEDED'
            assert job_result['progress']['compiled_units'] == 0
            assert job_result['progress']['tested_units'] == 0
            assert job_result['progress']['unknown_units'] > 0
            page.screenshot(path=str(output / 'console-results-4k.png'), full_page=True)
            assert not errors, errors
            (output / 'verification.json').write_text(json.dumps({'status': 'PASS', 'profiles': profiles,
                'job': job_result['id'], 'progress': job_result['progress'], 'page_errors': errors,
                'scope': 'Real Ghidra static import of synthetic NES fixture; no semantic equivalence test or LLM call.'}, indent=2) + '\n')
            print('PASS: console profiles, mismatch guard, real NES job and UNKNOWN counters')
        finally:
            browser.close()


if __name__ == '__main__':
    main()
