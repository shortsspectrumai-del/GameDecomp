"""Escaped, standalone report with no remote assets or scripts."""
import html
import json
from pathlib import Path


def write_report(output: Path, report: dict) -> None:
    (output / 'report.json').write_text(json.dumps(report, indent=2, ensure_ascii=False, allow_nan=False), encoding='utf-8')
    sections = []
    for function in report['functions']:
        source = function.get('source') or 'Source not recovered for this function.'
        candidate = function.get('candidate')
        extra = ''
        lowered = function.get('compatibility')
        if lowered:
            extra += '<h4>SIMD compatibility — semantics unverified</h4><pre>' + html.escape(json.dumps(lowered, ensure_ascii=False, indent=2)) + '</pre>'
        if candidate:
            label = {'DISPROVED': 'behavior disproved', 'TESTED': 'tested on finite cases'}.get(
                candidate.get('semantic_status'), 'behavior unverified')
            extra += '<h4>AI candidate — ' + label + '</h4><pre>' + html.escape(candidate['source']) + '</pre>'
            if candidate.get('semantic_validation') or candidate.get('validation'):
                extra += '<pre>' + html.escape(json.dumps(candidate.get('semantic_validation', candidate.get('validation')), ensure_ascii=False, indent=2)) + '</pre>'
        prediction = function.get('metadata', {}).get('gnn_prediction')
        if prediction:
            extra += '<h4>GNN — semantic hypothesis</h4><pre>' + html.escape(json.dumps(prediction, ensure_ascii=False, indent=2)) + '</pre>'
        recovered = function.get('metadata', {}).get('type_recovery')
        if recovered:
            extra += '<h4>Types — structural evidence</h4><pre>' + html.escape(json.dumps(recovered, ensure_ascii=False, indent=2)) + '</pre>'
        sections.append('<details><summary>' + html.escape(function['name']) + ' — ' + html.escape(function['compilation']['status']) + '</summary>'
                        '<p>Semantic status: ' + html.escape(function['semantic_status']) + '</p>'
                        '<pre>' + html.escape(source) + '</pre>' + extra +
                        '<pre>' + html.escape('\n'.join(function['diagnostics'])) + '</pre></details>')
    summary = report['summary']
    document = '''<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>GameDecomp — report</title><style>
body{background:#10151e;color:#e4eaf2;font:16px system-ui;margin:0 auto;padding:32px;max-width:1200px}
h1{color:#8bd5ca}a{color:#9ac8ff}details{background:#1b2432;border:1px solid #334258;border-radius:8px;padding:16px;margin:12px 0}
summary{cursor:pointer;font-weight:600}pre{white-space:pre-wrap;overflow-wrap:anywhere;font:13px monospace;background:#111827;padding:16px}
.stats{display:flex;gap:24px;flex-wrap:wrap}.stats b{font-size:24px;display:block;color:#8bd5ca}p{line-height:1.6}
</style><h1>GameDecomp</h1><p>Evidence-based recovery report. Compilation and equivalence are separate outcomes.</p>'''
    document += '<div class="stats">' + ''.join(f'<div><b>{summary[key]}</b>{label}</div>' for key, label in
                  [('total', 'Functions'), ('recovered', 'Recovered'), ('compiled', 'Compilable'), ('proved', 'Proved equivalent')]) + '</div>'
    document += '<p>Backend: ' + html.escape(report['backend']) + '. Total time: ' + f'{report["timings"]["total_seconds"]:.3f}' + ' s.</p>'
    document += '<pre>' + html.escape('\n'.join(report['limitations'])) + '</pre>'
    if report.get('project'):
        document += '<p>CMake project included in the ZIP: project/manifest.json lists units and dependencies. Complete recovery is not established.</p>'
    if report.get('translation'):
        document += '<details><summary>Function translation — provenance, attempts and unverified semantics</summary><pre>'
        document += html.escape(json.dumps(report['translation'], ensure_ascii=False, indent=2)) + '</pre></details>'
    structural = report.get('type_recovery', {})
    if structural.get('types'):
        document += '<details><summary>Recovered types and classes: ' + str(len(structural['types'])) + '</summary><pre>'
        document += html.escape(json.dumps(structural, ensure_ascii=False, indent=2)) + '</pre></details>'
    document += ''.join(sections) + '</html>'
    (output / 'report.html').write_text(document, encoding='utf-8')
