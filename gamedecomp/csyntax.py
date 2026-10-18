"""Conservative C/C++ lexical views for gates, not a complete language parser.

The original source is never rewritten for compilation. We account for C
trigraphs and line splicing before masking comments/literals for inspection.
Unsupported declarations are left to an explicit UNKNOWN ABI result.
"""
import re

_TRIGRAPHS = dict(zip('=/(\')!<>-', '#\\[^]|{}~'))
_IGNORED = re.compile(
    r'R"(?P<delimiter>[^ ()\\\t\r\n]{0,16})\(.*?\)(?P=delimiter)"'
    r'|/\*.*?\*/|//[^\r\n]*|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'', re.S)


def code_view(source):
    text = re.sub(r'\r\n|\n\r|\r', '\n', source)
    text = re.sub(r'\?\?([=/\(\)\'!<>-])', lambda m: _TRIGRAPHS[m[1]], text)
    # GCC/Clang also splice when horizontal whitespace follows the backslash.
    # Inspect the same tokens even when the compiler only warns about this extension.
    text = re.sub(r'\\[ \t\v\f]*\r?\n', '', text)
    text = _IGNORED.sub(lambda match: ''.join('\n' if c=='\n' else ' ' for c in match[0]), text)
    return text.replace('%:', '#').replace('<%', '{').replace('%>', '}').replace('<:', '[').replace(':>', ']')


def function_header(source, name):
    if not re.fullmatch(r'[A-Za-z_]\w*', name, flags=re.ASCII):
        return None
    clean = re.sub(r'^\s*#[^\n]*', '', code_view(source), flags=re.M)
    match = re.search(r'(?:^|[;}])\s*([^;{}]+?)\b'+re.escape(name)+r'\s*\(([^;{}]*)\)\s*\{', clean, flags=re.M)
    if not match:
        return None
    result = re.sub(r'\b(?:static|extern|inline)\b', '', match[1]).strip()
    return result, match[2]
