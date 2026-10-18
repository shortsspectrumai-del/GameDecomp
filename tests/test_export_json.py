"""Exercise the exporter's actual pure Java JSON encoder with malformed UTF-16."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


class ExportJSONTests(unittest.TestCase):
    def test_utf16_code_units_survive_utf8_json_transport_without_replacement(self):
        home = os.environ.get('JAVA_HOME')
        javac = (shutil.which(str(Path(home) / 'bin/javac')) if home else None) or shutil.which('javac')
        java = shutil.which(str(Path(javac).with_name('java'))) if javac else None
        if not java:
            self.skipTest('JDK required')
        source = (Path(__file__).resolve().parents[1] /
                  'gamedecomp/ghidra_scripts/ExportGameDecomp.java').read_text()
        # Compile the real dependency-free encoder in a trusted test harness;
        # Ghidra and recovered input code are never loaded by this harness.
        start = source.index('    private String q(String s) {')
        end = source.index('\n    private String utf8Prefix', start)
        method = source[start:end]
        harness = ('public final class EncodeFixture {\n' + method + '\n'
            'public static void main(String[] args) {\n'
            'String text = new String(new char[] {65, (char)0xd800, 66, (char)0xd83d, (char)0xde80, 10, 34, 92});\n'
            'System.out.print(new EncodeFixture().q(text));\n}\n}\n')
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'EncodeFixture.java'
            path.write_text(harness)
            subprocess.run([javac, '-proc:none', str(path)], check=True, capture_output=True, timeout=20)
            raw = subprocess.check_output([java, '-cp', temporary, 'EncodeFixture'], timeout=20)
        self.assertEqual(json.loads(raw), 'A\ud800B\U0001f680\n"\\')
