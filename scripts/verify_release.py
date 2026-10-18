#!/usr/bin/env python3
"""Build and verify local wheel/sdist offline, without contacting providers."""
import argparse
import email.parser
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import tomllib
import venv
import zipfile

ROOT = Path(__file__).resolve().parents[1]


def run(command, *, cwd, timeout=120):
    result = subprocess.run([str(x) for x in command], cwd=cwd, capture_output=True,
                            text=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError(f'Command failed: {command[0]}\n{result.stdout[-4000:]}\n{result.stderr[-4000:]}')
    return result.stdout


def verify(output):
    output = output.resolve()
    if output.exists():
        raise ValueError('Output must be a new directory')
    output.mkdir(parents=True)
    artifacts = output / 'artifacts'
    artifacts.mkdir()
    expected = tomllib.loads((ROOT/'pyproject.toml').read_text())['project']['version']
    run([sys.executable, '-m', 'pip', 'wheel', '--no-index', '--no-deps', '--no-build-isolation',
         '--wheel-dir', artifacts, ROOT], cwd=ROOT)
    run([sys.executable, '-c', 'import sys,setuptools.build_meta as b;b.build_sdist(sys.argv[1])', artifacts], cwd=ROOT)
    wheels, archives = list(artifacts.glob('*.whl')), list(artifacts.glob('*.tar.gz'))
    if len(wheels) != 1 or len(archives) != 1:
        raise AssertionError('Expected exactly one wheel and one source archive')
    wheel, source = wheels[0], archives[0]
    with zipfile.ZipFile(wheel) as package:
        if package.testzip():
            raise AssertionError('Corrupt wheel')
        members = package.namelist()
        metadata_path = next(x for x in members if x.endswith('.dist-info/METADATA'))
        metadata = email.parser.Parser().parsestr(package.read(metadata_path).decode())
        if metadata['Version'] != expected or 'License :: Other/Proprietary License' not in metadata.get_all('Classifier', []):
            raise AssertionError('Version/license metadata mismatch')
        license_path = next(x for x in members if x.endswith('.dist-info/LICENSE') or x.endswith('.dist-info/licenses/LICENSE'))
        if package.read(license_path) != (ROOT/'LICENSE').read_bytes():
            raise AssertionError('License contents mismatch')
        source_files = [p for p in (ROOT/'gamedecomp').rglob('*') if p.is_file() and '__pycache__' not in p.parts]
        for path in source_files:
            relative = path.relative_to(ROOT).as_posix()
            if relative not in members or package.read(relative) != path.read_bytes():
                raise AssertionError('Missing or stale package file: '+relative)
        for path in members:
            if path.startswith(('tools/', 'demo-output/', 'tests/', '.gamedecomp-')) or path.endswith(('.sqlite', '.so', '.o')):
                raise AssertionError('Development artifact included: '+path)
    with tarfile.open(source) as archive:
        tar_members = archive.getmembers()
        paths = [Path(x.name) for x in tar_members]
        for member, path in zip(tar_members, paths):
            if path.is_absolute() or '..' in path.parts or not (member.isfile() or member.isdir()):
                raise AssertionError('Unsafe source archive member')
            if any(x in path.parts for x in ('tools', 'demo-output', '.gamedecomp-ui', '__pycache__')):
                raise AssertionError('Development artifact included in source archive')
        relative_paths = {Path(*x.parts[1:]).as_posix() for x in paths}
        required = {'LICENSE', 'SECURITY.md', 'CHANGELOG.md', 'THIRD_PARTY_NOTICES.md',
                    'tests/test_ghidra_compat.py', 'benchmarks/real_game.py', 'scripts/verify_release.py'}
        if not required <= relative_paths:
            raise AssertionError('Incomplete source archive: '+str(required-relative_paths))
    with tempfile.TemporaryDirectory(prefix='gamedecomp-release-') as temporary:
        root = Path(temporary)
        environment = root/'venv'
        venv.EnvBuilder(with_pip=True).create(environment)
        python = environment / ('Scripts/python.exe' if sys.platform == 'win32' else 'bin/python')
        run([python, '-m', 'pip', 'install', '--no-index', '--no-deps', wheel], cwd=root)
        version = run([python, '-I', '-c', 'import gamedecomp;print(gamedecomp.__version__)'], cwd=root).strip()
        if version != expected:
            raise AssertionError('Installed version mismatch')
        doctor = json.loads(run([python, '-I', '-m', 'gamedecomp', 'doctor', '--json'], cwd=root))
        fixture = root/'add.wasm'
        fixture.write_bytes(bytes.fromhex('0061736d0100000001070160027f7f017f030201000707010361646400000a09010700200020016a0b'))
        run([python, '-I', '-m', 'gamedecomp', 'analyze', fixture, '-o', root/'analysis',
             '--backend', 'wasm', '--cache', root/'cache.sqlite', '--gnn-model', 'builtin'], cwd=root)
        report = json.loads((root/'analysis/report.json').read_text())
        if report['summary']['compiled'] != 1 or report['summary']['gnn_predictions'] != 1 or report['project']['summary']['exported_units'] != 1:
            raise AssertionError('Installed pipeline/resources/export check failed')
        run([python, '-I', '-m', 'gamedecomp', 'demo', '-o', root/'demo', '--cases', '256'], cwd=root)
        demo = json.loads((root/'demo/verification.json').read_text())
        if (demo.get('summary', {}).get('mismatches') != 0 or demo['summary'].get('tested') != 4
                or demo['summary'].get('cases_checked', 0) < 1024):
            raise AssertionError('Installed demo differential failed')
        (output/'installed-report.json').write_text(json.dumps(report, indent=2)+'\n')
        (output/'installed-demo.json').write_text(json.dumps(demo, indent=2)+'\n')
    result = {'status': 'VERIFIED', 'version': expected, 'offline_install': True,
              'package_files_compared': len(source_files), 'wheel_files': len(members),
              'installed_summary': report['summary'], 'demo_summary': demo['summary'],
              'artifacts': [{'path': str(path), 'bytes': path.stat().st_size,
                             'sha256': hashlib.sha256(path.read_bytes()).hexdigest()} for path in (wheel, source)],
              'scope': 'Local packaging, fresh environment, bundled resources, WASM pipeline and trusted scalar demo; no universal equivalence claim.'}
    (output/'verification.json').write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps(result, indent=2))
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    verify(parser.parse_args().output)
