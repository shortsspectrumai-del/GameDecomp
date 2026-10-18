"""Bounded Studio history, with integrity checks rather than authenticity claims.

Checkpoints contain no requests, credentials, worker logs or raw errors. Hashes
detect changed artifacts; they do not authenticate files against the local user.
"""
import hashlib
import json
import os
import re
import stat
import tempfile
from datetime import datetime
from pathlib import Path

_ID = re.compile(r'[a-f0-9]{32}\Z')
_KINDS = {'analyze', 'demo', 'gnn_demo', 'train_gnn', 'translate'}
_STATES = {'QUEUED', 'RUNNING', 'SUCCEEDED', 'FAILED', 'CANCELLED'}
_MAX_FILES = 10000
_MAX_BYTES = 128 * 1024**2
_MAX_MANIFEST = 4 * 1024**2


def _owned(root, path):
    relative = path.relative_to(root)
    current = root
    for part in relative.parts:
        if part in ('.', '..'):
            raise ValueError('Invalid history path')
        current /= part
        if current.is_symlink():
            raise ValueError('History does not permit symbolic links')
    if not path.resolve().is_relative_to(root):
        raise ValueError('History path outside workspace')
    return path


def _read(path, maximum):
    if not stat.S_ISREG(path.stat().st_mode):
        raise ValueError('History requires regular files')
    if path.stat().st_size > maximum:
        raise ValueError('History file too large')
    with path.open('rb') as stream:
        data = stream.read(maximum + 1)
    if len(data) > maximum:
        raise ValueError('History file too large')
    return data


class WorkspaceLock:
    """One supervisor per workspace; advisory locks are released after crashes."""
    def __init__(self, root):
        self.stream = None
        path = _owned(root, root / '.studio.lock')
        descriptor = os.open(path, os.O_RDWR | os.O_CREAT | getattr(os, 'O_NOFOLLOW', 0), 0o600)
        stream = os.fdopen(descriptor, 'r+b')
        try:
            if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                raise RuntimeError('Workspace lock requires a regular file')
            if os.name == 'posix':
                import fcntl
                fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            elif os.name == 'nt':
                import msvcrt
                if os.fstat(stream.fileno()).st_size == 0:
                    stream.write(b'\0')
                    stream.flush()
                stream.seek(0)
                msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                raise RuntimeError('Workspace locking unsupported on this platform')
        except (OSError, RuntimeError) as error:
            stream.close()
            raise RuntimeError('Studio workspace is already in use or locking is unavailable') from error
        self.stream = stream

    def close(self):
        if self.stream is not None:
            self.stream.close()
            self.stream = None


class SessionStore:
    def __init__(self, root):
        self.root = root

    def directory(self, job_id):
        if not isinstance(job_id, str) or not _ID.fullmatch(job_id):
            raise ValueError('Invalid history job identity')
        return _owned(self.root, self.root / 'jobs' / job_id)

    def _metadata(self, value):
        if not isinstance(value, dict):
            raise ValueError('Invalid history metadata')
        job_id = value.get('id')
        self.directory(job_id)
        if value.get('kind') not in _KINDS or value.get('status') not in _STATES:
            raise ValueError('Invalid history metadata')
        result = {key: value[key] for key in ('id', 'kind', 'status')}
        for key in ('created_at', 'updated_at'):
            stamp = value.get(key)
            if not isinstance(stamp, str) or len(stamp) > 64 or datetime.fromisoformat(stamp).tzinfo is None:
                raise ValueError('Invalid history timestamp')
            result[key] = stamp
        return result

    def checkpoint(self, job, inventory=None):
        data = self._metadata(job)
        data['version'] = 1
        if job['status'] == 'SUCCEEDED':
            if inventory is None:
                raise ValueError('Successful history requires an artifact inventory')
            data['inventory'] = inventory
        directory = self.directory(job['id'])
        target = _owned(self.root, directory / 'session.json')
        raw = json.dumps(data, ensure_ascii=True, allow_nan=False, separators=(',', ':')).encode()
        if len(raw) > _MAX_MANIFEST:
            raise ValueError('History manifest too large')
        descriptor, name = tempfile.mkstemp(prefix='.session-', suffix='.tmp', dir=directory)
        try:
            with os.fdopen(descriptor, 'wb') as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
            _owned(self.root, target)
            os.replace(name, target)
        finally:
            if os.path.exists(name):
                os.unlink(name)

    def seal(self, job):
        """Inventory exactly the export tree plus the supervisor result."""
        directory = self.directory(job['id'])
        artifact_root = _owned(self.root, directory / ('model' if job['kind'] in ('train_gnn', 'gnn_demo') else 'results'))
        if not artifact_root.is_dir():
            raise ValueError('History artifacts unavailable')
        paths = [directory / 'result.json']
        pending = [artifact_root]
        visited = 0
        while pending:
            current = pending.pop()
            with os.scandir(current) as entries:
                for entry in entries:
                    visited += 1
                    if visited > _MAX_FILES:
                        raise ValueError('History artifact count exceeds 10000')
                    path = _owned(self.root, Path(entry.path))
                    if entry.is_dir(follow_symlinks=False):
                        pending.append(path)
                    elif entry.is_file(follow_symlinks=False):
                        paths.append(path)
                    else:
                        raise ValueError('History requires regular artifacts')
        inventory, total, name_bytes = {}, 0, 0
        for path in sorted(paths):
            path = _owned(self.root, path)
            relative = path.relative_to(directory).as_posix()
            name_bytes += len(relative.encode('utf-8'))
            if len(relative) > 1024 or name_bytes > 1024**2:
                raise ValueError('History artifact paths too large')
            maximum = min(16 * 1024**2 if relative == 'result.json' else _MAX_BYTES, _MAX_BYTES - total)
            raw = _read(path, maximum)
            total += len(raw)
            if len(inventory) >= _MAX_FILES:
                raise ValueError('History artifact count exceeds 10000')
            inventory[relative] = {'size': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}
        return inventory

    def verify(self, job, inventory):
        if not isinstance(inventory, dict) or not inventory or len(inventory) > _MAX_FILES:
            raise ValueError('History artifact inventory unavailable')
        if self.seal(job) != inventory:
            raise ValueError('History artifacts changed or are unavailable')

    def result(self, job, inventory):
        self.verify(job, inventory)
        raw = _read(_owned(self.root, self.directory(job['id']) / 'result.json'), 16 * 1024**2)
        if hashlib.sha256(raw).hexdigest() != inventory['result.json']['sha256']:
            raise ValueError('History result changed')
        result = json.loads(raw, parse_constant=lambda value: (_ for _ in ()).throw(ValueError('Invalid history JSON')))
        if not isinstance(result, dict) or set(result) - {'summary', 'metrics', 'report'}:
            raise ValueError('Invalid history result')
        return result

    def restore(self):
        jobs, skipped = [], 0
        jobs_root = _owned(self.root, self.root / 'jobs')
        with os.scandir(jobs_root) as entries:
            for number, entry in enumerate(entries):
                if number >= 10000:
                    skipped += 1
                    break
                if not _ID.fullmatch(entry.name):
                    continue
                try:
                    directory = self.directory(entry.name)
                    manifest = _owned(self.root, directory / 'session.json')
                    if not manifest.exists():
                        continue
                    if len(jobs) >= 1000:
                        skipped += 1
                        continue
                    data = json.loads(_read(manifest, _MAX_MANIFEST))
                    if data.get('version') != 1 or data.get('id') != entry.name:
                        raise ValueError('Invalid history version or identity')
                    job = self._metadata(data)
                    job.update(restored=True, logs=[])
                    if job['status'] in ('QUEUED', 'RUNNING'):
                        job.update(status='FAILED', phase='Interrupted', error='Studio stopped before completion; no job was restarted')
                    elif job['status'] == 'SUCCEEDED':
                        try:
                            inventory = data.get('inventory')
                            job['result'] = self.result(job, inventory)
                            job['inventory'] = inventory
                            job.update(phase='Restored', report_url=f'/api/jobs/{job["id"]}/report', export_url=f'/api/jobs/{job["id"]}/export')
                        except (OSError, ValueError, KeyError, RecursionError):
                            job.pop('result', None)
                            job.update(status='FAILED', phase='History unavailable', error='Stored artifacts changed or are unavailable')
                            skipped += 1
                    else:
                        job['phase'] = 'Restored'
                    jobs.append(job)
                except (OSError, ValueError, KeyError, TypeError, AttributeError, RecursionError):
                    skipped += 1
        jobs.sort(key=lambda job: (job['created_at'], job['id']))
        return jobs, skipped
