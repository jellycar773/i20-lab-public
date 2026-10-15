#!/usr/bin/env python3
"""Check or export ONLY the reviewed public snapshot; never copy Git history.

This is an offline release gate, not a comprehensive secret-detection product.
It does not authenticate authors or audit the private repository's history.
"""
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import zipfile

PUBLIC_FILES = frozenset({
    '.gitignore', 'README.md', 'SECURITY.md', 'PROVENANCE.md', 'NOTICE.md',
    'docs/ARCHITECTURE.md', 'lab/__init__.py', 'lab/taskctl.py',
    'examples/task.json', 'examples/context/lemma.txt',
    'tests/test_taskctl.py', 'tests/test_release.py', 'release.py', 'MANIFEST.json',
})
MAX_FILE = 256_000
MAX_TOTAL = 2_000_000
PATTERNS = {
    'private-key': re.compile(r'-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----'),
    'github-token': re.compile(r'(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,})'),
    'provider-key': re.compile(r'\bsk-(?:proj-|svcacct-|ant-)?[A-Za-z0-9_-]{24,}'),
    'aws-key': re.compile(r'\b(?:AKIA|ASIA)[A-Z0-9]{16}\b'),
    'bearer-literal': re.compile(r'(?i)Bearer[ \t]+[A-Za-z0-9_.~+/-]{32,}'),
    'jwt-literal': re.compile(r'eyJ[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{12,}'),
    'credential-assignment': re.compile(
        r'''(?i)(?:api[_-]?key|access[_-]?token|refresh[_-]?token|client[_-]?secret|password|passwd)\s*["']?\s*[:=]\s*["'][A-Za-z0-9_./+\-=]{12,}["']'''),
    'url-credentials': re.compile(r'https?://[^\s/:]+:[^\s/@]+@'),
    'url-secret-query': re.compile(r'(?i)[?&](?:token|key|access_token|auth)=[A-Za-z0-9_-]{12,}'),
    'email-address': re.compile(r'\b[A-Za-z0-9.!#$%&\x27*+/=?^_`{|}~-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+\b'),
    'personal-home-path': re.compile(r'/(?:home|Users)/[A-Za-z0-9_.-]+/'),
}
IPV4 = re.compile(r'(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])')


class ReleaseError(ValueError):
    """Fail-closed publication refusal; messages never include matched secrets."""


def findings(text: str) -> list[dict[str, str | int]]:
    hits: list[dict[str, str | int]] = []
    for rule, pattern in PATTERNS.items():
        for match in pattern.finditer(text):
            hits.append({'rule': rule, 'line': text.count('\n', 0, match.start()) + 1})
    for match in IPV4.finditer(text):
        try:
            address = ipaddress.ip_address(match.group())
        except ValueError:
            continue
        if address.is_global:
            hits.append({'rule': 'public-ip-address', 'line': text.count('\n', 0, match.start()) + 1})
    return hits


def safe_read(root: Path, relative: str) -> bytes:
    parts = PurePosixPath(relative).parts
    if (relative not in PUBLIC_FILES or not parts or relative != '/'.join(parts)
            or any(p in {'', '.', '..', '.git'} for p in parts)):
        raise ReleaseError('Path is not on the exact public allowlist')
    if not hasattr(os, 'O_NOFOLLOW'):
        raise ReleaseError('Secure snapshot reads require a POSIX platform')
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    fd = os.open(root, flags)
    try:
        for part in parts[:-1]:
            child = os.open(part, flags, dir_fd=fd)
            os.close(fd)
            fd = child
        file_fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
        with os.fdopen(file_fd, 'rb') as stream:
            before = os.fstat(stream.fileno())
            if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > MAX_FILE:
                raise ReleaseError('Unsafe file type, link count, or size')
            data = stream.read(MAX_FILE + 1)
            after = os.fstat(stream.fileno())
        fields = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
        if len(data) > MAX_FILE or any(getattr(before, f) != getattr(after, f) for f in fields):
            raise ReleaseError('Oversized file or concurrent modification')
        return data
    finally:
        os.close(fd)


def inventory(root: Path) -> set[str]:
    """Reject unexpected payloads; do not descend into Git metadata or caches."""
    found: set[str] = set()
    for directory, dirs, names in os.walk(root, followlinks=False):
        parent = Path(directory)
        for name in list(dirs):
            path = parent / name
            rel = path.relative_to(root).as_posix()
            if path.is_symlink():
                raise ReleaseError('Symlink directory refused')
            if rel == '.git' or name == '__pycache__':
                dirs.remove(name)
                continue
            if not any(p.startswith(rel + '/') for p in PUBLIC_FILES):
                raise ReleaseError('Unexpected directory outside public allowlist')
        for name in names:
            rel = (parent / name).relative_to(root).as_posix()
            if rel == '.git':
                # Worktree metadata is deliberately excluded and never read.
                continue
            if rel not in PUBLIC_FILES:
                raise ReleaseError('Unexpected file outside public allowlist')
            found.add(rel)
    return found


def verify(root: Path) -> dict[str, bytes]:
    if root.is_symlink() or not root.is_dir():
        raise ReleaseError('Snapshot root must be a real directory')
    if inventory(root) != PUBLIC_FILES:
        raise ReleaseError('Public snapshot has missing or unexpected files')
    payload = {name: safe_read(root, name) for name in sorted(PUBLIC_FILES)}
    if sum(map(len, payload.values())) > MAX_TOTAL:
        raise ReleaseError('Snapshot exceeds the total byte budget')
    for name, data in payload.items():
        try:
            text = data.decode('utf-8')
        except UnicodeError as exc:
            raise ReleaseError('Non-text content refused') from exc
        if '\x00' in text:
            raise ReleaseError('Binary content refused')
        hits = findings(text)
        if hits:
            # Only a reviewed filename and rule/line are reported; never the value.
            raise ReleaseError(f'Publication scan failed in {name}: {hits}')
    manifest = json.loads(payload['MANIFEST.json'])
    expected_names = PUBLIC_FILES - {'MANIFEST.json'}
    if (not isinstance(manifest, dict) or manifest.get('schema') != 1
            or not isinstance(manifest.get('files'), dict)
            or set(manifest['files']) != expected_names):
        raise ReleaseError('Manifest does not match the exact allowlist')
    for name in expected_names:
        record = manifest['files'][name]
        if record != {'sha256': hashlib.sha256(payload[name]).hexdigest(), 'bytes': len(payload[name])}:
            raise ReleaseError(f'Manifest mismatch: {name}')
    return payload


def export(root: Path, output: Path) -> dict[str, str | int]:
    payload = verify(root)
    # Never overwrite an existing archive, including a symlink. The parent is
    # chosen by the owner and must be trusted, just like the snapshot root.
    fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, 'wb') as stream:
            with zipfile.ZipFile(stream, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
                for name, data in sorted(payload.items()):
                    item = zipfile.ZipInfo('i20-lab-public/' + name, (1980, 1, 1, 0, 0, 0))
                    item.create_system = 3
                    item.external_attr = (stat.S_IFREG | 0o644) << 16
                    item.compress_type = zipfile.ZIP_DEFLATED
                    archive.writestr(item, data)
        data = output.read_bytes()
        return {'files': len(payload), 'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()}
    except BaseException:
        # A partial archive must not be mistaken for an approved release.
        output.unlink(missing_ok=True)
        raise


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('command', choices=['check', 'export'])
    ap.add_argument('--root', type=Path, default=Path(__file__).resolve().parent)
    ap.add_argument('--out', type=Path)
    args = ap.parse_args()
    try:
        if args.command == 'check':
            payload = verify(args.root)
            print(json.dumps({'status': 'SNAPSHOT_CHECK_PASS', 'files': len(payload),
                              'bytes': sum(map(len, payload.values())), 'history_audited': False}))
        else:
            if args.out is None:
                raise ReleaseError('--out is required for export')
            print(json.dumps(export(args.root, args.out)))
    except (ReleaseError, OSError, UnicodeError, ValueError, TypeError, KeyError) as exc:
        # ReleaseError messages have deliberately non-sensitive content.
        message = str(exc) if isinstance(exc, ReleaseError) else type(exc).__name__
        ap.exit(2, f'Release refused: {message}\n')


if __name__ == '__main__':
    main()
