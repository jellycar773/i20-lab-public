#!/usr/bin/env python3
"""Offline task-contract builder and unauthenticated result-report inspector.

Adapted from the private lab's task preflight component. This module cannot
submit work, invoke a model, execute submitted Python, run Lean, or deploy a
controller. Research-specific context has been replaced with synthetic context.
A JSON report, even one with matching hashes, is never proof authentication.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
from typing import Any

ENGINES = {'codex', 'claude', 'lean', 'python', 'health'}
ROLES = {'prove', 'attack', 'replay', 'formalize', 'engineering'}
ID = re.compile(r'^[a-z0-9][a-z0-9_-]{0,63}$')
HEX = re.compile(r'^[0-9a-f]{64}$')
AXIOMS = {'propext', 'Classical.choice', 'Quot.sound'}
MAX_CONTEXT = 100_000
MAX_SOURCE = 150_000
MAX_INPUT = 250_000
FORBIDDEN = re.compile(
    r'\b(sorry|sorryAx|admit|axiom|unsafe|native_decide|initialize|'
    r'builtin_initialize|elab|elab_rules|macro|macro_rules|syntax|run_cmd|'
    r'run_elab|run_tac|implemented_by)\b|#\s*(eval|print)|\bset_option\b'
)
PROJECT_TARGETS = {
    'i20': ('synthetic-i20-example', 'PROJECT: I20. SYNTHETIC DEMONSTRATION CONTEXT; no research result is included.'),
    'i21': ('synthetic-i21-example', 'PROJECT: I21. SYNTHETIC DEMONSTRATION CONTEXT; no research result is included.'),
}
OUTPUT_RULE = (
    'Return the exact result, assumptions, assurance level, remaining obligation, '
    'and artifact hashes. Model prose is not a proof certificate. Do not spawn '
    'agents or alter credentials, billing, the controller, or another task.'
)
SENSITIVE_PARTS = {'.git', '.ssh', '.codex', '.claude', '.aws', '.azure', '.kube',
                   '.config', '.netrc', '.npmrc', '.pypirc', 'auth.json',
                   'credentials.json', 'credentials', 'hosts.yml', 'id_rsa',
                   'id_ed25519', 'secrets', 'secrets.json'}


class PreflightError(ValueError):
    """A task or report fails the local, non-certifying input checks."""


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def require_text(obj: dict[str, Any], key: str) -> str:
    value = obj.get(key)
    if not isinstance(value, str) or not value.strip():
        raise PreflightError(f'Missing nonempty text: {key}')
    return value


def source_check(source: str) -> None:
    """Conservative lint only; NOT a Lean parser, sandbox, or security proof."""
    if len(source.encode('utf-8')) > MAX_SOURCE:
        raise PreflightError('Source exceeds the transport limit')
    if FORBIDDEN.search(source):
        raise PreflightError('Source contains a forbidden construct')
    for line in source.splitlines():
        if re.match(r'^\s*import\s', line):
            for module in line.strip().split()[1:]:
                if module not in {'Goal', 'Mathlib'} and not module.startswith('Mathlib.'):
                    raise PreflightError('Unapproved import')


def dependency_parts(path: str) -> tuple[str, ...]:
    """Accept only canonical relative POSIX paths, with no credential locations."""
    p = PurePosixPath(path)
    if (not path or '\\' in path or '\x00' in path or p.is_absolute()
            or p.as_posix() != path or any(x in {'', '.', '..'} for x in path.split('/'))):
        raise PreflightError('Dependency must use a canonical relative path')
    for part in p.parts:
        low = part.lower()
        if (low in SENSITIVE_PARTS or low.startswith('.env')
                or low.endswith(('.pem', '.key', '.p12', '.pfx', '.jsonl', '.log'))):
            raise PreflightError('Credential or operational-log dependency refused')
    return p.parts


def safe_context_read(root: Path, parts: tuple[str, ...]) -> bytes:
    """POSIX descriptor-relative read: no symlinks, hardlinks, devices, or FIFOs.

    The caller supplies a trusted local context root. Ancestors of that root
    must be owner-controlled. This is not protection against a hostile owner.
    """
    if not hasattr(os, 'O_NOFOLLOW') or not hasattr(os, 'O_DIRECTORY'):
        raise PreflightError('Secure context reads require a POSIX platform')
    directory = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    fd = os.open(root, directory)
    try:
        for part in parts[:-1]:
            child = os.open(part, directory, dir_fd=fd)
            os.close(fd)
            fd = child
        file_fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
        with os.fdopen(file_fd, 'rb') as stream:
            before = os.fstat(stream.fileno())
            if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                    or before.st_size > MAX_CONTEXT):
                raise PreflightError('Context must be a bounded regular, single-link file')
            data = stream.read(MAX_CONTEXT + 1)
            after = os.fstat(stream.fileno())
        if len(data) > MAX_CONTEXT:
            raise PreflightError('Context exceeds the transport limit')
        fields = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
        if any(getattr(before, f) != getattr(after, f) for f in fields):
            raise PreflightError('Context changed during reading')
        return data
    finally:
        os.close(fd)


def resolve_dependency(root: Path, entry: dict[str, Any]) -> tuple[str, str, str]:
    if not isinstance(entry, dict):
        raise PreflightError('Each dependency must be an object')
    relative = require_text(entry, 'path')
    expected = require_text(entry, 'sha256')
    if not HEX.fullmatch(expected):
        raise PreflightError('Dependency SHA256 must have 64 lower-case hex digits')
    data = safe_context_read(root, dependency_parts(relative))
    if sha256(data) != expected:
        raise PreflightError('Dependency hash mismatch')
    return relative, expected, data.decode('utf-8')


def build(spec: dict[str, Any], root: Path, existing_ids: set[str] | None = None,
          killed_routes: set[str] | None = None) -> tuple[bytes, dict[str, Any]]:
    if not isinstance(spec, dict):
        raise PreflightError('Spec must be an object')
    if len(json.dumps(spec, ensure_ascii=False).encode()) > MAX_INPUT:
        raise PreflightError('Spec exceeds the transport limit')
    project = require_text(spec, 'project')
    if project not in PROJECT_TARGETS:
        raise PreflightError("Project must be explicitly 'i20' or 'i21'")
    target_id, target = PROJECT_TARGETS[project]
    ident = require_text(spec, 'id')
    if not ID.fullmatch(ident):
        raise PreflightError('Invalid task id')
    if ident in (existing_ids or set()):
        raise PreflightError('ID already exists; use a new id')
    engine, role = spec.get('engine'), spec.get('role')
    if not isinstance(engine, str) or not isinstance(role, str) or engine not in ENGINES or role not in ROLES:
        raise PreflightError('Unknown engine or role')
    if engine == 'health' and role != 'engineering':
        raise PreflightError('Health engine is for infrastructure only')
    if engine == 'python' and role not in {'replay', 'engineering'}:
        raise PreflightError('Python tasks must be replay or engineering')
    if role == 'formalize' and engine not in {'lean', 'codex', 'claude'}:
        raise PreflightError('Formalization requires a proof-capable engine')
    if project == 'i21' and (engine == 'lean' or role == 'formalize'):
        raise PreflightError('I21 formalization is unavailable through the legacy I20Goal interface')
    if role != 'engineering':
        for prefix in PROJECT_TARGETS:
            if ident.startswith((prefix + '-', prefix + '_')) and prefix != project:
                raise PreflightError('Task prefix conflicts with explicit project')
    route = require_text(spec, 'route_id')
    if route in (killed_routes or set()):
        raise PreflightError('Route is killed; change the hypothesis before retrying')
    parent = spec.get('parent_id')
    if parent is not None:
        if not isinstance(parent, str) or not ID.fullmatch(parent):
            raise PreflightError('Invalid parent_id')
        require_text(spec, 'retry_reason')
    contract = {key: require_text(spec, key) for key in (
        'statement', 'hypotheses', 'success', 'kill_condition', 'requested_assurance')}
    dep_entries = spec.get('dependencies', [])
    if not isinstance(dep_entries, list) or len(dep_entries) > 32:
        raise PreflightError('Dependencies must be a list of at most 32 entries')
    deps = [resolve_dependency(root, entry) for entry in dep_entries]
    contract_data = {'project': project, 'target_id': target_id, 'role': role,
                     'route_id': route, **contract, 'dependencies': [(p, h) for p, h, _ in deps]}
    fingerprint = sha256(json.dumps(contract_data, sort_keys=True, ensure_ascii=False).encode())
    mode = 'prove' if engine == 'lean' or role == 'formalize' else 'audit'
    job: dict[str, Any] = {'schema': 2, 'id': ident, 'engine': engine,
                           'purpose': 'infrastructure' if role == 'engineering' else 'research', 'mode': mode}
    if engine in {'codex', 'claude'}:
        sections = [target if role != 'engineering' else 'INFRASTRUCTURE ONLY; no proof promotion.',
                    'ROLE: ' + role, 'ROUTE: ' + route, 'CONTRACT_SHA256: ' + fingerprint]
        sections.extend(key.upper() + ': ' + value for key, value in contract.items())
        if parent is not None:
            sections.append('RETRY_REASON: ' + spec['retry_reason'])
        for path, digest, text in deps:
            sections.append(f'BEGIN_VERBATIM_CONTEXT {path} SHA256={digest}\n{text}\nEND_VERBATIM_CONTEXT {path}')
        sections.append(OUTPUT_RULE)
        job['prompt'] = '\n\n'.join(sections)
        if len(job['prompt'].encode()) > 140_000:
            raise PreflightError('Inline context exceeds the transport limit')
    if engine == 'python':
        code = require_text(spec, 'code')
        if len(code.encode()) > MAX_SOURCE:
            raise PreflightError('Code exceeds the transport limit')
        compile(code, '<unexecuted experiment>', 'exec')  # Syntax validation only.
        job['code'] = code
    if engine == 'lean' or mode == 'prove':
        job['goal'] = require_text(spec, 'goal')
        if not re.search(r'\bnamespace\s+I20Goal\b', job['goal']) or not re.search(r'\bdef\s+statement\s*:\s*Prop', job['goal']):
            raise PreflightError('Goal must define I20Goal.statement : Prop')
        source_check(job['goal'])
        if engine == 'lean':
            job['solution'] = require_text(spec, 'solution')
            source_check(job['solution'])
            if not re.search(r'\btheorem\s+i20_result\s*:\s*I20Goal.statement', job['solution']):
                raise PreflightError('Solution must target exactly I20Goal.statement')
    for key in ('seconds', 'max_turns', 'memory_mb'):
        if key in spec:
            value = spec[key]
            if value is not None and (type(value) is not int or value <= 0):
                raise PreflightError(key + ' must be a positive integer or null')
            job[key] = value
    if parent is not None:
        job['parent_id'] = parent
    for key in ('model', 'effort'):
        if key in spec:
            job[key] = require_text(spec, key)
    payload = (json.dumps(job, ensure_ascii=False, separators=(',', ':')) + '\n').encode()
    blob = hashlib.sha1(b'blob ' + str(len(payload)).encode() + b'\0' + payload).hexdigest()
    receipt = {'id': ident, 'contract_sha256': fingerprint, 'task_sha256': sha256(payload),
               'task_blob': blob, 'task_path': f'tasks/{ident}.json',
               'expected_result_path': f'results/{ident}-{blob[:12]}.json',
               'project': project, 'target_id': target_id, 'dependencies': [(p, h) for p, h, _ in deps],
               'assurance': 'PREFLIGHT_ONLY_NOT_A_PROOF', 'submitted': False}
    return payload, receipt


def inspect_result(result: dict[str, Any], task_bytes: bytes | None = None) -> dict[str, Any]:
    """Check internal consistency, never authenticate a controller or a proof.

    Free-form notes, errors, paths, timestamps, and logs are deliberately omitted.
    Matching hashes authenticate bytes against bytes, not the reporting party.
    """
    if not isinstance(result, dict):
        raise PreflightError('Result must be an object')
    statuses = {'UNVERIFIED_REVIEW', 'COMPUTATION_NOT_A_PROOF', 'KERNEL_CHECKED_REQUESTED_TYPE',
                'ERROR', 'FAILED', 'MISSING_STATUS'}
    status = result.get('status', 'MISSING_STATUS')
    if not isinstance(status, str) or status not in statuses:
        status = 'UNKNOWN_STATUS'
    verification = result.get('verification') or {}
    if not isinstance(verification, dict):
        raise PreflightError('Verification must be an object')
    out: dict[str, Any] = {'reported_status': status, 'task_bytes_matched': False,
                          'kernel_report_internally_consistent': False,
                          'provenance_authenticated': False, 'independently_verified': False,
                          'controller_kernel_confirmation': False,
                          'warning': 'An unauthenticated JSON report is not a proof certificate. '
                                     'Replay the exact formal statement with a trusted independent verifier.'}
    if task_bytes is None:
        return out
    if len(task_bytes) > MAX_INPUT:
        raise PreflightError('Task exceeds the inspection limit')
    job = json.loads(task_bytes)
    if not isinstance(job, dict):
        raise PreflightError('Task must be an object')
    blob = hashlib.sha1(b'blob ' + str(len(task_bytes)).encode() + b'\0' + task_bytes).hexdigest()
    if result.get('task_blob') != blob or result.get('id') != job.get('id') or not job.get('id'):
        raise PreflightError('Result does not match the supplied immutable task bytes')
    out['task_bytes_matched'] = True
    kernel = (status == 'KERNEL_CHECKED_REQUESTED_TYPE'
              and verification.get('status') == status and verification.get('compiled') is True)
    if kernel:
        goal = job.get('goal')
        if not isinstance(goal, str) or not goal or result.get('goal_sha256') != sha256(goal.encode()):
            raise PreflightError('Kernel report has a missing or different original goal hash')
        axioms = verification.get('axioms')
        if not isinstance(axioms, list) or not all(isinstance(a, str) and a in AXIOMS for a in axioms):
            raise PreflightError('Unapproved or missing axiom report')
        out['kernel_report_internally_consistent'] = True
    return out


def _read_input(path: Path) -> bytes:
    with path.open('rb') as stream:
        data = stream.read(MAX_INPUT + 1)
    if len(data) > MAX_INPUT:
        raise PreflightError('Input exceeds the local limit')
    return data


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    sub = ap.add_subparsers(dest='command', required=True)
    builder = sub.add_parser('build')
    builder.add_argument('spec', type=Path)
    builder.add_argument('--context-root', type=Path, required=True)
    builder.add_argument('--out-dir', type=Path, required=True,
                         help='A NEW private output directory; existing directories are refused')
    inspector = sub.add_parser('inspect')
    inspector.add_argument('result', type=Path)
    inspector.add_argument('--task', type=Path)
    args = ap.parse_args()
    try:
        if args.command == 'build':
            payload, receipt = build(json.loads(_read_input(args.spec)), args.context_root)
            # Parent directory must be owner-controlled; no overwrite of existing output.
            args.out_dir.mkdir(mode=0o700, parents=False, exist_ok=False)
            for suffix, data in [('.json', payload), ('.receipt.json', (json.dumps(receipt, indent=2) + '\n').encode())]:
                dest = args.out_dir / (receipt['id'] + suffix)
                fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                with os.fdopen(fd, 'wb') as stream:
                    stream.write(data)
            print(json.dumps(receipt, indent=2))
        else:
            out = inspect_result(json.loads(_read_input(args.result)),
                                 _read_input(args.task) if args.task else None)
            print(json.dumps(out, indent=2))
    except (PreflightError, OSError, UnicodeError, SyntaxError, KeyError, TypeError,
            json.JSONDecodeError, RecursionError, MemoryError) as exc:
        # Do not echo input values, source excerpts, credential material, or paths.
        ap.exit(2, f'Request refused ({type(exc).__name__}); inspect the local input privately.\n')


if __name__ == '__main__':
    main()
