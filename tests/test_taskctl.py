import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from lab.taskctl import build, inspect_result, PreflightError, source_check, dependency_parts


class TaskTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.spec = dict(project='i20', id='demo-001', engine='codex', role='attack',
                         route_id='r1', statement='Synthetic statement', hypotheses='Explicit domain',
                         success='An exact result', kill_condition='A counterexample',
                         requested_assurance='Written review only')

    def tearDown(self):
        self.temp.cleanup()

    def dependency(self, name='context.txt', data=b'Elementary context'):
        (self.root / name).write_bytes(data)
        return {'path': name, 'sha256': hashlib.sha256(data).hexdigest()}

    def test_no_submission_or_caps(self):
        payload, receipt = build(self.spec, self.root)
        job = json.loads(payload)
        self.assertFalse(receipt['submitted'])
        self.assertEqual(receipt['assurance'], 'PREFLIGHT_ONLY_NOT_A_PROOF')
        self.assertNotIn('seconds', job)
        self.assertNotIn('max_turns', job)

    def test_independent_hash_and_path_calculation(self):
        payload, receipt = build(self.spec, self.root)
        header = ('blob %d\0' % len(payload)).encode('ascii')
        expected_blob = hashlib.sha1(header + payload).hexdigest()
        self.assertEqual(expected_blob, receipt['task_blob'])
        self.assertEqual(hashlib.sha256(payload).hexdigest(), receipt['task_sha256'])
        self.assertEqual(f'results/demo-001-{expected_blob[:12]}.json', receipt['expected_result_path'])

    def test_determinism(self):
        self.assertEqual(build(self.spec, self.root), build(self.spec, self.root))

    def test_required_contract_fields(self):
        for key in ['project', 'id', 'route_id', 'statement', 'hypotheses', 'success',
                    'kill_condition', 'requested_assurance']:
            with self.subTest(key=key):
                spec = self.spec.copy()
                del spec[key]
                with self.assertRaises(PreflightError):
                    build(spec, self.root)

    def test_project_is_explicit(self):
        for value in ['', None, 'I20', 'i22', [], {}]:
            with self.subTest(value=value), self.assertRaises(PreflightError):
                build({**self.spec, 'project': value}, self.root)

    def test_bad_task_ids(self):
        for value in ['../x', '/x', 'X', 'a' * 65, 'x/y', 'x.json', 'x\ny', []]:
            with self.subTest(value=value), self.assertRaises(PreflightError):
                build({**self.spec, 'id': value}, self.root)

    def test_duplicate_id(self):
        with self.assertRaises(PreflightError):
            build(self.spec, self.root, {'demo-001'})

    def test_killed_route(self):
        with self.assertRaises(PreflightError):
            build(self.spec, self.root, killed_routes={'r1'})

    def test_retry_requires_reason(self):
        with self.assertRaises(PreflightError):
            build({**self.spec, 'parent_id': 'older'}, self.root)
        payload, _ = build({**self.spec, 'parent_id': 'older', 'retry_reason': 'Transport failure'}, self.root)
        self.assertEqual('older', json.loads(payload)['parent_id'])

    def test_invalid_parent(self):
        for value in ['', '../old', {}, 1]:
            with self.subTest(value=value), self.assertRaises(PreflightError):
                build({**self.spec, 'parent_id': value, 'retry_reason': 'Reason'}, self.root)

    def test_context_hash(self):
        dep = self.dependency()
        payload, receipt = build({**self.spec, 'dependencies': [dep]}, self.root)
        self.assertIn('Elementary context', json.loads(payload)['prompt'])
        self.assertEqual([(dep['path'], dep['sha256'])], receipt['dependencies'])

    def test_wrong_hash(self):
        dep = self.dependency()
        dep['sha256'] = '0' * 64
        with self.assertRaises(PreflightError):
            build({**self.spec, 'dependencies': [dep]}, self.root)

    def test_bad_hash_syntax(self):
        for digest in ['a', 'G' * 64, '', None]:
            with self.subTest(digest=digest), self.assertRaises(PreflightError):
                build({**self.spec, 'dependencies': [{'path': 'x', 'sha256': digest}]}, self.root)

    def test_traversal_and_noncanonical_paths(self):
        for path in ['../x', '/x', 'd/../x', './x', 'd//x', 'd\\x', 'd/./x', 'x\x00', '']:
            with self.subTest(path=path), self.assertRaises(PreflightError):
                dependency_parts(path)

    def test_sensitive_paths(self):
        for path in ['.env', '.env.production', '.ssh/id_rsa', '.codex/auth.json',
                     'auth.json', 'd/credentials.json', 'key.pem', 'session.jsonl', 'worker.log']:
            with self.subTest(path=path), self.assertRaises(PreflightError):
                dependency_parts(path)

    def test_symlink_file(self):
        dep = self.dependency()
        (self.root / 'link').symlink_to(self.root / dep['path'])
        dep['path'] = 'link'
        with self.assertRaises((PreflightError, OSError)):
            build({**self.spec, 'dependencies': [dep]}, self.root)

    def test_symlink_directory(self):
        dep = self.dependency()
        (self.root / 'link').symlink_to(self.root, target_is_directory=True)
        dep['path'] = 'link/context.txt'
        with self.assertRaises((PreflightError, OSError)):
            build({**self.spec, 'dependencies': [dep]}, self.root)

    def test_symlink_root(self):
        dep = self.dependency()
        (self.root / 'link').symlink_to(self.root, target_is_directory=True)
        with self.assertRaises((PreflightError, OSError)):
            build({**self.spec, 'dependencies': [dep]}, self.root / 'link')

    def test_hardlink(self):
        dep = self.dependency()
        os.link(self.root / dep['path'], self.root / 'other')
        with self.assertRaises(PreflightError):
            build({**self.spec, 'dependencies': [dep]}, self.root)

    def test_fifo_is_not_read(self):
        os.mkfifo(self.root / 'pipe')
        with self.assertRaises(PreflightError):
            build({**self.spec, 'dependencies': [{'path': 'pipe', 'sha256': '0' * 64}]}, self.root)

    def test_directory_not_context(self):
        (self.root / 'directory').mkdir()
        with self.assertRaises((PreflightError, OSError)):
            build({**self.spec, 'dependencies': [{'path': 'directory', 'sha256': '0' * 64}]}, self.root)

    def test_context_size_limit(self):
        dep = self.dependency(data=b'a' * 100_001)
        with self.assertRaises(PreflightError):
            build({**self.spec, 'dependencies': [dep]}, self.root)

    def test_context_is_utf8(self):
        dep = self.dependency(data=b'\xff\xfe')
        with self.assertRaises(UnicodeError):
            build({**self.spec, 'dependencies': [dep]}, self.root)

    def test_dependency_list_shape_and_count(self):
        for value in ['x', None, [None], [{}] * 33]:
            with self.subTest(value=value), self.assertRaises(PreflightError):
                build({**self.spec, 'dependencies': value}, self.root)

    def test_engine_role_combinations(self):
        for engine, role in [('python', 'prove'), ('health', 'attack'), ('python', 'formalize'),
                             ('unknown', 'prove'), ([], 'prove')]:
            with self.subTest(engine=engine, role=role), self.assertRaises(PreflightError):
                build({**self.spec, 'engine': engine, 'role': role}, self.root)

    def test_python_is_compiled_not_executed(self):
        marker = self.root / 'must-not-exist'
        code = f'from pathlib import Path\nPath({str(marker)!r}).write_text("executed")\nraise RuntimeError("executed")'
        payload, _ = build({**self.spec, 'engine': 'python', 'role': 'replay', 'code': code}, self.root)
        self.assertEqual(code, json.loads(payload)['code'])
        self.assertFalse(marker.exists())

    def test_python_syntax(self):
        with self.assertRaises(SyntaxError):
            build({**self.spec, 'engine': 'python', 'role': 'replay', 'code': 'if'}, self.root)

    def test_source_budget_before_compile(self):
        with self.assertRaises(PreflightError):
            build({**self.spec, 'engine': 'python', 'role': 'replay', 'code': '#' * 150_001}, self.root)

    def test_spec_and_prompt_budgets(self):
        for length in [150_001, 260_000]:
            with self.subTest(length=length), self.assertRaises(PreflightError):
                build({**self.spec, 'statement': 'x' * length}, self.root)

    def test_numeric_limits(self):
        for value in [True, False, 0, -1, '1', 1.5]:
            with self.subTest(value=value), self.assertRaises(PreflightError):
                build({**self.spec, 'seconds': value}, self.root)
        for value in [None, 1]:
            payload, _ = build({**self.spec, 'seconds': value}, self.root)
            self.assertEqual(value, json.loads(payload)['seconds'])

    def test_synthetic_context_only(self):
        for project in ['i20', 'i21']:
            payload, receipt = build({**self.spec, 'project': project}, self.root)
            self.assertIn('SYNTHETIC DEMONSTRATION CONTEXT', json.loads(payload)['prompt'])
            self.assertEqual(project, receipt['project'])
            self.assertNotIn('WRITTEN_PROOF_COMPLETE', json.loads(payload)['prompt'])

    def test_project_fingerprint_differs(self):
        _, a = build(self.spec, self.root)
        _, b = build({**self.spec, 'project': 'i21'}, self.root)
        self.assertNotEqual(a['contract_sha256'], b['contract_sha256'])

    def test_legacy_formalization_rejected(self):
        for engine, role in [('lean', 'prove'), ('codex', 'formalize'), ('claude', 'formalize')]:
            with self.subTest(engine=engine), self.assertRaises(PreflightError):
                build({**self.spec, 'project': 'i21', 'engine': engine, 'role': role}, self.root)

    def test_project_prefix_mismatch(self):
        with self.assertRaises(PreflightError):
            build({**self.spec, 'id': 'i21-review'}, self.root)

    def test_forbidden_constructs(self):
        for word in ['sorry', 'axiom', 'native_decide', 'set_option', 'unsafe']:
            with self.subTest(word=word), self.assertRaises(PreflightError):
                source_check('-- ' + word)

    def test_second_import_rejected(self):
        with self.assertRaises(PreflightError):
            source_check('import Mathlib Unknown')

    def test_valid_source_lint(self):
        source_check('import Mathlib\nnoncomputable section\ntheorem h : (1:ℝ)=1 := rfl')

    def proof_fixture(self):
        spec = {**self.spec, 'engine': 'lean', 'role': 'prove',
                'goal': 'import Mathlib\nnamespace I20Goal\ndef statement : Prop := True\nend I20Goal',
                'solution': 'import Goal\ntheorem i20_result : I20Goal.statement := True.intro'}
        payload, receipt = build(spec, self.root)
        result = {'id': spec['id'], 'task_blob': receipt['task_blob'],
                  'status': 'KERNEL_CHECKED_REQUESTED_TYPE',
                  'goal_sha256': hashlib.sha256(spec['goal'].encode()).hexdigest(),
                  'verification': {'status': 'KERNEL_CHECKED_REQUESTED_TYPE', 'compiled': True, 'axioms': []}}
        return payload, result

    def test_forged_consistent_report_never_authenticates(self):
        payload, result = self.proof_fixture()
        out = inspect_result(result, payload)
        self.assertTrue(out['task_bytes_matched'])
        self.assertTrue(out['kernel_report_internally_consistent'])
        self.assertFalse(out['provenance_authenticated'])
        self.assertFalse(out['independently_verified'])
        self.assertFalse(out['controller_kernel_confirmation'])

    def test_wrong_goal_hash(self):
        payload, result = self.proof_fixture()
        result['goal_sha256'] = '0' * 64
        with self.assertRaises(PreflightError):
            inspect_result(result, payload)

    def test_bad_axioms(self):
        for axioms in [None, ['sorryAx'], [{}], 'propext']:
            payload, result = self.proof_fixture()
            result['verification']['axioms'] = axioms
            with self.subTest(axioms=axioms), self.assertRaises(PreflightError):
                inspect_result(result, payload)

    def test_wrong_task(self):
        payload, result = self.proof_fixture()
        result['id'] = 'different'
        with self.assertRaises(PreflightError):
            inspect_result(result, payload)

    def test_missing_task_never_authenticates(self):
        _, result = self.proof_fixture()
        out = inspect_result(result)
        self.assertFalse(out['task_bytes_matched'])
        self.assertFalse(out['independently_verified'])

    def test_no_raw_notes_or_errors_in_public_summary(self):
        marker = 'PRIVATE-MARKER-DO-NOT-DISPLAY'
        out = inspect_result({'status': 'UNVERIFIED_REVIEW', 'notes.md': marker,
                              'error': marker, 'source_commit': marker})
        self.assertNotIn(marker, json.dumps(out))

    def test_report_types(self):
        for value in [[], '', None]:
            with self.subTest(value=value), self.assertRaises(PreflightError):
                inspect_result(value)
        with self.assertRaises(PreflightError):
            inspect_result({'verification': ['bad']})
        self.assertEqual('UNKNOWN_STATUS', inspect_result({'status': {'bad': 'x'}})['reported_status'])

    def test_cli_output_is_private_and_nonoverwriting(self):
        spec_path = self.root / 'spec.json'
        spec_path.write_text(json.dumps(self.spec))
        out_dir = self.root / 'out'
        command = [sys.executable, '-m', 'lab.taskctl', 'build', str(spec_path),
                   '--context-root', str(self.root), '--out-dir', str(out_dir)]
        completed = subprocess.run(command, capture_output=True, text=True)
        self.assertEqual(0, completed.returncode, completed.stderr)
        self.assertEqual(0o700, out_dir.stat().st_mode & 0o777)
        for path in out_dir.iterdir():
            self.assertEqual(0o600, path.stat().st_mode & 0o777)
        again = subprocess.run(command, capture_output=True, text=True)
        self.assertEqual(2, again.returncode)


if __name__ == '__main__':
    unittest.main()
