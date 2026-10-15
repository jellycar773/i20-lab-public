import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import tempfile
import unittest
import zipfile

import release

SOURCE = Path(__file__).resolve().parents[1]


class ReleaseTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name)
        self.root = self.base / 'snapshot'
        shutil.copytree(SOURCE, self.root, ignore=shutil.ignore_patterns('__pycache__', '.git'))

    def tearDown(self):
        self.temp.cleanup()

    def test_baseline_manifest(self):
        self.assertEqual(set(release.verify(self.root)), release.PUBLIC_FILES)

    def test_modified_file_refused(self):
        (self.root / 'README.md').write_text('Unreviewed replacement')
        with self.assertRaises(release.ReleaseError):
            release.verify(self.root)

    def test_missing_file_refused(self):
        (self.root / 'README.md').unlink()
        with self.assertRaises(release.ReleaseError):
            release.verify(self.root)

    def test_extra_secret_file_refused(self):
        (self.root / '.env').write_text('do not publish')
        with self.assertRaises(release.ReleaseError):
            release.verify(self.root)

    def test_extra_directory_refused(self):
        (self.root / 'results').mkdir()
        (self.root / 'results' / 'private.txt').write_text('do not publish')
        with self.assertRaises(release.ReleaseError):
            release.verify(self.root)

    def test_symlink_file_refused(self):
        path = self.root / 'README.md'
        path.unlink()
        path.symlink_to(SOURCE / 'README.md')
        with self.assertRaises((release.ReleaseError, OSError)):
            release.verify(self.root)

    def test_symlink_directory_refused(self):
        shutil.rmtree(self.root / 'docs')
        (self.root / 'docs').symlink_to(SOURCE / 'docs', target_is_directory=True)
        with self.assertRaises(release.ReleaseError):
            release.verify(self.root)

    def test_hardlink_refused(self):
        os.link(self.root / 'README.md', self.base / 'hardlink')
        with self.assertRaises(release.ReleaseError):
            release.verify(self.root)

    def test_root_symlink_refused(self):
        link = self.base / 'link'
        link.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(release.ReleaseError):
            release.verify(link)

    def test_fifo_refused_without_blocking(self):
        (self.root / 'README.md').unlink()
        os.mkfifo(self.root / 'README.md')
        with self.assertRaises(release.ReleaseError):
            release.verify(self.root)

    def test_large_file_refused(self):
        (self.root / 'README.md').write_bytes(b'x' * (release.MAX_FILE + 1))
        with self.assertRaises(release.ReleaseError):
            release.verify(self.root)

    def test_binary_refused(self):
        (self.root / 'README.md').write_bytes(b'\x00\xff')
        with self.assertRaises(release.ReleaseError):
            release.verify(self.root)

    def test_manifest_injection_refused(self):
        manifest = json.loads((self.root / 'MANIFEST.json').read_text())
        manifest['files']['../outside'] = {'sha256': '0' * 64, 'bytes': 0}
        (self.root / 'MANIFEST.json').write_text(json.dumps(manifest))
        with self.assertRaises(release.ReleaseError):
            release.verify(self.root)

    def test_paths_cannot_escape(self):
        for path in ['../README.md', '/README.md', '.git/config', 'README.md/../README.md']:
            with self.subTest(path=path), self.assertRaises(release.ReleaseError):
                release.safe_read(self.root, path)

    def test_synthetic_secret_detectors_do_not_disclose_values(self):
        # Construct fake fixtures at runtime; no literal credential is shipped.
        cases = {
            'github-token': 'gh' + 'p_' + 'A' * 36,
            'provider-key': 's' + 'k-' + 'B' * 48,
            'aws-key': 'AK' + 'IA' + 'C' * 16,
            'private-key': '-----BEGIN ' + 'PRIVATE KEY-----',
            'bearer-literal': 'Bear' + 'er ' + 'D' * 40,
            'jwt-literal': 'ey' + 'J' + 'A' * 20 + '.' + 'B' * 20 + '.' + 'C' * 20,
            'credential-assignment': 'pass' + 'word = "' + 'Z' * 20 + '"',
            'url-credentials': 'https://' + 'user' + ':' + 'secret' + '@' + 'example.test',
            'url-secret-query': 'https://example.test/?' + 'token=' + 'E' * 32,
            'email-address': 'private' + '@' + 'example.test',
            'personal-home-path': '/' + 'home' + '/' + 'private-person' + '/file',
            'public-ip-address': '.'.join(['8', '8', '8', '8']),
        }
        for rule, value in cases.items():
            with self.subTest(rule=rule):
                hits = release.findings(value)
                self.assertIn(rule, {hit['rule'] for hit in hits})
                self.assertNotIn(value, json.dumps(hits))

    def test_secret_scan_still_applies_after_manifest_update(self):
        value = 'gh' + 'p_' + 'A' * 36
        path = self.root / 'README.md'
        path.write_text(value)
        manifest = json.loads((self.root / 'MANIFEST.json').read_text())
        manifest['files']['README.md'] = {'sha256': hashlib.sha256(path.read_bytes()).hexdigest(), 'bytes': path.stat().st_size}
        (self.root / 'MANIFEST.json').write_text(json.dumps(manifest))
        with self.assertRaises(release.ReleaseError) as caught:
            release.verify(self.root)
        self.assertNotIn(value, str(caught.exception))

    def test_git_history_is_never_exported(self):
        (self.root / '.git').mkdir()
        (self.root / '.git' / 'private-history').write_text('never exported')
        output = self.base / 'public.zip'
        release.export(self.root, output)
        with zipfile.ZipFile(output) as archive:
            self.assertEqual({'i20-lab-public/' + x for x in release.PUBLIC_FILES}, set(archive.namelist()))
            self.assertFalse(any('/.git/' in name for name in archive.namelist()))

    def test_deterministic_archive_and_normalized_metadata(self):
        first, second = self.base / 'a.zip', self.base / 'b.zip'
        a = release.export(self.root, first)
        b = release.export(self.root, second)
        self.assertEqual(first.read_bytes(), second.read_bytes())
        self.assertEqual(a['sha256'], hashlib.sha256(first.read_bytes()).hexdigest())
        self.assertEqual(a['sha256'], b['sha256'])
        with zipfile.ZipFile(first) as archive:
            for info in archive.infolist():
                self.assertEqual((1980, 1, 1, 0, 0, 0), info.date_time)
                self.assertEqual(stat.S_IFREG | 0o644, info.external_attr >> 16)

    def test_existing_output_not_overwritten(self):
        output = self.base / 'public.zip'
        output.write_bytes(b'preserve')
        with self.assertRaises(FileExistsError):
            release.export(self.root, output)
        self.assertEqual(b'preserve', output.read_bytes())

    def test_output_symlink_refused(self):
        target = self.base / 'target'
        target.write_bytes(b'preserve')
        output = self.base / 'public.zip'
        output.symlink_to(target)
        with self.assertRaises(OSError):
            release.export(self.root, output)
        self.assertEqual(b'preserve', target.read_bytes())


if __name__ == '__main__':
    unittest.main()
