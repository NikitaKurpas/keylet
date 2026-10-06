"""Credential-free CLI regression: real process invocation through Homebrew-style symlinks."""
import json
import os
from pathlib import Path
import plistlib
import shutil
import subprocess
import tempfile
import unittest

import bundle_unsigned
import bundle_version
import release

ROOT = Path(__file__).resolve().parents[1]
BINARY = ROOT / '.build/debug/keylet'


class DiagnosticsTests(unittest.TestCase):
    def fixture_bundle(self, root):
        (root / 'packaging').mkdir()
        (root / 'licenses').mkdir()
        for source in ['packaging/Info.plist', 'packaging/keylet-ssh-sign',
                       'licenses/swift-argument-parser-LICENSE.txt', 'LICENSE', 'NOTICE.md', 'version.txt']:
            shutil.copyfile(ROOT / source, root / source)
        return bundle_unsigned.bundle(root, BINARY)

    def test_versions_follow_source_stamp_release_stamp_and_path_aliases(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            app = self.fixture_bundle(root)
            binary = app / 'Contents/MacOS/keylet'
            (root / 'bin').mkdir()
            alias = root / 'bin/keylet'
            alias.symlink_to(binary)
            second_alias = root / 'bin/another-keylet'
            second_alias.symlink_to(alias)
            environment = dict(os.environ, PATH=str(root / 'bin') + os.pathsep + os.environ['PATH'])
            for expected in [bundle_version.source_version(ROOT), '7.8.9']:
                # Exactly the stamping function used before release signing; no credentials.
                release.set_bundle_version(app, expected)
                info = plistlib.loads((app / 'Contents/Info.plist').read_bytes())
                self.assertEqual(info['CFBundleShortVersionString'], expected)
                self.assertEqual(info['CFBundleVersion'], expected)
                for command in [str(binary), str(alias), str(second_alias), 'keylet']:
                    for arguments in [['--version'], ['version']]:
                        result = subprocess.run([command, *arguments], cwd='/tmp', env=environment,
                                                text=True, capture_output=True, check=False)
                        self.assertEqual(result.returncode, 0, result.stderr)
                        self.assertEqual(result.stdout.strip(), expected)
                    for arguments in [['--json', '--version'], ['--json', 'version'],
                                      ['doctor', '--version', '--json'], ['--json', 'doctor']]:
                        result = subprocess.run([command, *arguments], cwd='/tmp', env=environment,
                                                text=True, capture_output=True, check=False)
                        self.assertEqual(result.returncode, 0, result.stderr)
                        self.assertEqual(json.loads(result.stdout)['version'], expected)

    def test_unbundled_build_and_doctor_contract(self):
        version = subprocess.run([str(BINARY), 'version'], cwd='/tmp', text=True,
                                 capture_output=True, check=False)
        self.assertEqual(version.returncode, 0, version.stderr)
        self.assertEqual(version.stdout.strip(), 'development')
        result = subprocess.run([str(BINARY), '--json', 'doctor'], cwd='/tmp',
                                text=True, capture_output=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report['version'], 'development')
        self.assertEqual(report['checks']['credential_access'], 'not_checked')
        self.assertEqual(report['checks']['provisioning'], 'not_checked')
        self.assertEqual(report['checks']['security_policy_enforcement'], 'not_checked')
        self.assertEqual(report['checks']['signing_metadata'], 'failed')
        self.assertTrue(report['problems'])
        self.assertNotIn('offline', report)
        self.assertNotIn('audit_path', report)
        self.assertNotIn('minimum_macos', report)
        text = subprocess.run([str(BINARY), 'doctor'], cwd='/tmp', text=True,
                              capture_output=True, check=False)
        self.assertEqual(text.returncode, 0, text.stderr)
        self.assertIn('Signing metadata: invalid', text.stdout)
        self.assertIn('not checked', text.stdout)
        self.assertIn('Problem: Use the correctly signed Keylet.app', text.stdout)
        self.assertNotIn('offline:', text.stdout)

    def test_bad_release_version_cannot_change_bundle(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            app = self.fixture_bundle(root)
            info = app / 'Contents/Info.plist'
            original = info.read_bytes()
            for invalid in ['0.1', '01.2.3', '1.2.3\nother', '$(fixture)']:
                with self.assertRaises(ValueError):
                    release.set_bundle_version(app, invalid)
                self.assertEqual(info.read_bytes(), original)
            release.set_bundle_version(app, None)
            self.assertEqual(info.read_bytes(), original)
