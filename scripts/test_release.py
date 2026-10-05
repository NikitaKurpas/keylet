"""Release validation with synthetic public data; all external commands forbidden."""
import base64
import contextlib
from types import SimpleNamespace
import datetime as dt
import hashlib
import os
import plistlib
import io
import zipfile
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch
import release
import sign_bundle

class ReleaseTests(unittest.TestCase):
    def setUp(self):
        self.no_process = patch.object(release.subprocess, 'run', side_effect=AssertionError('External commands forbidden'))
        self.no_process.start()
        self.addCleanup(self.no_process.stop)
        self.no_network = patch.object(release.urllib.request, 'urlopen', side_effect=AssertionError('Network forbidden'))
        self.no_network.start()
        self.addCleanup(self.no_network.stop)

    def test_signer_failure_uses_status_only_and_never_tool_output(self):
        for code, status in list(sign_bundle.SIGNING_EXIT_CODES.items()) + [('signing_child_unclassified_failure', 1), ('signing_child_unclassified_failure', -9), ('signing_child_unclassified_failure', 255)]:
            stdout, stderr = io.StringIO(), io.StringIO()
            child = SimpleNamespace(returncode=status, stdout=b'SENSITIVE_FIXTURE', stderr=b'sign: codesign_failed SENSITIVE_FIXTURE')
            with patch.object(release.subprocess, 'run', return_value=child) as mocked, contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                with self.assertRaisesRegex(ValueError, r'\['+code+r'\]') as caught:
                    release.run_signer({'KEYLET_SIGN_DIAGNOSTICS':'ignored', 'PROFILE':'SENSITIVE_FIXTURE'})
            self.assertEqual(str(caught.exception), 'Release signing failed ['+code+']')
            self.assertEqual(stdout.getvalue()+stderr.getvalue(), '')
            self.assertEqual(mocked.call_args.kwargs['env']['KEYLET_SIGN_DIAGNOSTICS'], 'exit-code-v1')
            self.assertEqual(mocked.call_args.kwargs['stdout'], release.subprocess.PIPE)
            self.assertEqual(mocked.call_args.kwargs['stderr'], release.subprocess.PIPE)
            self.assertEqual(mocked.call_args.args[0], [release.sys.executable, str(release.ROOT/'scripts/sign_bundle.py')])

    def test_signer_success_and_spawn_failure_do_not_forward_output(self):
        stdout, stderr = io.StringIO(), io.StringIO()
        with patch.object(release.subprocess, 'run', return_value=SimpleNamespace(returncode=0, stdout=b'SENSITIVE_FIXTURE', stderr=b'SENSITIVE_FIXTURE')), contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            self.assertIsNone(release.run_signer({}))
        self.assertEqual(stdout.getvalue()+stderr.getvalue(), '')
        with patch.object(release.subprocess, 'run', side_effect=OSError('SENSITIVE_FIXTURE')):
            with self.assertRaisesRegex(ValueError, r'\[signing_child_launch_failed\]') as caught: release.run_signer({})
        self.assertNotIn('SENSITIVE_FIXTURE', str(caught.exception))

    def test_versions_reject_shell_and_nonrelease_refs(self):
        self.assertEqual(release.version('v1.2.3'), '1.2.3')
        for tag in ['main', 'v1.2', 'v01.2.3', 'v1.2.3;echo x', 'v1.2.3\n', '--help', 'v1.2.3-beta']:
            with self.assertRaises(ValueError): release.version(tag)

    def test_release_profile_requires_all_devices_no_debugging(self):
        team = 'EXAMPL1234'
        certificate = b'public synthetic fixture'
        identity = hashlib.sha1(certificate).hexdigest().upper()
        now = dt.datetime.now(dt.timezone.utc)
        profile = {'TeamIdentifier': [team], 'ApplicationIdentifierPrefix': [team],
            'Entitlements': {'com.apple.developer.team-identifier':team,
                'com.apple.application-identifier':team+'.'+sign_bundle.IDENTIFIER,
                'keychain-access-groups':[team+'.*'],
                'com.apple.security.hardened-process':True,
                'com.apple.security.hardened-process.enhanced-security-version-string':'*'},
            'DeveloperCertificates':[certificate], 'ExpirationDate':now+dt.timedelta(days=1),
            'ProvisionsAllDevices': True}
        def validate(mode='developer-id'):
            sign_bundle.validate_profile(profile, team=team, identity=identity, device_ids=set(), now=now, mode=mode)
        validate()
        with self.assertRaisesRegex(ValueError, 'this Mac'): validate('development')
        profile['ProvisionsAllDevices'] = False
        with self.assertRaisesRegex(ValueError, 'all devices'): validate()
        profile['ProvisionsAllDevices'] = True
        profile['ProvisionedDevices'] = ['SYNTHETIC-MAC']
        with self.assertRaisesRegex(ValueError, 'all devices'): validate()
        del profile['ProvisionedDevices']
        profile['Entitlements']['com.apple.security.get-task-allow'] = True
        with self.assertRaisesRegex(ValueError, 'debugging'): validate()
        with self.assertRaisesRegex(ValueError, 'Unknown'): validate('typo')

    def test_empty_make_export_preserves_development_mode(self):
        for environment in [{}, {'SIGNING_MODE':''}, {'SIGNING_MODE':'development'}]:
            self.assertEqual(sign_bundle.signing_mode(environment),'development')
        self.assertEqual(sign_bundle.signing_mode({'SIGNING_MODE':'developer-id'}),'developer-id')
        with self.assertRaisesRegex(ValueError,'Unknown'): sign_bundle.signing_mode({'SIGNING_MODE':'typo'})

    def test_identity_type_and_exact_fingerprint(self):
        identity = 'A'*40
        development = '  1) '+identity+' "Apple Development: Synthetic"\n'
        public = '  1) '+identity+' "Developer ID Application: Synthetic"\n'
        sign_bundle.validate_identity(development, identity, 'development')
        sign_bundle.validate_identity(public, identity, 'developer-id')
        with self.assertRaisesRegex(ValueError, 'Developer ID'): sign_bundle.validate_identity(development, identity, 'developer-id')
        with self.assertRaisesRegex(ValueError, 'existing valid'): sign_bundle.validate_identity(public, 'B'*40, 'developer-id')

    def test_formula_uses_bundle_and_immutable_archive(self):
        result = release.formula_text('v1.2.3', 'NikitaKurpas/keylet', 'a'*64, 'b'*64)
        self.assertNotIn('@VERSION@', result)
        self.assertIn('libexec.install "Keylet.app"', result)
        self.assertIn('service do', result)
        self.assertIn('post_install_steps do', result)
        self.assertIn('run "keylet-verify-install", base: :libexec', result)
        self.assertNotIn('def post_install', result)
        self.assertNotIn('  version ', result)
        self.assertIn('if digest !=', result)
        self.assertIn('b'*64, result)
        self.assertIn('KEYLET_KEY_ID', result)
        self.assertNotIn('codesign --force', result)
        self.assertIn('Contents/MacOS/keylet', result)
        self.assertIn('depends_on arch: :arm64', result)
        self.assertNotIn('zap', result)
        for repository, checksum in [('owner/repo"', 'a'*64), ('owner/repo', 'fake')]:
            with self.assertRaises(ValueError): release.formula_text('v1.2.3', repository, checksum, 'b'*64)

    def test_formula_rejects_invalid_binary_digest(self):
        for value in ['fake', 'a'*63, 'A'*64, 'a'*64+'\n']:
            with self.assertRaises(ValueError):
                release.formula_text('v1.2.3', 'owner/repo', 'a'*64, value)

    def test_archive_executable_must_be_unique_regular_and_nonempty(self):
        name = 'Keylet.app/Contents/MacOS/keylet'
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary)/'fixture.zip'
            for contents, mode in [(b'', 0o100755), (b'public fixture', 0o120777), (b'public fixture', 0o040755)]:
                with zipfile.ZipFile(path, 'w') as archive:
                    entry = zipfile.ZipInfo(name)
                    entry.external_attr = mode << 16
                    archive.writestr(entry, contents)
                with self.assertRaises(ValueError): release.archive_binary_digest(path)
            with zipfile.ZipFile(path, 'w') as archive:
                archive.writestr('unrelated', b'public fixture')
            with self.assertRaises(ValueError): release.archive_binary_digest(path)

    def test_secret_file_is_private_and_never_overwritten(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = release.write_secret(Path(temporary), 'fixture', base64.b64encode(b'noncredential fixture').decode())
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            with self.assertRaises(FileExistsError): release.write_secret(Path(temporary), 'fixture', 'YQ==')
            self.assertEqual(path.read_bytes(), b'noncredential fixture')

    def test_workflow_is_credential_free_until_trusted_release(self):
        ci = (release.ROOT/'.github/workflows/ci.yml').read_text()
        workflow = (release.ROOT/'.github/workflows/release.yml').read_text()
        self.assertNotIn('secrets.', ci)
        self.assertNotIn('pull_request_target', ci+workflow)
        self.assertNotIn('pull_request:', workflow)
        self.assertIn('environment: release', workflow)
        self.assertIn("github.event_name != 'workflow_dispatch' || github.ref == 'refs/heads/main'", workflow)
        self.assertIn('merge-base --is-ancestor HEAD origin/main', workflow)
        self.assertIn('persist-credentials: false', workflow)
        self.assertLess(workflow.index('make test'), workflow.index('secrets.DEVELOPER_ID'))
        self.assertLess(workflow.index('Publish verified release'), workflow.index('secrets.TAP_TOKEN'))
        self.assertIn('make bundle', workflow)
        for text in [ci, workflow]:
            self.assertIn('actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683', text)

    def test_failed_signing_always_deletes_explicit_temporary_keychain(self):
        calls = []
        active = ['/fixture/login.keychain-db']
        def command(args, **kwargs):
            nonlocal active
            calls.append(args)
            if args[:5] == ['security','list-keychains','-d','user','-s']:
                active = args[5:]
            if args == ['security','list-keychains','-d','user']:
                return ('\n'.join('"'+name+'"' for name in active)+'\n').encode()
            return b''
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            contents = root/'dist/Keylet.app/Contents'
            contents.mkdir(parents=True)
            (contents/'Info.plist').write_bytes(plistlib.dumps({}))
            environment = {name:base64.b64encode(b'noncredential fixture').decode()
                for name in ['DEVELOPER_ID_P12_BASE64','DEVELOPER_ID_PROFILE_BASE64','NOTARY_KEY_BASE64']}
            environment.update(DEVELOPER_ID_P12_PASSWORD='noncredential fixture', DEVELOPER_ID_IDENTITY='A'*40, APPLE_TEAM_ID='EXAMPL1234')
            with patch.object(release,'ROOT',root), patch.object(release,'check_tools'), patch.object(sign_bundle,'validate_bundle'), patch.object(release,'run',side_effect=command), patch.object(release,'run_signer',side_effect=ValueError('Synthetic signing failure')), patch.dict(os.environ,environment,clear=True):
                with self.assertRaisesRegex(ValueError,'Synthetic signing failure'): release.prepare('v1.2.3')
        self.assertEqual(calls[-1][:2], ['security','delete-keychain'])
        created = next(args[-1] for args in calls if args[:2] == ['security','create-keychain'])
        self.assertEqual(calls[-1][-1], created)
        self.assertFalse(Path(created).parent.exists())
        self.assertIn(['security','list-keychains','-d','user','-s','/fixture/login.keychain-db'], calls)
        self.assertFalse(any('default-keychain' in args for args in calls))

    def test_search_list_is_explicit_ordered_and_normalizes_path_aliases(self):
        keychain = Path('/tmp/keylet-public-fixture/keychain-db')
        previous = ['/fixture/login with spaces.keychain-db', '/fixture/other.keychain-db']
        observed = ('\n'.join('"'+str(Path(name).resolve())+'"' for name in [str(keychain)]+previous)).encode()
        with patch.object(release, 'run', side_effect=[b'', observed]) as mocked:
            release.configure_keychain_search_list(keychain, previous)
        self.assertEqual(mocked.call_args_list[0].args[0], ['security','list-keychains','-d','user','-s',str(keychain)]+previous)
        self.assertEqual(previous, ['/fixture/login with spaces.keychain-db', '/fixture/other.keychain-db'])
        for bad in [previous, [str(keychain)], previous+[str(keychain)]]:
            with patch.object(release, 'run', side_effect=[b'', ('\n'.join('"'+name+'"' for name in bad)).encode()]):
                with self.assertRaisesRegex(ValueError, 'temporary_keychain_search_list_failed'):
                    release.configure_keychain_search_list(keychain, previous)
        for error in [OSError('SENSITIVE_FIXTURE'), ValueError('SENSITIVE_FIXTURE')]:
            with patch.object(release, 'run', side_effect=error):
                with self.assertRaisesRegex(ValueError, 'temporary_keychain_search_list_failed') as caught:
                    release.configure_keychain_search_list(keychain, previous)
            self.assertNotIn('SENSITIVE_FIXTURE', str(caught.exception))

    def test_signing_check_skips_release_and_always_attempts_cleanup(self):
        for fault in ['none', 'signer', 'restore', 'signer-and-restore', 'create', 'readback']:
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                contents = root/'dist/Keylet.app/Contents'
                contents.mkdir(parents=True)
                original_info = plistlib.dumps({'CFBundleVersion':'unchanged fixture'})
                (contents/'Info.plist').write_bytes(original_info)
                calls, active = [], ['/fixture/login with spaces.keychain-db']
                created = []
                def command(args, **kwargs):
                    nonlocal active
                    calls.append(args)
                    if args[:2] == ['security','create-keychain']:
                        created.append(args[-1])
                        if fault == 'create': raise ValueError('Synthetic create failure')
                    if args[:5] == ['security','list-keychains','-d','user','-s']:
                        if len(args) == 6 and fault in ['restore', 'signer-and-restore']:
                            raise OSError('SENSITIVE_FIXTURE')
                        active = args[5:]
                    if args == ['security','list-keychains','-d','user']:
                        values = active if fault != 'readback' or len(active) == 1 else []
                        return ('\n'.join('"'+name+'"' for name in values)).encode()
                    return b''
                environment = {name:base64.b64encode(b'noncredential fixture').decode()
                    for name in ['DEVELOPER_ID_P12_BASE64','DEVELOPER_ID_PROFILE_BASE64']}
                environment.update(DEVELOPER_ID_P12_PASSWORD='noncredential fixture', DEVELOPER_ID_IDENTITY='A'*40, APPLE_TEAM_ID='EXAMPL1234')
                stdout, stderr = io.StringIO(), io.StringIO()
                side_effect = ValueError('Synthetic signing failure') if fault in ['signer','signer-and-restore'] else None
                with patch.object(release,'ROOT',root), patch.object(release,'check_tools'), patch.object(sign_bundle,'validate_bundle'), patch.object(release,'run',side_effect=command), patch.object(release,'run_signer',side_effect=side_effect) as signer_mock, patch.object(release,'api',side_effect=AssertionError('No publication')), patch.dict(os.environ,environment,clear=True), contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                    if fault == 'none': release.prepare(None)
                    else:
                        expected = {'signer':'Synthetic signing failure', 'restore':'cleanup failed', 'signer-and-restore':'Synthetic signing failure', 'create':'Synthetic create failure', 'readback':'temporary_keychain_search_list_failed'}[fault]
                        with self.assertRaisesRegex(ValueError, expected): release.prepare(None)
                self.assertEqual((contents/'Info.plist').read_bytes(), original_info)
                self.assertEqual(calls[-1], ['security','delete-keychain',created[0]])
                self.assertIn(['security','list-keychains','-d','user','-s','/fixture/login with spaces.keychain-db'], calls)
                self.assertFalse(Path(created[0]).parent.exists())
                self.assertFalse(any(args[0] in ['ditto','xcrun','gh','codesign','spctl'] for args in calls))
                self.assertNotIn('SENSITIVE_FIXTURE', stdout.getvalue()+stderr.getvalue())
                self.assertFalse(list((root/'dist').glob('*.zip*')))
                if fault in ['create','readback']: signer_mock.assert_not_called()
                else:
                    signer_mock.assert_called_once()
                    self.assertEqual(signer_mock.call_args.args[0]['SIGNING_KEYCHAIN'], created[0])
                    self.assertEqual(signer_mock.call_args.args[0]['SIGNING_MODE'], 'developer-id')
                if fault == 'none': self.assertIn('Signing check passed', stdout.getvalue())
                else: self.assertNotIn('Signing check passed', stdout.getvalue())

    def test_signing_check_workflow_is_main_only_and_cannot_publish(self):
        workflow = (release.ROOT/'.github/workflows/signing-check.yml').read_text()
        self.assertIn('workflow_dispatch:', workflow)
        self.assertIn("if: github.ref == 'refs/heads/main'", workflow)
        self.assertIn('ref: ${{ github.sha }}', workflow)
        self.assertIn('environment: release', workflow)
        self.assertIn('contents: read', workflow)
        self.assertIn('persist-credentials: false', workflow)
        self.assertIn('actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683', workflow)
        self.assertIn('python3 scripts/release.py check-signing', workflow)
        self.assertLess(workflow.index('make test'), workflow.index('secrets.DEVELOPER_ID'))
        for forbidden in ['contents: write','push:','pull_request','NOTARY_','TAP_TOKEN','GH_TOKEN','release.py publish','release.py tap','upload-artifact']:
            self.assertNotIn(forbidden, workflow)

    def test_tap_accepts_only_this_run_artifact_and_validates_remote_bytes(self):
        repo = 'NikitaKurpas/keylet'
        prefix = 'https://github.com/'+repo+'/releases/download/v1.2.3/'
        name = 'Keylet-1.2.3-arm64.zip'
        metadata = {'assets':[{'name':name,'browser_download_url':prefix+name},
            {'name':name+'.sha256','browser_download_url':prefix+name+'.sha256'}]}
        fixture = io.BytesIO()
        with zipfile.ZipFile(fixture, 'w') as archive:
            archive.writestr('Keylet.app/Contents/MacOS/keylet', b'public noncredential binary fixture')
        original = fixture.getvalue()
        altered = b'different noncredential fixture'
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root/'dist').mkdir()
            (root/'packaging').mkdir()
            (root/'packaging/keylet.rb.in').write_text((release.ROOT/'packaging/keylet.rb.in').read_text())
            (root/'dist'/name).write_bytes(original)
            digest = hashlib.sha256(original).hexdigest()
            (root/'dist'/(name+'.sha256')).write_text(digest+'  '+name+'\n')
            def execute(remote_digest, archive, expected_error=None):
                def response(url, **kwargs):
                    if url.endswith('.sha256'): return io.BytesIO((remote_digest+'  '+name+'\n').encode())
                    return io.BytesIO(archive)
                def api_response(method, endpoint, token, body=None):
                    if '/releases/tags/' in endpoint: return metadata
                    if method == 'GET': return {'sha':'previous-formula-sha'}
                    return {'content':{'sha':'updated-formula-sha'}}
                with patch.object(release,'ROOT',root), patch.dict(os.environ,{'GITHUB_REPOSITORY':repo,'TAP_TOKEN':'noncredential fixture','GH_TOKEN':'noncredential fixture'},clear=True), patch.object(release,'api',side_effect=api_response) as api_mock, patch.object(release.urllib.request,'urlopen',side_effect=response):
                    if expected_error:
                        with self.assertRaisesRegex(ValueError,expected_error): release.update_tap('v1.2.3')
                        self.assertEqual(api_mock.call_count,1)
                    else:
                        release.update_tap('v1.2.3')
                        self.assertEqual(api_mock.call_count,3)
                        args = api_mock.call_args.args
                        self.assertEqual(args[0],'PUT')
                        self.assertTrue(args[1].endswith('/contents/Formula/keylet.rb'))
                        self.assertIn(hashlib.sha256(b'public noncredential binary fixture').hexdigest(),base64.b64decode(args[3]['content']).decode())
                        self.assertEqual(args[3]['sha'],'previous-formula-sha')
                        self.assertIn(digest,base64.b64decode(args[3]['content']).decode())
            execute(digest,original)
            execute(hashlib.sha256(altered).hexdigest(),altered,'differs from this run')
            execute(digest,altered,'checksum mismatch')

    def test_missing_inputs_and_bad_tag_fail_before_operations(self):
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(ValueError, 'Missing release input'): release.require_env('NOTARY_KEY_ID')
        with self.assertRaisesRegex(ValueError, 'Release tag'): release.prepare('main')

if __name__ == '__main__': unittest.main()
