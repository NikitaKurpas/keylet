"""Synthetic public profile metadata only; importing the helper never runs main/signing."""
import copy
import contextlib
import io
import subprocess
import datetime as dt
import hashlib
import plistlib
import os
from pathlib import Path
import unittest
import tempfile
from unittest.mock import patch
import sign_bundle as signer

TEAM = 'EXAMPL1234'
CERT = b'public certificate fixture; no cryptographic private key'
IDENTITY = hashlib.sha1(CERT).hexdigest().upper()
NOW = dt.datetime(2026, 10, 5, tzinfo=dt.timezone.utc)

class SigningMetadataTests(unittest.TestCase):
    def setUp(self):
        self.profile = {
            'TeamIdentifier': [TEAM], 'ApplicationIdentifierPrefix': [TEAM],
            'Entitlements': {'com.apple.developer.team-identifier': TEAM,
                'com.apple.application-identifier': TEAM + '.' + signer.IDENTIFIER,
                'keychain-access-groups': [TEAM + '.*'],
                'com.apple.security.hardened-process': True,
                'com.apple.security.hardened-process.enhanced-security-version-string': '*'},
            'ExpirationDate': NOW + dt.timedelta(days=1),
            'DeveloperCertificates': [CERT], 'ProvisionedDevices': ['THIS-MAC']}
        self.no_process = patch.object(signer.subprocess, 'run', side_effect=AssertionError('No external commands permitted in pure tests'))
        self.no_process.start()
        self.addCleanup(self.no_process.stop)

    def validate(self, profile=None):
        signer.validate_profile(self.profile if profile is None else profile,
            team=TEAM, identity=IDENTITY, device_ids={'THIS-MAC'}, now=NOW)

    def test_diagnostic_statuses_are_unique_and_fixed(self):
        values = list(signer.SIGNING_EXIT_CODES.values())
        self.assertEqual(len(values), len(set(values)))
        self.assertTrue(all(64 <= value < 126 for value in values))
        for code in signer.SIGNING_EXIT_CODES:
            stderr = io.StringIO()
            with patch.dict(os.environ, {'KEYLET_SIGN_DIAGNOSTICS':'exit-code-v1'}, clear=True), patch.object(signer, 'main', side_effect=signer.SigningError(code, 'SENSITIVE_FIXTURE')), contextlib.redirect_stderr(stderr):
                self.assertEqual(signer.cli(), signer.SIGNING_EXIT_CODES[code])
            self.assertEqual(stderr.getvalue(), 'sign: '+code+'\n')

    def test_diagnostic_untyped_errors_withhold_messages_and_local_exit_stays_one(self):
        for error in [ValueError('SENSITIVE_FIXTURE'), OSError('SENSITIVE_FIXTURE'), TypeError('SENSITIVE_FIXTURE'), RuntimeError('SENSITIVE_FIXTURE')]:
            stderr = io.StringIO()
            code = 'signing_unexpected_failure' if isinstance(error, RuntimeError) else 'signing_input_read_or_parse_failed'
            with patch.dict(os.environ, {'KEYLET_SIGN_DIAGNOSTICS':'exit-code-v1'}, clear=True), patch.object(signer, 'main', side_effect=error), contextlib.redirect_stderr(stderr):
                self.assertEqual(signer.cli(), signer.SIGNING_EXIT_CODES[code])
            self.assertEqual(stderr.getvalue(), 'sign: '+code+'\n')
        stderr = io.StringIO()
        with patch.dict(os.environ, {}, clear=True), patch.object(signer, 'main', side_effect=signer.SigningError('profile_expired', 'Public local guidance')), contextlib.redirect_stderr(stderr):
            self.assertEqual(signer.cli(), 1)
        self.assertEqual(stderr.getvalue(), 'sign: Public local guidance\n')
        with patch.dict(os.environ, {}, clear=True), patch.object(signer, 'main', side_effect=RuntimeError('Public unexpected fixture')):
            with self.assertRaises(RuntimeError): signer.cli()

    def test_diagnostic_commands_capture_raw_output_and_keep_only_named_stage(self):
        failure = subprocess.CalledProcessError(1, ['SENSITIVE_FIXTURE'], output=b'SENSITIVE_FIXTURE', stderr=b'SENSITIVE_FIXTURE')
        with patch.dict(os.environ, {'KEYLET_SIGN_DIAGNOSTICS':'exit-code-v1'}, clear=True), patch.object(signer.subprocess, 'run', side_effect=failure) as mocked:
            with self.assertRaises(signer.SigningError) as caught:
                signer.command(['SENSITIVE_FIXTURE'], capture=False, failure_code='codesign_failed')
            self.assertEqual(caught.exception.code, 'codesign_failed')
            self.assertNotIn('SENSITIVE_FIXTURE', str(caught.exception))
            self.assertTrue(mocked.call_args.kwargs['capture_output'])

    def test_codesign_categories_project_only_fixed_known_failure_phrases(self):
        cases = [
            (b'SENSITIVE_FIXTURE: user interaction is not allowed.', 'codesign_interaction_required'),
            (b'Warning: unable to build chain to self-signed root for signer SENSITIVE_FIXTURE\nerrSecInternalComponent', 'codesign_certificate_chain_failed'),
            (b'SENSITIVE_FIXTURE: CSSMERR_TP_NOT_TRUSTED', 'codesign_certificate_chain_failed'),
            (b'SENSITIVE_FIXTURE: The timestamp service is not available.', 'codesign_timestamp_failed'),
            (b'SENSITIVE_FIXTURE: resource fork, Finder information, or similar detritus not allowed', 'codesign_bundle_metadata_failed'),
            (b'SENSITIVE_FIXTURE: errSecInternalComponent', 'codesign_internal_component'),
            (b'SENSITIVE_FIXTURE: The specified item could not be found in the keychain.', 'codesign_keychain_item_missing'),
            (b'SENSITIVE_FIXTURE certificate timestamp resource unknown', 'codesign_failed'),
            (b'\xff errSecInternalComponent SENSITIVE_FIXTURE', 'codesign_failed'),
            (b'errSecInternalComponent'+b'x'*(64*1024), 'codesign_failed'),
            (None, 'codesign_failed')]
        for stderr, code in cases:
            self.assertEqual(signer.codesign_failure_category(stderr), code)
            failure = subprocess.CalledProcessError(1, ['SENSITIVE_FIXTURE'], output=b'SENSITIVE_FIXTURE', stderr=stderr)
            with patch.dict(os.environ, {'KEYLET_SIGN_DIAGNOSTICS':'exit-code-v1'}, clear=True), patch.object(signer.subprocess,'run',side_effect=failure):
                with self.assertRaises(signer.SigningError) as caught:
                    signer.command(['/usr/bin/codesign'], capture=False, failure_code='codesign_failed')
            self.assertEqual(caught.exception.code, code)
            self.assertNotIn('SENSITIVE_FIXTURE', str(caught.exception))
        failure = subprocess.CalledProcessError(1, [], stderr=b'errSecInternalComponent')
        for environment, stage in [({}, 'codesign_failed'), ({'KEYLET_SIGN_DIAGNOSTICS':'exit-code-v1'}, 'signature_verification_failed')]:
            with patch.dict(os.environ, environment, clear=True), patch.object(signer.subprocess,'run',side_effect=failure):
                with self.assertRaises(signer.SigningError) as caught:
                    signer.command(['/usr/bin/codesign'], failure_code=stage)
            self.assertEqual(caught.exception.code, stage)

    def test_profile_checks_return_specific_diagnostic_codes(self):
        cases = [('TeamIdentifier', ['OTHER12345'], 'profile_team_mismatch'),
                 ('ApplicationIdentifierPrefix', ['OTHER12345'], 'profile_prefix_mismatch'),
                 ('DeveloperCertificates', [], 'profile_certificate_missing'),
                 ('ExpirationDate', NOW, 'profile_expired')]
        for field, value, code in cases:
            profile = copy.deepcopy(self.profile)
            profile[field] = value
            with self.assertRaises(signer.SigningError) as caught: self.validate(profile)
            self.assertEqual(caught.exception.code, code)
        profile = copy.deepcopy(self.profile)
        profile['Entitlements']['com.apple.security.hardened-process.enhanced-security-version-string'] = '1'
        with self.assertRaises(signer.SigningError) as caught: self.validate(profile)
        self.assertEqual(caught.exception.code, 'profile_enhanced_security_missing')

    def test_valid_metadata_without_commands(self):
        self.validate()

    def test_wrong_team(self):
        self.profile['TeamIdentifier'] = ['OTHER12345']
        with self.assertRaisesRegex(ValueError, 'team'): self.validate()

    def test_wrong_prefix(self):
        self.profile['ApplicationIdentifierPrefix'] = ['OTHER12345']
        with self.assertRaisesRegex(ValueError, 'prefix'): self.validate()

    def test_wrong_app_id(self):
        self.profile['Entitlements']['com.apple.application-identifier'] = TEAM + '.old-app'
        with self.assertRaisesRegex(ValueError, 'explicit App ID'): self.validate()

    def test_exact_and_wildcard_group(self):
        self.profile['Entitlements']['keychain-access-groups'] = [TEAM + '.' + signer.IDENTIFIER]
        self.validate()
        self.assertFalse(signer.permits('OTHER.*', TEAM + '.' + signer.IDENTIFIER))
        self.assertFalse(signer.permits(TEAM + '.?*', TEAM + '.' + signer.IDENTIFIER))

    def test_enhanced_security_profile_authorization(self):
        self.validate()
        version='com.apple.security.hardened-process.enhanced-security-version-string'
        self.profile['Entitlements'][version]='2'
        self.validate()
        for value in [None,'1','3',2]:
            self.profile['Entitlements'][version]=value
            with self.assertRaisesRegex(ValueError, 'authorize Enhanced Security'): self.validate()
        self.profile['Entitlements'][version]='*'
        for value in [None,False,1]:
            self.profile['Entitlements']['com.apple.security.hardened-process']=value
            with self.assertRaisesRegex(ValueError, 'authorize the hardened-process'): self.validate()

    def test_bundle_rejects_profile_destination_and_directory_symlinks(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary)
            app=root/'dist/Keylet.app'
            for path in [app/'Contents/MacOS',app/'Contents/Resources']:
                path.mkdir(parents=True)
            (app/'Contents/Info.plist').write_bytes(plistlib.dumps({'CFBundleIdentifier':signer.IDENTIFIER}))
            (app/'Contents/MacOS/keylet').write_bytes(b'nonexecutable public fixture')
            for name in ['LICENSE','NOTICE.md']:
                (root/name).write_text('public notice fixture')
                (app/'Contents/Resources'/name).write_text('public notice fixture')
            (root/'licenses').mkdir()
            (app/'Contents/Resources/Licenses').mkdir()
            for path in [root/'licenses/swift-argument-parser-LICENSE.txt', app/'Contents/Resources/Licenses/swift-argument-parser-LICENSE.txt']:
                path.write_text('public dependency notice fixture')
            signer.validate_bundle(root,app)
            dependency_license = app/'Contents/Resources/Licenses/swift-argument-parser-LICENSE.txt'
            dependency_license.write_text('tampered public notice')
            with self.assertRaisesRegex(ValueError,'swift-argument-parser license'): signer.validate_bundle(root,app)
            dependency_license.write_text('public dependency notice fixture')
            embedded=app/'Contents/embedded.provisionprofile'
            external=root/'untouched'
            external.write_text('unchanged')
            embedded.symlink_to(external)
            with self.assertRaisesRegex(ValueError, 'Embedded profile'): signer.validate_bundle(root,app)
            self.assertEqual(external.read_text(),'unchanged')
            embedded.unlink()
            embedded.mkdir()
            with self.assertRaisesRegex(ValueError, 'Embedded profile'): signer.validate_bundle(root,app)
            embedded.rmdir()
            resources=app/'Contents/Resources'
            real=app/'Contents/SavedResources'
            resources.rename(real)
            resources.symlink_to(real,target_is_directory=True)
            with self.assertRaisesRegex(ValueError, 'directories'): signer.validate_bundle(root,app)
            resources.unlink()
            real.rename(resources)
            signature=app/'Contents/_CodeSignature'
            signature.symlink_to(root,target_is_directory=True)
            with self.assertRaisesRegex(ValueError, 'Bundle tree'): signer.validate_bundle(root,app)
            signature.unlink()
            special=app/'Contents/special-fixture'
            os.mkfifo(special)
            with self.assertRaisesRegex(ValueError, 'Bundle tree'): signer.validate_bundle(root,app)
            special.unlink()
            os.link(external,special)
            with self.assertRaisesRegex(ValueError, 'hard-linked'): signer.validate_bundle(root,app)
            special.unlink()


    def test_wrong_group(self):
        self.profile['Entitlements']['keychain-access-groups'] = ['OTHER.*']
        with self.assertRaisesRegex(ValueError, 'Keychain group'): self.validate()

    def test_expired_and_missing_expiry(self):
        self.profile['ExpirationDate'] = NOW
        with self.assertRaisesRegex(ValueError, 'expired'): self.validate()
        del self.profile['ExpirationDate']
        with self.assertRaisesRegex(ValueError, 'expiration'): self.validate()

    def test_naive_plist_date_is_utc(self):
        self.profile['ExpirationDate'] = (NOW + dt.timedelta(days=1)).replace(tzinfo=None)
        self.validate()

    def test_wrong_certificate(self):
        self.profile['DeveloperCertificates'] = [b'another public fixture']
        with self.assertRaisesRegex(ValueError, 'certificate'): self.validate()

    def test_wrong_or_missing_mac(self):
        self.profile['ProvisionedDevices'] = ['OTHER-MAC']
        with self.assertRaisesRegex(ValueError, 'this Mac'): self.validate()
        del self.profile['ProvisionedDevices']
        with self.assertRaisesRegex(ValueError, 'this Mac'): self.validate()

    def test_bad_inputs_and_profile_path_with_spaces(self):
        for values in [{}, {'PROFILE':'x', 'IDENTITY':'name', 'TEAM_ID':TEAM},
                {'PROFILE':'x', 'IDENTITY':IDENTITY, 'TEAM_ID':'bad'}]:
            with self.assertRaises(ValueError): signer.inputs(values)
        self.assertEqual(signer.inputs({'PROFILE':'/tmp/a profile', 'IDENTITY':IDENTITY.lower(), 'TEAM_ID':TEAM})[0], Path('/tmp/a profile'))

    def test_hardware_prefers_provisioning_udid(self):
        self.assertEqual(signer.hardware_ids({'SPHardwareDataType':[{'platform_UUID':'OLD', 'provisioning_UDID':'THIS-MAC', 'serial_number':'unused'}]}), {'THIS-MAC'})
        self.assertEqual(signer.hardware_ids({'SPHardwareDataType':[{'sp_hardware_uuid':'INTEL-MAC'}]}), {'INTEL-MAC'})

    def test_generated_template_pins_policy_without_personal_identifiers(self):
        template = plistlib.loads((Path(__file__).resolve().parent.parent / 'packaging/Entitlements.plist.in').read_bytes())
        result = signer.generated_entitlements(template, TEAM)
        self.assertEqual(result['keychain-access-groups'], [TEAM + '.' + signer.IDENTIFIER])
        self.assertEqual(result['com.apple.security.hardened-process.enhanced-security-version-string'], '2')
        self.assertTrue(result['com.apple.security.app-sandbox'])
        self.assertNotIn('com.apple.security.get-task-allow', result)
        bad = copy.deepcopy(template)
        bad['com.apple.security.hardened-process.enhanced-security-version-string'] = '*'
        with self.assertRaisesRegex(ValueError, 'version 2'): signer.generated_entitlements(bad, TEAM)
        bad = copy.deepcopy(template)
        bad['com.apple.security.get-task-allow'] = True
        with self.assertRaisesRegex(ValueError, 'Debugging'): signer.generated_entitlements(bad, TEAM)

if __name__ == '__main__':
    unittest.main()
