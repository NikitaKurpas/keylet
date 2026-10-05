"""Synthetic public profile metadata only; importing the helper never runs main/signing."""
import copy
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
