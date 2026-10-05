#!/usr/bin/env python3
"""Explicit user-invoked local development signing; no provisioning or credential creation.

Apple references:
https://developer.apple.com/documentation/technotes/tn3125-inside-code-signing-provisioning-profiles
https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.hardened-process
https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.hardened-process.enhanced-security-version-string
"""
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import plistlib
import platform
import re
import shutil
import stat
import subprocess
import sys
import tempfile

IDENTIFIER = 'me.kurpas.keylet'


# Opt-in child/parent protocol: only these fixed numeric statuses cross the
# release boundary. Never infer a diagnosis from credential-bearing tool output.
SIGNING_EXIT_CODES = {
    'invalid_inputs': 64,
    'unknown_signing_mode': 65,
    'unsupported_runtime': 66,
    'bundle_invalid': 67,
    'profile_file_unavailable': 68,
    'identity_lookup_failed': 69,
    'identity_not_found': 70,
    'identity_not_developer_id': 71,
    'hardware_lookup_failed': 72,
    'template_policy_invalid': 73,
    'profile_cms_decode_failed': 74,
    'profile_payload_invalid': 75,
    'profile_entitlements_invalid': 76,
    'profile_team_mismatch': 77,
    'profile_prefix_mismatch': 78,
    'profile_app_id_mismatch': 79,
    'profile_hardened_process_missing': 80,
    'profile_enhanced_security_missing': 81,
    'profile_keychain_group_missing': 82,
    'profile_expiry_invalid': 83,
    'profile_expired': 84,
    'profile_certificate_missing': 85,
    'profile_not_all_devices': 86,
    'profile_debugging_enabled': 87,
    'profile_device_missing': 88,
    'codesign_failed': 89,
    'signature_verification_failed': 90,
    'command_failed': 91,
    'signing_input_read_or_parse_failed': 92,
    'signing_unexpected_failure': 93,
}


class SigningError(ValueError):
    def __init__(self, code, message):
        if code not in SIGNING_EXIT_CODES:
            raise ValueError('Unknown signing diagnostic code')
        super().__init__(message)
        self.code = code


def diagnostic_mode(environment):
    return environment.get('KEYLET_SIGN_DIAGNOSTICS') == 'exit-code-v1'


def inputs(environment):
    profile = environment.get('PROFILE', '').strip()
    identity = environment.get('IDENTITY', '').strip().upper()
    team = environment.get('TEAM_ID', '').strip().upper()
    if not profile or not re.fullmatch(r'[0-9A-F]{40}', identity) or not re.fullmatch(r'[A-Z0-9]{10}', team):
        raise SigningError('invalid_inputs', 'Set PROFILE to the downloaded Mac development profile, IDENTITY to its existing certificate SHA-1, and TEAM_ID to the ten-character team ID')
    return Path(profile).expanduser(), identity, team


def permits(pattern, value):
    return isinstance(pattern, str) and (pattern == value or
        (pattern.endswith('*') and pattern.count('*') == 1 and value.startswith(pattern[:-1])))


def validate_profile(profile, *, team, identity, device_ids, now, mode='development'):
    if mode not in ['development', 'developer-id']: raise SigningError('unknown_signing_mode', 'Unknown signing mode')
    """Pure metadata checks. CMS/platform authorization remains the OS's responsibility."""
    if not isinstance(profile, dict):
        raise SigningError('profile_payload_invalid', 'Profile payload is not a property-list dictionary')
    expected = team + '.' + IDENTIFIER
    entitlements = profile.get('Entitlements', {})
    if not isinstance(entitlements, dict):
        raise SigningError('profile_entitlements_invalid', 'Profile has no entitlement dictionary')
    if team not in profile.get('TeamIdentifier', []) or entitlements.get('com.apple.developer.team-identifier') != team:
        raise SigningError('profile_team_mismatch', 'Profile team does not match TEAM_ID')
    if team not in profile.get('ApplicationIdentifierPrefix', []):
        raise SigningError('profile_prefix_mismatch', 'Profile App ID prefix differs from the enforced team-derived Keychain group')
    if entitlements.get('com.apple.application-identifier') != expected:
        raise SigningError('profile_app_id_mismatch', 'Profile must authorize the explicit App ID ' + expected)
    if entitlements.get('com.apple.security.hardened-process') is not True:
        raise SigningError('profile_hardened_process_missing', 'Profile must authorize the hardened-process entitlement; obtain an Enhanced Security profile')
    if entitlements.get('com.apple.security.hardened-process.enhanced-security-version-string') not in ['*', '2']:
        raise SigningError('profile_enhanced_security_missing', 'Profile must authorize Enhanced Security version 2 (2 or wildcard); obtain a matching profile')
    groups = entitlements.get('keychain-access-groups', [])
    if not isinstance(groups, list) or not any(permits(group, expected) for group in groups):
        raise SigningError('profile_keychain_group_missing', 'Profile does not authorize the dedicated Keychain group ' + expected)
    expiry = profile.get('ExpirationDate')
    if not isinstance(expiry, dt.datetime):
        raise SigningError('profile_expiry_invalid', 'Profile has no valid expiration date')
    if expiry.tzinfo is None:
        expiry = expiry.replace(tzinfo=dt.timezone.utc)
    if expiry <= now:
        raise SigningError('profile_expired', 'Provisioning profile has expired; download a current profile')
    certificates = profile.get('DeveloperCertificates', [])
    if not isinstance(certificates, list) or not any(isinstance(cert, bytes) and hashlib.sha1(cert).hexdigest().upper() == identity for cert in certificates):
        raise SigningError('profile_certificate_missing', 'Profile does not include the selected signing certificate')
    if mode == 'developer-id':
        if profile.get('ProvisionsAllDevices') is not True or profile.get('ProvisionedDevices'):
            raise SigningError('profile_not_all_devices', 'Developer ID profile must authorize all devices without registered-device restrictions')
        if entitlements.get('com.apple.security.get-task-allow') is True:
            raise SigningError('profile_debugging_enabled', 'Developer ID profile must not enable debugging')
        return
    devices = profile.get('ProvisionedDevices', [])
    if not isinstance(devices, list) or not device_ids or not any(isinstance(device, str) and device.upper() in device_ids for device in devices):
        raise SigningError('profile_device_missing', 'Profile does not include this Mac; select its registered provisioning device ID')


def hardware_ids(hardware):
    rows = hardware.get('SPHardwareDataType', [])
    provisioned = {str(value).upper() for row in rows for key, value in row.items()
        if key.lower() == 'provisioning_udid' and value}
    if provisioned:
        return provisioned
    return {str(value).upper() for row in rows for key, value in row.items()
        if key.lower() in ['platform_uuid', 'sp_hardware_uuid'] and value}


def generated_entitlements(template, team):
    def replace(value):
        if isinstance(value, str):
            return value.replace('TEAM_ID', team)
        if isinstance(value, list):
            return [replace(item) for item in value]
        if isinstance(value, dict):
            return {key: replace(item) for key, item in value.items()}
        return value
    result = replace(template)
    if result.get('com.apple.security.hardened-process.enhanced-security-version-string') != '2':
        raise SigningError('template_policy_invalid', 'Maintained template must specify Enhanced Security version 2')
    if result.get('com.apple.security.get-task-allow') is True:
        raise SigningError('template_policy_invalid', 'Debugging entitlement is forbidden in this signing path')
    return result


def command(arguments, *, capture=True, failure_code='command_failed'):
    try:
        return subprocess.run(arguments, check=True, capture_output=capture or diagnostic_mode(os.environ)).stdout
    except (subprocess.CalledProcessError, OSError):
        raise SigningError(failure_code, 'Signing tool failed; verify its inputs and authorization') from None


def validate_bundle(root, app):
    """Reject symlinks/nonregular destinations before any identity lookup or signing."""
    directories = [root / 'dist', app, app / 'Contents', app / 'Contents/MacOS', app / 'Contents/Resources']
    if any(path.is_symlink() or not path.is_dir() for path in directories):
        raise SigningError('bundle_invalid', 'Use regular bundle directories produced by make bundle; symlinks are refused')
    info = app / 'Contents/Info.plist'
    binary = app / 'Contents/MacOS/keylet'
    files = [info, binary, app / 'Contents/Resources/LICENSE', app / 'Contents/Resources/NOTICE.md']
    if any(path.is_symlink() or not path.is_file() for path in files):
        raise SigningError('bundle_invalid', 'Bundle inputs must be regular files; symlinks are refused')
    embedded = app / 'Contents/embedded.provisionprofile'
    if embedded.is_symlink() or (embedded.exists() and not embedded.is_file()):
        raise SigningError('bundle_invalid', 'Embedded profile destination must be absent or a regular file; symlinks are refused')
    # This bare CLI bundle has no legitimate symlinks or special files, including signature metadata.
    for directory, folders, names in os.walk(app, followlinks=False):
        for name in folders + names:
            node = Path(directory) / name
            metadata = node.lstat()
            if not (stat.S_ISDIR(metadata.st_mode) or stat.S_ISREG(metadata.st_mode)):
                raise SigningError('bundle_invalid', 'Bundle tree contains a symlink or special file; rebuild a regular bundle')
            if stat.S_ISREG(metadata.st_mode) and metadata.st_nlink != 1:
                raise SigningError('bundle_invalid', 'Bundle tree contains a hard-linked file; rebuild a regular bundle')
    if plistlib.loads(info.read_bytes()).get('CFBundleIdentifier') != IDENTIFIER:
        raise SigningError('bundle_invalid', 'Bundle identifier differs from ' + IDENTIFIER)
    for name in ['LICENSE', 'NOTICE.md']:
        if (app / ('Contents/Resources/' + name)).read_bytes() != (root / name).read_bytes():
            raise SigningError('bundle_invalid', 'Bundle must contain unchanged ' + name)
    license_source = root / 'licenses/swift-argument-parser-LICENSE.txt'
    license_copy = app / 'Contents/Resources/Licenses/swift-argument-parser-LICENSE.txt'
    if not license_source.is_file() or not license_copy.is_file() or license_copy.read_bytes() != license_source.read_bytes():
        raise SigningError('bundle_invalid', 'Bundle must contain unchanged swift-argument-parser license')


def validate_identity(available, identity, mode):
    match = re.search(r'^\s*\d+\)\s+' + re.escape(identity) + r'\s+"([^"\n]+)"', available, re.MULTILINE)
    if not match:
        raise SigningError('identity_not_found', 'Selected identity is not an existing valid local code-signing identity')
    if mode == 'developer-id' and not match.group(1).startswith('Developer ID Application:'):
        raise SigningError('identity_not_developer_id', 'Public release requires a Developer ID Application identity')


def signing_mode(environment):
    mode = environment.get('SIGNING_MODE') or 'development'
    if mode not in ['development', 'developer-id']: raise SigningError('unknown_signing_mode', 'Unknown signing mode')
    return mode


def main():
    mode = signing_mode(os.environ)
    keychain = os.environ.get('SIGNING_KEYCHAIN', '')
    profile_path, identity, team = inputs(os.environ)
    version = tuple(int(part) for part in platform.mac_ver()[0].split('.')[:2])
    if version < (26, 4):
        raise SigningError('unsupported_runtime', 'This version-2 policy requires macOS 26.4 or later')
    root = Path(__file__).resolve().parent.parent
    app = root / 'dist/Keylet.app'
    validate_bundle(root,app)
    if not profile_path.is_file():
        raise SigningError('profile_file_unavailable', 'PROFILE must name a readable regular provisioning-profile file')
    identity_command = ['/usr/bin/security', 'find-identity', '-v', '-p', 'codesigning']
    if keychain: identity_command.append(keychain)
    available = command(identity_command, failure_code='identity_lookup_failed').decode()
    validate_identity(available, identity, mode)
    device_ids = set()
    if mode == 'development':
        hardware = json.loads(command(['/usr/sbin/system_profiler', '-json', 'SPHardwareDataType'], failure_code='hardware_lookup_failed'))
        device_ids = hardware_ids(hardware)
    template = plistlib.loads((root / 'packaging/Entitlements.plist.in').read_bytes())
    entitlements = generated_entitlements(template, team)
    # Read once and validate the exact bytes subsequently embedded; never leave decoded profile data behind.
    with tempfile.TemporaryDirectory(prefix='sign-', dir=root / 'dist') as temporary:
        directory = Path(temporary)
        profile_copy = directory / 'profile.provisionprofile'
        profile_copy.write_bytes(profile_path.read_bytes())
        payload = plistlib.loads(command(['/usr/bin/security', 'cms', '-D', '-i', str(profile_copy)], failure_code='profile_cms_decode_failed'))
        validate_profile(payload, team=team, identity=identity, device_ids=device_ids, now=dt.datetime.now(dt.timezone.utc), mode=mode)
        signing_plist = directory / 'Entitlements.plist'
        signing_plist.write_bytes(plistlib.dumps(entitlements))
        shutil.copyfile(profile_copy, app / 'Contents/embedded.provisionprofile')
        # No shell interpolation, profile creation, certificate creation, keys or agent launch.
        command(['/usr/bin/codesign', '--force', '--sign', identity, '--identifier', IDENTIFIER,
            '--options', 'runtime', '--timestamp' if mode == 'developer-id' else '--timestamp=none',
            '--entitlements', str(signing_plist)] + (['--keychain', keychain] if keychain else []) + [str(app)], capture=False, failure_code='codesign_failed')
        command(['/usr/bin/codesign', '--verify', '--strict', '--verbose=2', str(app)], capture=False, failure_code='signature_verification_failed')
    print('Signed and verified dist/Keylet.app. Run its executable with --json doctor; no key was created.')


def cli():
    try:
        main()
        return 0
    except Exception as error:
        if diagnostic_mode(os.environ):
            if isinstance(error, SigningError):
                code = error.code
            elif isinstance(error, (ValueError, OSError, plistlib.InvalidFileException, json.JSONDecodeError, TypeError, AttributeError)):
                code = 'signing_input_read_or_parse_failed'
            else:
                code = 'signing_unexpected_failure'
            print('sign: ' + code, file=sys.stderr)
            return SIGNING_EXIT_CODES[code]
        # Preserve normal development error/exit behavior. No tool stderr is echoed.
        if not isinstance(error, (ValueError, OSError, plistlib.InvalidFileException, json.JSONDecodeError, TypeError, AttributeError)):
            raise
        message = str(error) if isinstance(error, ValueError) and not isinstance(error, json.JSONDecodeError) else 'Cannot read or parse local signing inputs; check profile, bundle and tool availability'
        print('sign: ' + message, file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(cli())
