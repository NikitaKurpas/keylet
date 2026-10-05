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


def inputs(environment):
    profile = environment.get('PROFILE', '').strip()
    identity = environment.get('IDENTITY', '').strip().upper()
    team = environment.get('TEAM_ID', '').strip().upper()
    if not profile or not re.fullmatch(r'[0-9A-F]{40}', identity) or not re.fullmatch(r'[A-Z0-9]{10}', team):
        raise ValueError('Set PROFILE to the downloaded Mac development profile, IDENTITY to its existing certificate SHA-1, and TEAM_ID to the ten-character team ID')
    return Path(profile).expanduser(), identity, team


def permits(pattern, value):
    return isinstance(pattern, str) and (pattern == value or
        (pattern.endswith('*') and pattern.count('*') == 1 and value.startswith(pattern[:-1])))


def validate_profile(profile, *, team, identity, device_ids, now, mode='development'):
    if mode not in ['development', 'developer-id']: raise ValueError('Unknown signing mode')
    """Pure metadata checks. CMS/platform authorization remains the OS's responsibility."""
    if not isinstance(profile, dict):
        raise ValueError('Profile payload is not a property-list dictionary')
    expected = team + '.' + IDENTIFIER
    entitlements = profile.get('Entitlements', {})
    if not isinstance(entitlements, dict):
        raise ValueError('Profile has no entitlement dictionary')
    if team not in profile.get('TeamIdentifier', []) or entitlements.get('com.apple.developer.team-identifier') != team:
        raise ValueError('Profile team does not match TEAM_ID')
    if team not in profile.get('ApplicationIdentifierPrefix', []):
        raise ValueError('Profile App ID prefix differs from the enforced team-derived Keychain group')
    if entitlements.get('com.apple.application-identifier') != expected:
        raise ValueError('Profile must authorize the explicit App ID ' + expected)
    if entitlements.get('com.apple.security.hardened-process') is not True:
        raise ValueError('Profile must authorize the hardened-process entitlement; obtain an Enhanced Security profile')
    if entitlements.get('com.apple.security.hardened-process.enhanced-security-version-string') not in ['*', '2']:
        raise ValueError('Profile must authorize Enhanced Security version 2 (2 or wildcard); obtain a matching profile')
    groups = entitlements.get('keychain-access-groups', [])
    if not isinstance(groups, list) or not any(permits(group, expected) for group in groups):
        raise ValueError('Profile does not authorize the dedicated Keychain group ' + expected)
    expiry = profile.get('ExpirationDate')
    if not isinstance(expiry, dt.datetime):
        raise ValueError('Profile has no valid expiration date')
    if expiry.tzinfo is None:
        expiry = expiry.replace(tzinfo=dt.timezone.utc)
    if expiry <= now:
        raise ValueError('Provisioning profile has expired; download a current profile')
    certificates = profile.get('DeveloperCertificates', [])
    if not isinstance(certificates, list) or not any(isinstance(cert, bytes) and hashlib.sha1(cert).hexdigest().upper() == identity for cert in certificates):
        raise ValueError('Profile does not include the selected signing certificate')
    if mode == 'developer-id':
        if profile.get('ProvisionsAllDevices') is not True or profile.get('ProvisionedDevices'):
            raise ValueError('Developer ID profile must authorize all devices without registered-device restrictions')
        if entitlements.get('com.apple.security.get-task-allow') is True:
            raise ValueError('Developer ID profile must not enable debugging')
        return
    devices = profile.get('ProvisionedDevices', [])
    if not isinstance(devices, list) or not device_ids or not any(isinstance(device, str) and device.upper() in device_ids for device in devices):
        raise ValueError('Profile does not include this Mac; select its registered provisioning device ID')


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
        raise ValueError('Maintained template must specify Enhanced Security version 2')
    if result.get('com.apple.security.get-task-allow') is True:
        raise ValueError('Debugging entitlement is forbidden in this signing path')
    return result


def command(arguments, *, capture=True):
    try:
        return subprocess.run(arguments, check=True, capture_output=capture).stdout
    except subprocess.CalledProcessError:
        raise ValueError('Command failed: ' + Path(arguments[0]).name + '; verify its inputs and local authorization') from None


def validate_bundle(root, app):
    """Reject symlinks/nonregular destinations before any identity lookup or signing."""
    directories = [root / 'dist', app, app / 'Contents', app / 'Contents/MacOS', app / 'Contents/Resources']
    if any(path.is_symlink() or not path.is_dir() for path in directories):
        raise ValueError('Use regular bundle directories produced by make bundle; symlinks are refused')
    info = app / 'Contents/Info.plist'
    binary = app / 'Contents/MacOS/keylet'
    files = [info, binary, app / 'Contents/Resources/LICENSE', app / 'Contents/Resources/NOTICE.md']
    if any(path.is_symlink() or not path.is_file() for path in files):
        raise ValueError('Bundle inputs must be regular files; symlinks are refused')
    embedded = app / 'Contents/embedded.provisionprofile'
    if embedded.is_symlink() or (embedded.exists() and not embedded.is_file()):
        raise ValueError('Embedded profile destination must be absent or a regular file; symlinks are refused')
    # This bare CLI bundle has no legitimate symlinks or special files, including signature metadata.
    for directory, folders, names in os.walk(app, followlinks=False):
        for name in folders + names:
            node = Path(directory) / name
            metadata = node.lstat()
            if not (stat.S_ISDIR(metadata.st_mode) or stat.S_ISREG(metadata.st_mode)):
                raise ValueError('Bundle tree contains a symlink or special file; rebuild a regular bundle')
            if stat.S_ISREG(metadata.st_mode) and metadata.st_nlink != 1:
                raise ValueError('Bundle tree contains a hard-linked file; rebuild a regular bundle')
    if plistlib.loads(info.read_bytes()).get('CFBundleIdentifier') != IDENTIFIER:
        raise ValueError('Bundle identifier differs from ' + IDENTIFIER)
    for name in ['LICENSE', 'NOTICE.md']:
        if (app / ('Contents/Resources/' + name)).read_bytes() != (root / name).read_bytes():
            raise ValueError('Bundle must contain unchanged ' + name)
    license_source = root / 'licenses/swift-argument-parser-LICENSE.txt'
    license_copy = app / 'Contents/Resources/Licenses/swift-argument-parser-LICENSE.txt'
    if not license_source.is_file() or not license_copy.is_file() or license_copy.read_bytes() != license_source.read_bytes():
        raise ValueError('Bundle must contain unchanged swift-argument-parser license')


def validate_identity(available, identity, mode):
    match = re.search(r'^\s*\d+\)\s+' + re.escape(identity) + r'\s+"([^"\n]+)"', available, re.MULTILINE)
    if not match:
        raise ValueError('Selected identity is not an existing valid local code-signing identity')
    if mode == 'developer-id' and not match.group(1).startswith('Developer ID Application:'):
        raise ValueError('Public release requires a Developer ID Application identity')


def signing_mode(environment):
    mode = environment.get('SIGNING_MODE') or 'development'
    if mode not in ['development', 'developer-id']: raise ValueError('Unknown signing mode')
    return mode


def main():
    mode = signing_mode(os.environ)
    keychain = os.environ.get('SIGNING_KEYCHAIN', '')
    profile_path, identity, team = inputs(os.environ)
    version = tuple(int(part) for part in platform.mac_ver()[0].split('.')[:2])
    if version < (26, 4):
        raise ValueError('This version-2 policy requires macOS 26.4 or later')
    root = Path(__file__).resolve().parent.parent
    app = root / 'dist/Keylet.app'
    validate_bundle(root,app)
    if not profile_path.is_file():
        raise ValueError('PROFILE must name a readable regular provisioning-profile file')
    identity_command = ['/usr/bin/security', 'find-identity', '-v', '-p', 'codesigning']
    if keychain: identity_command.append(keychain)
    available = command(identity_command).decode()
    validate_identity(available, identity, mode)
    device_ids = set()
    if mode == 'development':
        hardware = json.loads(command(['/usr/sbin/system_profiler', '-json', 'SPHardwareDataType']))
        device_ids = hardware_ids(hardware)
    template = plistlib.loads((root / 'packaging/Entitlements.plist.in').read_bytes())
    entitlements = generated_entitlements(template, team)
    # Read once and validate the exact bytes subsequently embedded; never leave decoded profile data behind.
    with tempfile.TemporaryDirectory(prefix='sign-', dir=root / 'dist') as temporary:
        directory = Path(temporary)
        profile_copy = directory / 'profile.provisionprofile'
        profile_copy.write_bytes(profile_path.read_bytes())
        payload = plistlib.loads(command(['/usr/bin/security', 'cms', '-D', '-i', str(profile_copy)]))
        validate_profile(payload, team=team, identity=identity, device_ids=device_ids, now=dt.datetime.now(dt.timezone.utc), mode=mode)
        signing_plist = directory / 'Entitlements.plist'
        signing_plist.write_bytes(plistlib.dumps(entitlements))
        shutil.copyfile(profile_copy, app / 'Contents/embedded.provisionprofile')
        # No shell interpolation, profile creation, certificate creation, keys or agent launch.
        command(['/usr/bin/codesign', '--force', '--sign', identity, '--identifier', IDENTIFIER,
            '--options', 'runtime', '--timestamp' if mode == 'developer-id' else '--timestamp=none',
            '--entitlements', str(signing_plist)] + (['--keychain', keychain] if keychain else []) + [str(app)], capture=False)
        command(['/usr/bin/codesign', '--verify', '--strict', '--verbose=2', str(app)], capture=False)
    print('Signed and verified dist/Keylet.app. Run its executable with --json doctor; no key was created.')


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, plistlib.InvalidFileException, json.JSONDecodeError, TypeError, AttributeError) as error:
        # OSError carries no key material; avoid echoing profile payloads or command stderr.
        message = str(error) if isinstance(error, ValueError) and not isinstance(error, json.JSONDecodeError) else 'Cannot read or parse local signing inputs; check profile, bundle and tool availability'
        print('sign: ' + message, file=sys.stderr)
        sys.exit(1)
