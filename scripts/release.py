#!/usr/bin/env python3
"""Trusted-release entry point. Never invoke with credentials from an untrusted checkout."""
import base64
import hashlib
import json
import os
from pathlib import Path
import plistlib
import platform
import re
import secrets
import shlex
import subprocess
import sys
import tempfile
import urllib.request
import urllib.error
import zipfile

ROOT = Path(__file__).resolve().parent.parent
TAP = 'NikitaKurpas/homebrew-tap'


def version(tag):
    if not re.fullmatch(r'v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)', tag):
        raise ValueError('Release tag must be vMAJOR.MINOR.PATCH')
    return tag[1:]


def run(args, *, env=None, capture=True):
    result = subprocess.run(args, env=env, stdout=subprocess.PIPE if capture else None,
                            stderr=subprocess.PIPE, check=False)
    if result.returncode:
        # Tools may echo credential inputs: never print their output on failure.
        raise ValueError('Release command failed: ' + Path(args[0]).name)
    return result.stdout or b''


def require_env(name):
    value = os.environ.get(name, '')
    if not value: raise ValueError('Missing release input: ' + name)
    return value


def write_secret(directory, name, encoded):
    value = base64.b64decode(encoded, validate=True)
    path = directory / name
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, 'wb') as stream: stream.write(value)
    return path


def check_tools():
    if tuple(map(int, platform.mac_ver()[0].split('.')[:2])) < (26, 4):
        raise ValueError('Release requires macOS 26.4+')
    sdk = run(['xcrun', '--sdk', 'macosx', '--show-sdk-version']).decode().strip()
    match = re.search(r'Swift version (\d+)\.(\d+)', run(['swift', '--version']).decode())
    if tuple(map(int, sdk.split('.')[:2])) < (26, 4) or not match or tuple(map(int, match.groups())) < (6, 2):
        raise ValueError('Release requires macOS SDK 26.4+ and Swift 6.2+')
    if run(['uname', '-m']).strip() != b'arm64': raise ValueError('Release runner must be arm64')


def prepare(tag):
    release_version = version(tag)
    check_tools()
    # Tests and build run in the earlier credential-free workflow step.
    app = ROOT / 'dist/Keylet.app'
    import sign_bundle
    sign_bundle.validate_bundle(ROOT, app)
    info_path = app / 'Contents/Info.plist'
    info = plistlib.loads(info_path.read_bytes())
    info['CFBundleShortVersionString'] = release_version
    info['CFBundleVersion'] = release_version
    info_path.write_bytes(plistlib.dumps(info))
    with tempfile.TemporaryDirectory(prefix='keylet-release-') as temporary:
        directory = Path(temporary)
        os.chmod(directory, 0o700)
        certificate = write_secret(directory, 'identity.p12', require_env('DEVELOPER_ID_P12_BASE64'))
        profile = write_secret(directory, 'release.provisionprofile', require_env('DEVELOPER_ID_PROFILE_BASE64'))
        notary_key = write_secret(directory, 'notary.p8', require_env('NOTARY_KEY_BASE64'))
        keychain = directory / 'release.keychain-db'
        password = secrets.token_hex(32)
        previous_search_list = shlex.split(run(['security', 'list-keychains', '-d', 'user']).decode())
        created = False
        try:
            run(['security', 'create-keychain', '-p', password, str(keychain)])
            created = True
            run(['security', 'set-keychain-settings', '-lut', '21600', str(keychain)])
            run(['security', 'unlock-keychain', '-p', password, str(keychain)])
            run(['security', 'import', str(certificate), '-k', str(keychain), '-P', require_env('DEVELOPER_ID_P12_PASSWORD'), '-T', '/usr/bin/codesign'])
            run(['security', 'set-key-partition-list', '-S', 'apple-tool:,apple:,codesign:', '-s', '-k', password, str(keychain)])
            env = dict(os.environ, PROFILE=str(profile), IDENTITY=require_env('DEVELOPER_ID_IDENTITY'),
                       TEAM_ID=require_env('APPLE_TEAM_ID'), SIGNING_MODE='developer-id', SIGNING_KEYCHAIN=str(keychain))
            run([sys.executable, str(ROOT / 'scripts/sign_bundle.py')], env=env)
            upload = directory / 'notarization.zip'
            run(['ditto', '-c', '-k', '--sequesterRsrc', '--keepParent', str(app), str(upload)])
            result = json.loads(run(['xcrun', 'notarytool', 'submit', str(upload), '--key', str(notary_key),
                '--key-id', require_env('NOTARY_KEY_ID'), '--issuer', require_env('NOTARY_ISSUER_ID'), '--wait', '--output-format', 'json']))
            if result.get('status') != 'Accepted': raise ValueError('Notarization did not return Accepted')
            run(['xcrun', 'stapler', 'staple', str(app)])
            run(['xcrun', 'stapler', 'validate', str(app)])
            run(['codesign', '--verify', '--strict', '--verbose=2', str(app)])
            run(['spctl', '--assess', '--type', 'execute', str(app)])
        finally:
            # Some OS versions add newly created keychains to the user search list.
            # Restore the exact previous list, then delete our keychain, even after tool failure.
            if created:
                active_error = sys.exc_info()[0] is not None
                cleanup_failed = False
                for arguments in [
                    ['security', 'list-keychains', '-d', 'user', '-s'] + previous_search_list,
                    ['security', 'delete-keychain', str(keychain)]]:
                    try: run(arguments)
                    except ValueError: cleanup_failed = True
                if cleanup_failed:
                    if not active_error: raise ValueError('Temporary keychain cleanup failed; runner must be discarded')
                    print('release: temporary keychain cleanup failed; runner must be discarded', file=sys.stderr)
    archive = ROOT / 'dist' / ('Keylet-' + release_version + '-arm64.zip')
    # Avoid AppleDouble files being materialized inside a sealed app by Homebrew.
    run(['ditto', '-c', '-k', '--norsrc', '--noextattr', '--noqtn', '--keepParent', str(app), str(archive)])
    # Prove archive transport retained the signature and stapled ticket, rather
    # than assuming removing extended attributes is safe for every signing mode.
    with tempfile.TemporaryDirectory(prefix='keylet-archive-check-') as temporary:
        extracted = Path(temporary) / 'Keylet.app'
        run(['ditto', '-x', '-k', str(archive), temporary])
        expected = hashlib.sha256((app / 'Contents/MacOS/keylet').read_bytes()).hexdigest()
        if archive_binary_digest(archive) != expected or hashlib.sha256((extracted / 'Contents/MacOS/keylet').read_bytes()).hexdigest() != expected:
            raise ValueError('Archive transport changed the signed executable')
        run(['codesign', '--verify', '--strict', '--verbose=2', str(extracted)])
        run(['xcrun', 'stapler', 'validate', str(extracted)])
        run(['spctl', '--assess', '--type', 'execute', str(extracted)])
    checksum = hashlib.sha256(archive.read_bytes()).hexdigest()
    (archive.with_suffix('.zip.sha256')).write_text(checksum + '  ' + archive.name + '\n')
    print('Prepared notarized release ' + tag)


def validate_repository(repository):
    if not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repository):
        raise ValueError('Invalid public repository name')
    return repository


def formula_text(tag, repository, checksum, binary_checksum):
    release_version = version(tag)
    if not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repository) or not all(re.fullmatch(r'[0-9a-f]{64}', value) for value in (checksum, binary_checksum)):
        raise ValueError('Invalid public release metadata')
    text = (ROOT / 'packaging/keylet.rb.in').read_text()
    return text.replace('@VERSION@', release_version).replace('@REPOSITORY@', repository).replace('@SHA256@', checksum).replace('@BINARY_SHA256@', binary_checksum)


def archive_binary_digest(path):
    # Includes the embedded signature: forbid relocation/ad-hoc repair afterward.
    with zipfile.ZipFile(path) as archive:
        binary_name = 'Keylet.app/Contents/MacOS/keylet'
        entries = [entry for entry in archive.infolist() if entry.filename == binary_name]
        if len(entries) != 1 or not 0 < entries[0].file_size <= 128 * 1024 * 1024:
            raise ValueError('Release archive must contain one bounded Keylet executable')
        mode = entries[0].external_attr >> 16
        if (mode & 0o170000) not in (0, 0o100000) or entries[0].is_dir():
            raise ValueError('Release executable must be a regular file')
        return hashlib.sha256(archive.read(entries[0])).hexdigest()


def api(method, endpoint, token, body=None):
    request = urllib.request.Request('https://api.github.com/' + endpoint, method=method,
        headers={'Authorization': 'Bearer ' + token, 'Accept': 'application/vnd.github+json',
                 'X-GitHub-Api-Version': '2022-11-28', 'Content-Type': 'application/json'},
        data=json.dumps(body).encode() if body is not None else None)
    with urllib.request.urlopen(request, timeout=30) as response: return json.load(response)


def publish(tag):
    release_version = version(tag)
    repository = validate_repository(require_env('GITHUB_REPOSITORY'))
    archive = ROOT / 'dist' / ('Keylet-' + release_version + '-arm64.zip')
    checksum_path = archive.with_suffix('.zip.sha256')
    # gh authenticates from GH_TOKEN, never from a command argument or remote URL.
    run(['gh', 'release', 'create', tag, str(archive), str(checksum_path), '--repo', repository,
         '--verify-tag', '--title', 'Keylet ' + release_version, '--generate-notes'])


def update_tap(tag):
    release_version = version(tag)
    repository = validate_repository(require_env('GITHUB_REPOSITORY'))
    token = require_env('TAP_TOKEN')
    # Resolve immutable release asset/checksum via public GitHub release, not arbitrary workflow text.
    release = api('GET', 'repos/' + repository + '/releases/tags/' + tag, require_env('GH_TOKEN'))
    name = 'Keylet-' + release_version + '-arm64.zip'
    assets = {asset['name']: asset for asset in release['assets']}
    if name not in assets or name + '.sha256' not in assets: raise ValueError('Published release assets missing')
    url = assets[name + '.sha256']['browser_download_url']
    expected_url = 'https://github.com/' + repository + '/releases/download/' + tag + '/' + name + '.sha256'
    if url != expected_url: raise ValueError('Unexpected checksum asset URL')
    with urllib.request.urlopen(url, timeout=30) as response: checksum_line = response.read(1024).decode().strip()
    match = re.fullmatch(r'([0-9a-f]{64})  ' + re.escape(name), checksum_line)
    if not match: raise ValueError('Malformed published checksum')
    local_archive = ROOT / 'dist' / name
    local_checksum = local_archive.with_suffix('.zip.sha256')
    local_digest = hashlib.sha256(local_archive.read_bytes()).hexdigest()
    if local_checksum.read_text().strip() != local_digest + '  ' + name or local_digest != match.group(1):
        raise ValueError('Published release differs from this run prepared archive')
    # Independently hash the public archive before the tap is changed.
    archive_url = assets[name]['browser_download_url']
    if archive_url != expected_url[:-7]: raise ValueError('Unexpected archive asset URL')
    digest = hashlib.sha256()
    with urllib.request.urlopen(archive_url, timeout=60) as response:
        while chunk := response.read(1024 * 1024): digest.update(chunk)
    if digest.hexdigest() != match.group(1): raise ValueError('Published archive checksum mismatch')
    binary_digest = archive_binary_digest(local_archive)
    content = formula_text(tag, repository, match.group(1), binary_digest)
    endpoint = 'repos/' + TAP + '/contents/Formula/keylet.rb'
    try: current = api('GET', endpoint, token)
    except urllib.error.HTTPError as error:
        if error.code != 404: raise
        current = {}
    body = {'message': 'Update Keylet to ' + release_version, 'content': base64.b64encode(content.encode()).decode()}
    if current.get('sha'): body['sha'] = current['sha']
    api('PUT', endpoint, token, body)
    print('Updated public Keylet formula to ' + release_version)


if __name__ == '__main__':
    try:
        if len(sys.argv) != 3 or sys.argv[1] not in ['prepare', 'publish', 'tap']:
            raise ValueError('Usage: release.py prepare|publish|tap vMAJOR.MINOR.PATCH')
        {'prepare': prepare, 'publish': publish, 'tap': update_tap}[sys.argv[1]](sys.argv[2])
    except Exception as error:
        print('release: ' + (str(error) if isinstance(error, ValueError) else 'Release operation failed; sensitive tool output withheld'), file=sys.stderr)
        sys.exit(1)
