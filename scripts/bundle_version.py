"""Stamp bundle metadata from the existing source version or a validated release tag."""
from pathlib import Path
import plistlib
import re
import sys


def version(tag):
    if not re.fullmatch(r'v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)', tag):
        raise ValueError('Release tag must be vMAJOR.MINOR.PATCH')
    return tag[1:]


def source_version(root):
    return version('v' + (root / 'version.txt').read_text().strip())


def set_bundle_version(app, release_version):
    if release_version is None:
        return
    release_version = version('v' + release_version)
    info_path = app / 'Contents/Info.plist'
    info = plistlib.loads(info_path.read_bytes())
    info['CFBundleShortVersionString'] = release_version
    info['CFBundleVersion'] = release_version
    info_path.write_bytes(plistlib.dumps(info))


if __name__ == '__main__':
    set_bundle_version(Path(sys.argv[1]), source_version(Path(__file__).resolve().parent.parent))
