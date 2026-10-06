#!/usr/bin/env python3
"""Build a separate unsigned review bundle; never touch the retained signed product."""
from pathlib import Path
import os
import shutil
import stat
import subprocess


def directory(path):
    if path.exists() or path.is_symlink():
        mode = path.lstat().st_mode
        if not stat.S_ISDIR(mode):
            raise ValueError('Bundle destination must use regular directories')
    else:
        path.mkdir(mode=0o755)


def regular(path):
    mode = path.lstat()
    if not stat.S_ISREG(mode.st_mode) or mode.st_nlink != 1:
        raise ValueError('Bundle inputs/destinations must be regular unlinked files')


def bundle(root, binary):
    destination = root / 'dist/unsigned/Keylet.app'
    for path in [root / 'dist', root / 'dist/unsigned', destination,
                 destination / 'Contents', destination / 'Contents/MacOS',
                 destination / 'Contents/Resources', destination / 'Contents/Resources/Licenses']:
        directory(path)
    # Check all existing output nodes before writes; no profile/signature is carried over.
    for parent, folders, names in os.walk(destination, followlinks=False):
        for name in folders:
            directory(Path(parent) / name)
        for name in names:
            regular(Path(parent) / name)
    if (destination / 'Contents/embedded.provisionprofile').exists() or (destination / 'Contents/_CodeSignature').exists():
        raise ValueError('Unsigned review destination must not contain signed artifacts')
    copies = [(root / 'packaging/Info.plist', destination / 'Contents/Info.plist'),
              (root / 'packaging/keylet-ssh-sign', destination / 'Contents/Resources/keylet-ssh-sign'),
              (binary, destination / 'Contents/MacOS/keylet'),
              *[(root / name, destination / 'Contents/Resources' / name) for name in ['LICENSE', 'NOTICE.md']],
              (root / 'licenses/swift-argument-parser-LICENSE.txt', destination / 'Contents/Resources/Licenses/swift-argument-parser-LICENSE.txt')]
    for source, target in copies:
        regular(source)
        if target.exists(): regular(target)
    for source, target in copies:
        shutil.copyfile(source, target)
        target.chmod(0o755 if target.name in ('keylet', 'keylet-ssh-sign') else 0o644)
    return destination


if __name__ == '__main__':
    root = Path(__file__).resolve().parent.parent
    build = subprocess.run(['swift', 'build', '-c', 'release', '--show-bin-path'], cwd=root,
                           capture_output=True, text=True, check=True).stdout.strip()
    print(bundle(root, Path(build) / 'keylet'))
