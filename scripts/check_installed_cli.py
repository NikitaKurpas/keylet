#!/usr/bin/env python3
"""Credential-free functional check for the directly launched, installed CLI."""
import json
from pathlib import Path
import subprocess
import sys


def check(binary):
    executable = str(Path(binary).resolve(strict=True))
    for payload, message_type, supported in [('0b', 11, True), ('0d', 13, True), ('ff', 255, False)]:
        child = subprocess.run([executable, '--json', 'protocol', 'decode', '--hex', payload],
                               capture_output=True, text=True, timeout=20, check=False)
        expected = {'ok': True, 'message_type': message_type, 'supported': supported, 'bytes': 1}
        if child.returncode != 0 or json.loads(child.stdout) != expected:
            raise RuntimeError('Installed CLI failed public protocol decoding')
    child = subprocess.run([executable, '--json', 'protocol', 'decode', '--hex', 'zz'],
                           capture_output=True, text=True, timeout=20, check=False)
    result = json.loads(child.stdout)
    if child.returncode != 1 or result.get('ok') is not False or result.get('error', {}).get('code') != 'invalid_arguments':
        raise RuntimeError('Installed CLI failed malformed protocol input rejection')
    print('Installed CLI functional check passed: supported/unsupported public payloads and malformed input')


if __name__ == '__main__':
    check(sys.argv[1])
