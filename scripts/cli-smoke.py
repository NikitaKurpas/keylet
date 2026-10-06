#!/usr/bin/env python3
"""Safe CLI regression checks; supply an unsigned fixture executable. No credential commands."""
import json
import subprocess
import sys
from pathlib import Path

binary = str(Path(sys.argv[1]).resolve())
def run(args):
    p = subprocess.run([binary, '--json', *args], text=True, capture_output=True, check=False)
    return p.returncode, json.loads(p.stdout)

code, doctor = run(['doctor'])
assert code == 0 and doctor['ok'] and doctor['checks']['credential_access'] == 'not_checked'
assert doctor['checks']['provisioning'] == 'not_checked'
assert doctor['checks']['security_policy_enforcement'] == 'not_checked'
assert all(field not in doctor for field in ['offline', 'minimum_macos', 'audit_path'])
for args in [['keys', 'public'], ['keys', 'public', '--id', 'bad'], ['keys', 'resolve'],
             ['keys', 'resolve', '--label', ''], ['agent', '--key', 'bad'], ['protocol', 'decode', '--hex', '']]:
    code, result = run(args)
    assert code == 1 and result['error']['code'] == 'invalid_arguments', (args, result)
    assert result['error']['message'] and 'help' in result['error']['message']
for command in [[], ['doctor'], ['version'], ['keys'], ['keys', 'list'], ['keys', 'resolve'], ['keys', 'public'],
                ['keys', 'create'], ['keys', 'delete'], ['agent'], ['protocol'], ['protocol', 'decode'], ['audit'], ['audit', 'list'], ['audit', 'top']]:
    code, result = run([*command, '--help'])
    assert code == 0 and result['ok'] and 'usage:' in result['help'].lower(), command
code, result = run(['keys', 'create', '--label', 'public preview', '--policy', 'after-first-unlock', '--dry-run'])
assert code == 0 and result['dry_run'] and not result['key_created']
code, result = run(['protocol', 'decode', '--hex', '0b'])
assert code == 0 and result['message_type'] == 11
# No audit command that opens the user's database is run here. Invalid bounds must
# be rejected by parser validation before any persistence or signing setup.
for args in [['audit', 'list', '--limit', '0'], ['audit', 'list', '--limit', '201'],
             ['audit', 'list', '--before', '0'], ['audit', 'top', '--limit', '-1'],
             ['doctor', '--unknown'], ['keys', 'create', '--label', 'preview', '--policy', 'bad', '--dry-run']]:
    code, result = run(args)
    assert code == 1 and result['error']['code'] == 'invalid_arguments', (args, result)
for args in [['doctor', '--json'], ['keys', 'create', '--label', 'preview', '--policy', 'when-unlocked', '--dry-run', '--json']]:
    p = subprocess.run([binary, *args], text=True, capture_output=True, check=False)
    assert p.returncode == 0 and json.loads(p.stdout)['ok']
p = subprocess.run([binary, '--json', '--version'], text=True, capture_output=True, check=False)
assert p.returncode == 0 and json.loads(p.stdout)['version'] == doctor['version']
p = subprocess.run([binary, '--json', 'doctor', '--version'], text=True, capture_output=True, check=False)
assert p.returncode == 0 and json.loads(p.stdout)['version'] == doctor['version']
p = subprocess.run([binary], text=True, capture_output=True, check=False)
assert p.returncode == 0 and 'USAGE:' in p.stdout and 'audit' in p.stdout
print('CLI smoke passed: validation errors, help, hardware/signature doctor, dry-run, wire inspection, JSON, version')

# Deletion validation must fail before signing setup or any Keychain access.
target = '00000000-0000-0000-0000-000000000001'
for args in [
    ['keys', 'delete'],
    ['keys', 'delete', '--id', 'bad', '--dry-run'],
    ['keys', 'delete', '--id', target],
    ['keys', 'delete', '--id', target, '--confirm-id', 'bad'],
    ['keys', 'delete', '--id', target, '--confirm-id', '00000000-0000-0000-0000-000000000002'],
    ['keys', 'delete', '--id', target, '--dry-run', '--confirm-id', 'bad'],
    ['keys', 'delete', '--label', 'fixture', '--dry-run'],
    ['keys', 'delete', '--id', target, '--yes'],
]:
    code, result = run(args)
    assert code == 1 and result['error']['code'] == 'invalid_arguments', (args, result)
print('Deletion CLI checks passed: help and eight credential-free validation failures')
