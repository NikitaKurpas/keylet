"""Exercise Ruby formula staging/wrapper with public byte fixtures only; no app launch."""
import hashlib
import os
from pathlib import Path
import subprocess
import socket
import struct
import tempfile
import threading
import unittest
import release

HARNESS = r'''
require "pathname"
require "fileutils"
require "shellwords"
class Pathname
  def install(source)
    mkpath
    FileUtils.cp_r(source, self.to_s)
  end
  def install_symlink(source)
    mkpath
    File.symlink(source, self/source.basename)
  end
end
class PostInstallSteps
  attr_reader :steps
  def initialize; @steps = []; end
  def run(command, args: [], base: nil)
    @steps << [command, args, base]
  end
end
module Kernel
  def system(*args)
    expected = ["/usr/bin/codesign", "--verify", "--strict", File.join(ENV.fetch("DEST"), "libexec/Keylet.app")]
    matches = args.length == 4 && args.take(3) == expected.take(3)
    matches &&= File.realpath(args.last) == File.realpath(expected.last)
    raise "Unexpected native operation" unless matches
    File.write(ENV.fetch("DEST")+"/verification-requested", "strict")
    ENV["VERIFY_FAIL"] != "1"
  end
  def exec(*args)
    expected = File.join(ENV.fetch("DEST"), "libexec/Keylet.app/Contents/MacOS/keylet")
    raise "Unexpected executable or arguments" unless File.realpath(args.first) == File.realpath(expected) && args.drop(1) == ["agent"]
    File.write(ENV.fetch("DEST")+"/launch-requested", "agent")
    exit 0
  end
end
class Formula
  def self.test(&block); define_method(:test, &block); end
  def self.post_install_steps(&block)
    dsl = PostInstallSteps.new
    dsl.instance_eval(&block)
    @steps = dsl.steps
  end
  def self.steps; @steps; end
  def self.method_missing(*)
  end
  def buildpath; Pathname.new(ENV.fetch("STAGE")); end
  def libexec; Pathname.new(ENV.fetch("DEST"))/"libexec"; end
  def opt_libexec; libexec; end
  def bin; Pathname.new(ENV.fetch("DEST"))/"bin"; end
  def system(path)
    raise "Unexpected formula test executable" unless path == libexec/"keylet-verify-install"
    load path.to_s
  end
  def chmod(mode, path); File.chmod(mode, path); end
  def odie(message); raise message; end
end
load ARGV.fetch(0)
ARGV.clear
raise "Verification ran at formula load" if File.exist?(ENV.fetch("DEST")+"/verification-requested")
formula = Keylet.new
formula.install
if ENV["TAMPER"] == "1"
  File.binwrite(formula.libexec/"Keylet.app/Contents/MacOS/keylet", "changed public fixture")
end
raise "Unexpected post-install steps" unless Keylet.steps == [["keylet-verify-install", [], :libexec]]
# The native runner resolves :libexec after linkage. Load this fixture helper
# there with Kernel#system mocked, never invoking codesign or an app.
Keylet.steps.each { |command, _, _| load (formula.libexec/command).to_s }
if ENV["TEST_TAMPER"] == "1"
  File.binwrite(formula.libexec/"Keylet.app/Contents/MacOS/keylet", "changed public fixture")
end
ENV["VERIFY_FAIL"] = "1" if ENV["TEST_VERIFY_FAIL"] == "1"
formula.test
if ENV["RUN_SERVICE"] == "1"
  if ENV["SERVICE_TAMPER"] == "1"
    File.binwrite(formula.libexec/"Keylet.app/Contents/MacOS/keylet", "changed public fixture")
  end
  ENV["VERIFY_FAIL"] = "1" if ENV["SERVICE_VERIFY_FAIL"] == "1"
  ARGV.replace(["agent"])
  load (formula.libexec/"keylet-verify-install").to_s
  raise "Service did not exec the agent"
end
'''

class FormulaTests(unittest.TestCase):
    def test_both_staging_layouts_and_fail_closed_wrapper(self):
        fixture = b'public non-executable fixture'
        for flattened in [False, True]:
            with self.subTest(flattened=flattened), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                stage = root/'stage'
                contents = stage/('Contents' if flattened else 'Keylet.app/Contents')
                (contents/'MacOS').mkdir(parents=True)
                (contents/'MacOS/keylet').write_bytes(fixture)
                (contents/'Resources').mkdir()
                helper = contents/'Resources/keylet-ssh-sign'
                helper.write_bytes((release.ROOT/'packaging/keylet-ssh-sign').read_bytes())
                helper.chmod(0o755)
                formula = root/'keylet.rb'
                formula.write_text(release.formula_text('v1.2.3', 'owner/repo', 'a'*64, hashlib.sha256(fixture).hexdigest()))
                harness = root/'harness.rb'
                harness.write_text(HARNESS)
                destination = root/'destination with spaces'
                environment = dict(os.environ, STAGE=str(stage), DEST=str(destination))
                subprocess.run(['/usr/bin/ruby', str(harness), str(formula)], cwd=stage,
                    env=dict(environment, RUN_SERVICE='1'), check=True, capture_output=True)
                self.assertEqual((destination/'libexec/Keylet.app/Contents/MacOS/keylet').read_bytes(), fixture)
                self.assertTrue((destination/'verification-requested').is_file())
                wrapper = destination/'libexec/keylet-verify-install'
                subprocess.run(['/usr/bin/ruby', '-c', str(wrapper)], check=True, capture_output=True)
                self.assertEqual((destination/'launch-requested').read_text(), 'agent')
                signer = destination/'bin/keylet-ssh-sign'
                self.assertTrue(signer.is_symlink())
                self.assertEqual(signer.resolve(), (destination/'libexec/Keylet.app/Contents/Resources/keylet-ssh-sign').resolve())
                # The native signer must use Keylet's socket even with another agent in the environment.
                with tempfile.TemporaryDirectory(dir='/tmp', prefix='kls-') as signing_home:
                    socket_path = Path(signing_home)/'Library/Containers/me.kurpas.keylet/Data/agent/socket.ssh'
                    socket_path.parent.mkdir(parents=True)
                    public_key = Path(signing_home)/'public key.pub'
                    public_key.write_text('ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBOVEjgAA5PHqRgwykjN5qM21uWCHFSY/Sqo5gkHAkn+e1MMQKHOLga7ucB9b3mif33MBid59GRK9GEPVlMiSQwo= fixture\n')
                    requests = []
                    with socket.socket(socket.AF_UNIX) as listener:
                        listener.bind(str(socket_path))
                        listener.listen(1)
                        listener.settimeout(5)
                        def reject_identity():
                            connection, _ = listener.accept()
                            with connection, connection.makefile('rb') as stream:
                                length = struct.unpack('>I', stream.read(4))[0]
                                requests.append(stream.read(length))
                                connection.sendall(bytes.fromhex('000000050c00000000'))
                        server = threading.Thread(target=reject_identity, daemon=True)
                        server.start()
                        result = subprocess.run([str(signer), '-Y', 'sign', '-n', 'git', '-f', str(public_key)],
                            input=b'public fixture', env=dict(environment, HOME=signing_home, SSH_AUTH_SOCK='/unused-agent'),
                            capture_output=True, timeout=5)
                        server.join(timeout=5)
                        self.assertFalse(server.is_alive())
                    self.assertEqual(requests, [b'\x0b'])
                    self.assertNotEqual(result.returncode, 0)
                # A changed binary must stop before codesign/app execution.
                (destination/'libexec/Keylet.app/Contents/MacOS/keylet').write_bytes(b'changed public fixture')
                result = subprocess.run(['/usr/bin/ruby', str(wrapper), 'agent'], env=environment, capture_output=True)
                self.assertEqual(result.returncode, 1)
                self.assertIn(b'Homebrew changed the signed Keylet binary', result.stderr)

    def test_post_install_rejects_changed_digest_and_failed_signature(self):
        fixture = b'public non-executable fixture'
        for fault in ['TAMPER', 'VERIFY_FAIL', 'TEST_TAMPER', 'TEST_VERIFY_FAIL', 'SERVICE_TAMPER', 'SERVICE_VERIFY_FAIL']:
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                stage = root/'stage'
                binary = stage/'Contents/MacOS/keylet'
                binary.parent.mkdir(parents=True)
                binary.write_bytes(fixture)
                formula = root/'keylet.rb'
                formula.write_text(release.formula_text('v1.2.3', 'owner/repo', 'a'*64, hashlib.sha256(fixture).hexdigest()))
                harness = root/'harness.rb'
                harness.write_text(HARNESS)
                destination = root/'destination with spaces'
                result = subprocess.run(['/usr/bin/ruby', str(harness), str(formula)], cwd=stage,
                    env=dict(os.environ, STAGE=str(stage), DEST=str(destination), RUN_SERVICE='1', **{fault:'1'}), capture_output=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse((destination/'launch-requested').exists())
                if fault in ['TAMPER', 'TEST_TAMPER', 'SERVICE_TAMPER']:
                    self.assertIn(b'Homebrew changed the signed Keylet binary', result.stderr)
                    self.assertEqual((destination/'verification-requested').exists(), fault != 'TAMPER')
                else:
                    self.assertIn(b'Keylet signature verification failed', result.stderr)
                    self.assertTrue((destination/'verification-requested').exists())

    def test_missing_staging_bundle_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            formula = root/'keylet.rb'
            formula.write_text(release.formula_text('v1.2.3', 'owner/repo', 'a'*64, 'b'*64))
            harness = root/'harness.rb'
            harness.write_text(HARNESS)
            result = subprocess.run(['/usr/bin/ruby', str(harness), str(formula)], cwd=root,
                env=dict(os.environ, STAGE=str(root), DEST=str(root/'dest')), capture_output=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(b'no Keylet.app/Contents', result.stderr)

if __name__ == '__main__': unittest.main()
