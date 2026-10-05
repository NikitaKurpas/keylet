"""Exercise Ruby formula staging/wrapper with public byte fixtures only; no app launch."""
import hashlib
import os
from pathlib import Path
import subprocess
import tempfile
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
class Formula
  def self.test; end
  def self.method_missing(*)
  end
  def buildpath; Pathname.new(ENV.fetch("STAGE")); end
  def libexec; Pathname.new(ENV.fetch("DEST"))/"libexec"; end
  def opt_libexec; libexec; end
  def bin; Pathname.new(ENV.fetch("DEST"))/"bin"; end
  def chmod(mode, path); File.chmod(mode, path); end
  def odie(message); raise message; end
  def system(*args)
    raise "Unexpected native operation" unless args == ["/usr/bin/codesign", "--verify", "--strict", libexec/"Keylet.app"]
    File.write(ENV.fetch("DEST")+"/verification-requested", "strict")
  end
end
load ARGV.fetch(0)
Keylet.new.install
Keylet.new.post_install
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
                formula = root/'keylet.rb'
                formula.write_text(release.formula_text('v1.2.3', 'owner/repo', 'a'*64, hashlib.sha256(fixture).hexdigest()))
                harness = root/'harness.rb'
                harness.write_text(HARNESS)
                destination = root/'destination with spaces'
                environment = dict(os.environ, STAGE=str(stage), DEST=str(destination))
                subprocess.run(['/usr/bin/ruby', str(harness), str(formula)], cwd=stage, env=environment, check=True, capture_output=True)
                self.assertEqual((destination/'libexec/Keylet.app/Contents/MacOS/keylet').read_bytes(), fixture)
                self.assertTrue((destination/'verification-requested').is_file())
                wrapper = destination/'bin/keylet-agent-service'
                subprocess.run(['/bin/bash', '-n', str(wrapper)], check=True, capture_output=True)
                for value in ['', 'bad', 'A'*36, '00000000-0000-0000-0000-000000000000;echo injected']:
                    result = subprocess.run(['/bin/bash', str(wrapper)], env=dict(environment, KEYLET_KEY_ID=value), capture_output=True)
                    self.assertEqual(result.returncode, 1)
                    self.assertIn(b'Set KEYLET_KEY_ID', result.stderr)
                # Valid UUID with changed public binary must stop before codesign/app execution.
                (destination/'libexec/Keylet.app/Contents/MacOS/keylet').write_bytes(b'changed public fixture')
                result = subprocess.run(['/bin/bash', str(wrapper)], env=dict(environment, KEYLET_KEY_ID='00000000-0000-0000-0000-000000000000'), capture_output=True)
                self.assertEqual(result.returncode, 1)
                self.assertIn(b'binary differs', result.stderr)

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
