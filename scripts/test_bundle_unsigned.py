import pathlib
import tempfile
import unittest
import bundle_unsigned


class UnsignedBundleTests(unittest.TestCase):
    def fixture(self, root):
        (root / 'packaging').mkdir()
        (root / 'licenses').mkdir()
        (root / 'licenses/swift-argument-parser-LICENSE.txt').write_bytes(b'public license fixture')
        (root / 'packaging/Info.plist').write_bytes(b'public plist fixture')
        for name in ['LICENSE', 'NOTICE.md', 'binary']:
            (root / name).write_bytes(b'public fixture')
        return root / 'binary'

    def test_preserves_retained_signed_bundle(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary); binary = self.fixture(root)
            retained = root / 'dist/Keylet.app'; retained.mkdir(parents=True)
            (retained / 'retained').write_bytes(b'unchanged signed fixture')
            out = bundle_unsigned.bundle(root, binary)
            self.assertEqual((out / 'Contents/MacOS/keylet').read_bytes(), binary.read_bytes())
            self.assertEqual((retained / 'retained').read_bytes(), b'unchanged signed fixture')

    def test_rejects_destination_symlink(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary); binary = self.fixture(root)
            (root / 'dist').symlink_to(root / 'packaging', target_is_directory=True)
            with self.assertRaises(ValueError): bundle_unsigned.bundle(root, binary)

    def test_rejects_existing_output_link(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary); binary = self.fixture(root)
            out = bundle_unsigned.bundle(root, binary)
            target = out / 'Contents/MacOS/keylet'; target.unlink(); target.symlink_to(binary)
            with self.assertRaises(ValueError): bundle_unsigned.bundle(root, binary)

    def test_rejects_signed_destination(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary); binary = self.fixture(root)
            out = bundle_unsigned.bundle(root, binary)
            (out / 'Contents/embedded.provisionprofile').write_bytes(b'public fixture')
            with self.assertRaises(ValueError): bundle_unsigned.bundle(root, binary)
