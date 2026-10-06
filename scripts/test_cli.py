"""CLI parser regressions using the unsigned debug product built by `swift test`."""
import subprocess
import sys
import unittest
from pathlib import Path


class CLITests(unittest.TestCase):
    def test_credential_free_cli_contract(self):
        root = Path(__file__).resolve().parents[1]
        binary = root / ".build" / "debug" / "keylet"
        self.assertTrue(binary.is_file(), "Run swift test before Python tests to build the unsigned CLI")
        result = subprocess.run(
            [sys.executable, str(root / "scripts" / "cli-smoke.py"), str(binary)],
            cwd="/tmp", text=True, capture_output=True, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_direct_functional_checker(self):
        root = Path(__file__).resolve().parents[1]
        binary = root / ".build" / "debug" / "keylet"
        # This product is unsigned and uses only the public protocol parser.
        result = subprocess.run([sys.executable, str(root / "scripts/check_installed_cli.py"), str(binary)],
                                cwd="/tmp", text=True, capture_output=True, check=False)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('functional check passed', result.stdout)


if __name__ == "__main__":
    unittest.main()
