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


if __name__ == "__main__":
    unittest.main()
