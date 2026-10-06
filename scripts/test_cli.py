"""CLI parser regressions using the unsigned debug product built by `swift test`."""
import json
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

    def test_json_flag_stops_at_end_of_options(self):
        root = Path(__file__).resolve().parents[1]
        binary = root / ".build" / "debug" / "keylet"
        literal_flag = subprocess.run(
            [str(binary), "doctor", "--", "--json"], cwd="/tmp",
            text=True, capture_output=True, check=False,
        )
        self.assertEqual(literal_flag.returncode, 1)
        self.assertEqual(literal_flag.stdout, "")
        self.assertIn("Unexpected argument '--json'", literal_flag.stderr)

        json_mode = subprocess.run(
            [str(binary), "--json", "doctor", "--", "--json"], cwd="/tmp",
            text=True, capture_output=True, check=False,
        )
        self.assertEqual(json_mode.returncode, 1)
        self.assertEqual(json.loads(json_mode.stdout), {
            "ok": False,
            "error": {
                "code": "invalid_arguments",
                "message": "Missing or invalid arguments; use the subcommand's --help",
            },
        })
        self.assertEqual(json_mode.stderr, "")


if __name__ == "__main__":
    unittest.main()
