import unittest
import subprocess
import tempfile
import sys
import shutil
from pathlib import Path

class SSHBruteForceDetectorTests(unittest.TestCase):

    def run_detector(self, log_contents):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)

            detector_source = Path(__file__).with_name("detector.py")

            shutil.copy2(
                detector_source,
                temp_path / "detector.py"
            )

            (temp_path / "auth.log").write_text(
                log_contents,
                encoding="utf-8"
            )
            
            result = subprocess.run(
                [sys.executable, str(temp_path / "detector.py")],
                cwd=temp_path,
                capture_output=True,
                text=True
            )

            return result

    def test_detects_brute_force(self):
        log = """\
Nov 07 10:00:01 server sshd: Failed password for root from 192.0.2.10 port 50001 ssh2
Nov 07 10:00:03 server sshd: Failed password for root from 192.0.2.10 port 50002 ssh2
Nov 07 10:00:05 server sshd: Failed password for admin from 192.0.2.10 port 50003 ssh2
Nov 07 10:00:07 server sshd: Failed password for test from 192.0.2.10 port 50004 ssh2
Nov 07 10:00:09 server sshd: Failed password for root from 192.0.2.10 port 50005 ssh2
"""

        result = self.run_detector(log)

        self.assertEqual(result.returncode, 0)
        self.assertIn("192.0.2.10", result.stdout)
        self.assertIn(
            "Maximum attempts within 5 minutes: 5",
            result.stdout
        )

    def test_does_not_flag_spread_out_attempts(self):
        log = """\
Nov 07 10:00:01 server sshd: Failed password for root from 192.0.2.10 port 50001 ssh2
Nov 07 10:02:01 server sshd: Failed password for root from 192.0.2.10 port 50002 ssh2
Nov 07 10:04:01 server sshd: Failed password for admin from 192.0.2.10 port 50003 ssh2
Nov 07 10:06:01 server sshd: Failed password for test from 192.0.2.10 port 50004 ssh2
Nov 07 10:08:01 server sshd: Failed password for root from 192.0.2.10 port 50005 ssh2
"""

        result = self.run_detector(log)

        self.assertEqual(result.returncode, 0)
        self.assertIn(
            "No IP addresses reached the threshold.",
            result.stdout
        )

    def test_ignores_successful_login(self):
        log = """\
Nov 07 10:02:01 server sshd: Accepted password for student from 192.0.2.30 port 50008 ssh2
"""

        result = self.run_detector(log)

        self.assertEqual(result.returncode, 0)
        self.assertIn(
            "Total failed login attempts: 0",
            result.stdout
        )

    def test_ignores_invalid_ip_address(self):
        log = """\
Nov 07 10:00:01 server sshd: Failed password for root from 999.999.999.999 port 50001 ssh2
"""

        result = self.run_detector(log)

        self.assertEqual(result.returncode, 0)
        self.assertIn(
            "Total failed login attempts: 0",
            result.stdout
        )

if __name__ == "__main__":
    unittest.main()