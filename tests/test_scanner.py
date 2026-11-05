"""Contract tests for both distributed CLI entry points, including failure controls."""

import json
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import unittest

from fixture_server import FixtureServer


ROOT = Path(__file__).resolve().parents[1]
SCANNERS = [ROOT / "run.py", ROOT / ".github/actions/minisecscan/run.py"]


class ScannerContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture = FixtureServer()
        cls.fixture.__enter__()

    @classmethod
    def tearDownClass(cls):
        cls.fixture.__exit__()

    def scan(self, scanner, *, url=None, html=None, trusted=True, policy=None):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "report.json"
            args = [sys.executable, str(scanner), "--out", str(output)]
            if html is not None:
                source = Path(directory) / "fixture page.html"
                source.write_text(html)
                args += ["--file", str(source)]
            else:
                args += ["--url", url]
            args += policy or ["--min-score", "75", "--fail-on", "HIGH"]
            result = subprocess.run(args, capture_output=True, text=True, timeout=25,
                                    env=self.fixture.environment(trusted))
            self.assertTrue(output.exists(), result.stderr)
            return result.returncode, json.loads(output.read_text())

    def test_secure_https_passes_real_default_policy(self):
        for scanner in SCANNERS:
            with self.subTest(scanner=scanner):
                code, report = self.scan(scanner, url=self.fixture.url + "/secure")
                self.assertEqual(code, 0)
                self.assertEqual(report["mode"], "url")
                self.assertEqual(report["score"], 100)
                self.assertEqual(report["findings"], [])

    def test_insecure_https_is_rejected_with_header_findings(self):
        for scanner in SCANNERS:
            with self.subTest(scanner=scanner):
                code, report = self.scan(scanner, url=self.fixture.url + "/insecure")
                self.assertEqual(code, 1)
                self.assertLess(report["score"], 75)
                titles = {f["title"] for f in report["findings"]}
                self.assertIn("Content-Security-Policy missing", titles)
                self.assertIn("HSTS missing", titles)

    def test_high_severity_fails_even_above_score_threshold(self):
        for scanner in SCANNERS:
            for page, finding in [
                ("mixed-content", "Mixed content (src)"),
                ("password-get", "Password form uses GET"),
                ("password-http", "Password form posts to HTTP"),
                ("cookie", "Cookie SameSite=None without Secure"),
            ]:
                with self.subTest(scanner=scanner, page=page):
                    code, report = self.scan(scanner, url=self.fixture.url + "/" + page)
                    self.assertEqual(code, 1)
                    self.assertGreaterEqual(report["score"], 75)
                    self.assertIn(finding, {f["title"] for f in report["findings"]})

    def test_configured_medium_severity_policy_is_enforced(self):
        for scanner in SCANNERS:
            with self.subTest(scanner=scanner):
                code, report = self.scan(scanner, url=self.fixture.url + "/csrf",
                                         policy=["--min-score", "75", "--fail-on", "MEDIUM"])
                self.assertEqual(code, 1)
                self.assertGreater(report["score"], 75)
                self.assertIn("Possible missing CSRF token", {f["title"] for f in report["findings"]})

    def test_score_policy_is_enforced_without_high_findings(self):
        for scanner in SCANNERS:
            with self.subTest(scanner=scanner):
                code, report = self.scan(scanner, url=self.fixture.url + "/csrf",
                                         policy=["--min-score", "99", "--fail-on", "HIGH"])
                self.assertEqual(code, 1)
                self.assertFalse(any(f["severity"] == "HIGH" for f in report["findings"]))

    def test_tls_verification_is_required(self):
        for scanner in SCANNERS:
            with self.subTest(scanner=scanner):
                code, report = self.scan(scanner, url=self.fixture.url + "/secure", trusted=False)
                self.assertEqual(code, 1)
                self.assertEqual(report["findings"][0]["title"], "Fetch failed")

    def test_connection_failure_is_rejected(self):
        with socket.socket() as closed:
            closed.bind(("127.0.0.1", 0))  # Reserve a port without starting a listener.
            url = f"https://127.0.0.1:{closed.getsockname()[1]}"
            for scanner in SCANNERS:
                with self.subTest(scanner=scanner):
                    code, report = self.scan(scanner, url=url)
                    self.assertEqual(code, 1)
                    self.assertEqual(report["findings"][0]["severity"], "HIGH")

    def test_local_html_modes_preserve_failure_detection(self):
        for scanner in SCANNERS:
            for html, expected in [("<h1>Safe</h1>", 0),
                                   ('<form method="get"><input type="password"></form>', 1)]:
                with self.subTest(scanner=scanner, expected=expected):
                    code, report = self.scan(scanner, html=html)
                    self.assertEqual(code, expected)
                    self.assertEqual(report["mode"], "file")

    def test_target_is_required(self):
        for scanner in SCANNERS:
            with self.subTest(scanner=scanner), tempfile.TemporaryDirectory() as directory:
                result = subprocess.run([sys.executable, str(scanner), "--out", str(Path(directory) / "out.json")],
                                        capture_output=True, text=True, timeout=25)
                self.assertEqual(result.returncode, 3)


if __name__ == "__main__":
    unittest.main()
