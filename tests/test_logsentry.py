"""Unit tests for LogSentry. Run with:  python3 -m unittest discover -s tests -v"""
import contextlib
import gzip
import io
import json
import os
import sys
import tempfile
import unittest
from datetime import datetime

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import logsentry as ls  # noqa: E402

ROOT = os.path.join(os.path.dirname(__file__), "..")
AUTH = os.path.join(ROOT, "samples", "auth.log")
ACCESS = os.path.join(ROOT, "samples", "access.log")


def slurp(path):
    """Read a whole text file and close it."""
    with open(path, encoding="utf-8") as handle:
        return handle.read()


def run_cli(*argv):
    """Run the CLI in-process; return (exit_code, stdout, stderr)."""
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = ls.main(list(argv))
    return code, out.getvalue(), err.getvalue()


def fail_lines(ip, count, start_minute=0, step_seconds=5, user="root"):
    """Build `count` sshd 'Failed password' lines from `ip`."""
    lines = []
    for i in range(count):
        total = start_minute * 60 + i * step_seconds
        h, m, s = total // 3600, (total % 3600) // 60, total % 60
        lines.append(f"Oct 17 {10 + h:02d}:{m:02d}:{s:02d} h sshd[1]: "
                     f"Failed password for {user} from {ip} port 22 ssh2")
    return lines


class ParsingTests(unittest.TestCase):
    def test_failed_password(self):
        kind, user, ip, when = ls.parse_ssh_line(
            "Oct  4 10:00:01 h sshd[1]: Failed password for root from 192.0.2.1 port 22 ssh2", 2026)
        self.assertEqual((kind, user, ip), ("failed", "root", "192.0.2.1"))
        self.assertEqual(when, datetime(2026, 10, 4, 10, 0, 1))

    def test_failed_invalid_user_variant(self):
        kind, user, ip, _ = ls.parse_ssh_line(
            "Oct  4 10:00:01 h sshd[1]: Failed password for invalid user admin from 192.0.2.1 port 22 ssh2", 2026)
        self.assertEqual((kind, user), ("failed", "admin"))

    def test_invalid_user_line_is_not_a_failure(self):
        """'Invalid user' is logged alongside 'Failed password'; counting both would double count."""
        kind, *_ = ls.parse_ssh_line("Oct  4 10:00:01 h sshd[1]: Invalid user bob from 192.0.2.1 port 22", 2026)
        self.assertEqual(kind, "invalid")

    def test_success_and_ipv6(self):
        kind, user, ip, _ = ls.parse_ssh_line(
            "2026-10-04T10:00:01+05:30 h sshd[1]: Accepted publickey for bob from 2001:db8::1 port 22 ssh2", 2026)
        self.assertEqual((kind, user, ip), ("success", "bob", "2001:db8::1"))

    def test_garbage_ip_rejected(self):
        self.assertIsNone(ls.parse_ssh_line("x sshd: Failed password for root from 999.1.1.1 port 22", 2026))

    def test_unrelated_line_ignored(self):
        self.assertIsNone(ls.parse_ssh_line("Oct  4 10:00:01 h cron[1]: job done", 2026))

    def test_web_lines(self):
        ok = '203.0.113.9 - - [17/Oct/2026:10:00:00 +0000] "POST /login HTTP/1.1" 401 10 "-" "ua"'
        nf = '203.0.113.9 - - [17/Oct/2026:10:00:01 +0000] "GET /.env HTTP/1.1" 404 10 "-" "ua"'
        fine = '203.0.113.9 - - [17/Oct/2026:10:00:02 +0000] "GET / HTTP/1.1" 200 10 "-" "ua"'
        self.assertEqual(ls.parse_web_line(ok)[:3], ("failed", "/login", "203.0.113.9"))
        self.assertEqual(ls.parse_web_line(nf)[0], "probe")
        self.assertIsNone(ls.parse_web_line(fine))

    def test_detect_format(self):
        self.assertEqual(ls.detect_format(slurp(ACCESS).splitlines()), "web")
        self.assertEqual(ls.detect_format(slurp(AUTH).splitlines()), "ssh")


class DetectionTests(unittest.TestCase):
    def analyze(self, lines, **kw):
        events = ls.parse_lines(lines, "ssh", 2026)
        return ls.analyze(events, len(lines), "ssh", **kw)

    def test_burst_is_flagged(self):
        report = self.analyze(fail_lines("192.0.2.1", 6))
        self.assertEqual([s["ip"] for s in report["suspects"]], ["192.0.2.1"])

    def test_below_threshold_not_flagged(self):
        self.assertEqual(self.analyze(fail_lines("192.0.2.1", 4))["suspects"], [])

    def test_slow_trickle_needs_wide_window(self):
        lines = fail_lines("192.0.2.1", 6, step_seconds=1500)     # 25 minutes apart
        self.assertEqual(self.analyze(lines, window=10)["suspects"], [])
        self.assertEqual(len(self.analyze(lines, window=0)["suspects"]), 1)
        self.assertEqual(len(self.analyze(lines, window=200)["suspects"]), 1)

    def test_peak_in_window(self):
        events = ls.parse_lines(fail_lines("192.0.2.1", 5, step_seconds=60), "ssh", 2026)
        self.assertEqual(ls.peak_in_window(events, 2), 3)     # 0:00, 1:00, 2:00 fit in 2 minutes
        self.assertEqual(ls.peak_in_window(events, 0), 5)

    def test_compromise_flag(self):
        lines = fail_lines("192.0.2.9", 6, user="deploy")
        lines.append("Oct 17 10:05:00 h sshd[1]: Accepted password for deploy from 192.0.2.9 port 22 ssh2")
        sus = self.analyze(lines)["suspects"][0]
        self.assertTrue(sus["possible_compromise"])
        self.assertEqual(sus["accepted_users"], ["deploy"])

    def test_success_before_failures_is_not_compromise(self):
        lines = ["Oct 17 09:00:00 h sshd[1]: Accepted password for deploy from 192.0.2.9 port 22 ssh2"]
        lines += fail_lines("192.0.2.9", 6, user="deploy")
        self.assertFalse(self.analyze(lines)["suspects"][0]["possible_compromise"])

    def test_allowlist_cidr(self):
        allow = ls.parse_allow(["192.0.2.0/24"])
        self.assertEqual(self.analyze(fail_lines("192.0.2.1", 9), allow=allow)["suspects"], [])

    def test_invalid_allow_value(self):
        with self.assertRaises(ls.LogSentryError):
            ls.parse_allow(["not-an-ip"])

    def test_web_scanning_and_bruteforce(self):
        lines = slurp(ACCESS).splitlines()
        events = ls.parse_lines(lines, "web", 2026)
        report = ls.analyze(events, len(lines), "web")
        by_ip = {s["ip"]: s for s in report["suspects"]}
        self.assertEqual(by_ip["203.0.113.99"]["reasons"], ["brute-force"])
        self.assertEqual(by_ip["198.51.100.23"]["reasons"], ["scanning"])
        self.assertNotIn("192.0.2.10", by_ip)                 # normal visitor, one 404


class CliTests(unittest.TestCase):
    def test_exit_1_when_suspicious(self):
        code, out, _ = run_cli(AUTH, "--year", "2026")
        self.assertEqual(code, 1)
        self.assertIn("203.0.113.45", out)
        self.assertIn("POSSIBLE COMPROMISE", out)

    def test_exit_0_when_clean(self):
        code, out, _ = run_cli(AUTH, "--year", "2026", "-t", "100")
        self.assertEqual(code, 0)
        self.assertIn("No suspicious IPs detected.", out)

    def test_missing_file_exit_2(self):
        code, _, err = run_cli("does-not-exist.log")
        self.assertEqual(code, 2)
        self.assertIn("File not found", err)

    def test_directory_error(self):
        code, _, err = run_cli(tempfile.gettempdir())
        self.assertEqual(code, 2)
        self.assertIn("directory", err)

    def test_bad_option_value(self):
        code, _, err = run_cli(AUTH, "-t", "0")
        self.assertEqual(code, 2)

    def test_json_report_is_valid(self):
        code, out, _ = run_cli(AUTH, "--year", "2026", "-r", "json")
        data = json.loads(out)
        self.assertEqual(data["format"], "ssh")
        self.assertEqual(len(data["suspects"]), 2)

    def test_csv_report(self):
        _, out, _ = run_cli(AUTH, "--year", "2026", "-r", "csv", "-w", "180")
        rows = out.strip().splitlines()
        self.assertTrue(rows[0].startswith("ip,reasons,failures"))
        self.assertEqual(len(rows), 4)                         # header + 3 suspects with wide window

    def test_gzip_input(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "auth.log.gz")
            with gzip.open(path, "wt") as fh:
                fh.write("\n".join(fail_lines("192.0.2.1", 6)) + "\n")
            code, out, _ = run_cli(path, "--year", "2026")
        self.assertEqual(code, 1)
        self.assertIn("192.0.2.1", out)

    def test_corrupt_gzip(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "bad.log.gz")
            with open(path, "wb") as fh:
                fh.write(b"this is not gzip data")
            code, _, err = run_cli(path)
        self.assertEqual(code, 2)
        self.assertIn("Could not read", err)

    def test_output_file_and_blocklist(self):
        with tempfile.TemporaryDirectory() as tmp:
            rep, block = os.path.join(tmp, "r.txt"), os.path.join(tmp, "block.txt")
            code, out, _ = run_cli(AUTH, "--year", "2026", "-o", rep, "--blocklist", block)
            self.assertEqual(out, "")                          # report went to the file
            self.assertIn("LogSentry", slurp(rep))
            self.assertEqual(slurp(block).split(), ["203.0.113.45", "192.0.2.88"])

    def test_allow_option(self):
        code, out, _ = run_cli(AUTH, "--year", "2026", "--allow", "203.0.113.0/24", "--allow", "192.0.2.88")
        self.assertEqual(code, 0)


if __name__ == "__main__":
    unittest.main()
