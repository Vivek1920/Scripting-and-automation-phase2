#!/usr/bin/env python3
"""
LogSentry - brute-force detector for SSH auth logs and web access logs.

What it does
------------
Reads one or more log files (plain text, .gz, or stdin), finds failed logins
(SSH) or failed/probing requests (web), and reports the source IPs that look
like brute-force or scanning activity. Detection uses a sliding time window
("N failures within M minutes"), so a slow trickle of typos is not flagged but
a burst of guesses is. It also warns when an attacking IP later logged in
successfully (possible compromise).

The tool only READS logs. It never blocks or changes anything on your system.

Exit codes: 0 = nothing suspicious, 1 = suspicious activity found, 2 = error.

Usage: python3 logsentry.py -h
"""

import argparse
import csv
import gzip
import io
import ipaddress
import json
import re
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Iterable, List, Optional, Sequence

__version__ = "2.0.0"

# --------------------------------------------------------------------------
# Patterns
# --------------------------------------------------------------------------

# Timestamps: classic syslog ("Oct  4 10:00:01", no year) or ISO ("2026-10-04T10:00:01")
SYSLOG_TS = re.compile(r"^([A-Z][a-z]{2}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})\s")
ISO_TS = re.compile(r"^(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2}:\d{2})")

# sshd messages. The IP group is validated afterwards with the ipaddress module.
_IP = r"(?P<ip>[0-9A-Fa-f:.]+)"
SSH_FAILED = re.compile(
    r"Failed (?:password|publickey|keyboard-interactive/pam|none) for "
    r"(?:invalid user )?(?P<user>\S+) from " + _IP
)
SSH_SUCCESS = re.compile(r"Accepted \S+ for (?P<user>\S+) from " + _IP)
SSH_INVALID = re.compile(r"Invalid user (?P<user>\S+) from " + _IP)

# Apache/Nginx "combined" access log line
WEB_LINE = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] "(?P<req>[^"]*)" (?P<status>\d{3}) '
)

FORMATS = ("ssh", "web")


class LogSentryError(Exception):
    """A problem the user can fix (bad file, bad option). Shown without a traceback."""


@dataclass
class Event:
    """One interesting log line, reduced to the fields we need."""
    seq: int                    # order in which it was read (used for "after" checks)
    time: Optional[datetime]    # None when the line has no usable timestamp
    ip: str
    target: str                 # username (ssh) or request path (web)
    kind: str                   # failed | success | invalid | probe


# --------------------------------------------------------------------------
# Parsing
# --------------------------------------------------------------------------

def valid_ip(text: str) -> Optional[str]:
    """Return the normalised IP string, or None if `text` is not a real IP."""
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        return None


def parse_time(line: str, year: int) -> Optional[datetime]:
    """Extract a timestamp from the start of a syslog/ISO line (naive datetime)."""
    m = ISO_TS.match(line)
    try:
        if m:
            return datetime.strptime(f"{m.group(1)} {m.group(2)}", "%Y-%m-%d %H:%M:%S")
        m = SYSLOG_TS.match(line)
        if m:
            # syslog has no year, so we supply one (--year, default: current year)
            return datetime.strptime(f"{year} {m.group(1)}", "%Y %b %d %H:%M:%S")
    except ValueError:
        pass
    return None


def parse_ssh_line(line: str, year: int):
    """Return (kind, user, ip, time) for an sshd line of interest, else None."""
    for kind, rx in (("failed", SSH_FAILED), ("success", SSH_SUCCESS), ("invalid", SSH_INVALID)):
        m = rx.search(line)
        if m:
            ip = valid_ip(m.group("ip"))
            if ip is None:
                return None
            return kind, m.group("user"), ip, parse_time(line, year)
    return None


def parse_web_line(line: str):
    """Return (kind, path, ip, time) for a combined-log line, else None.

    401/403 responses count as failed access; 404s count as probes (scanning).
    """
    m = WEB_LINE.match(line)
    if not m:
        return None
    status = int(m.group("status"))
    if status in (401, 403):
        kind = "failed"
    elif status == 404:
        kind = "probe"
    else:
        return None
    ip = valid_ip(m.group("ip"))
    if ip is None:
        return None
    parts = m.group("req").split()
    path = parts[1] if len(parts) > 1 else "-"
    try:
        when = datetime.strptime(m.group("ts"), "%d/%b/%Y:%H:%M:%S %z").replace(tzinfo=None)
    except ValueError:
        when = None
    return kind, path, ip, when


def detect_format(lines: Sequence[str]) -> str:
    """Guess 'web' or 'ssh' from the first lines of the input."""
    for line in lines[:50]:
        if WEB_LINE.match(line):
            return "web"
    return "ssh"


def parse_lines(lines: Iterable[str], fmt: str, year: int) -> List[Event]:
    """Turn raw log lines into Event objects (lines we don't care about are skipped)."""
    events = []
    for seq, line in enumerate(lines):
        parsed = parse_web_line(line) if fmt == "web" else parse_ssh_line(line, year)
        if parsed:
            kind, target, ip, when = parsed
            events.append(Event(seq, when, ip, target, kind))
    return events


# --------------------------------------------------------------------------
# Detection
# --------------------------------------------------------------------------

def peak_in_window(events: Sequence[Event], window_minutes: int) -> int:
    """Largest number of events that fall inside any `window_minutes` span.

    If window is 0, or any event has no timestamp, we fall back to the plain
    total so the tool still works on logs without usable times.
    """
    if window_minutes <= 0 or any(e.time is None for e in events):
        return len(events)
    times = sorted(e.time for e in events)
    span = timedelta(minutes=window_minutes)
    best, lo = 0, 0
    for hi in range(len(times)):
        while times[hi] - times[lo] > span:      # shrink window from the left
            lo += 1
        best = max(best, hi - lo + 1)
    return best


def is_allowed(ip: str, allow: Sequence) -> bool:
    """True if `ip` belongs to any allow-listed network."""
    addr = ipaddress.ip_address(ip)
    return any(addr in net for net in allow if net.version == addr.version)


def analyze(events: Sequence[Event], line_count: int, fmt: str, threshold: int = 5,
            window: int = 10, top: int = 5, allow: Sequence = ()) -> dict:
    """Build the full report (a plain dict, easy to print or dump as JSON)."""
    events = [e for e in events if not is_allowed(e.ip, allow)]

    failed_by_ip = defaultdict(list)
    probe_by_ip = defaultdict(list)
    success_by_ip = defaultdict(list)
    for e in events:
        if e.kind == "failed":
            failed_by_ip[e.ip].append(e)
        elif e.kind == "probe":
            probe_by_ip[e.ip].append(e)
        elif e.kind == "success":
            success_by_ip[e.ip].append(e)

    suspects = []
    for ip in sorted(set(failed_by_ip) | set(probe_by_ip)):
        evs = failed_by_ip.get(ip, [])
        probes = probe_by_ip.get(ip, [])
        peak_fail = peak_in_window(evs, window) if evs else 0
        peak_probe = peak_in_window(probes, window) if probes else 0
        reasons = []
        if peak_fail >= threshold:
            reasons.append("brute-force")
        if peak_probe >= threshold:
            reasons.append("scanning")
        if not reasons:
            continue
        everything = evs + probes
        first_seq = min(e.seq for e in everything)
        # Compromise check: a successful login from the same IP AFTER it started failing
        later_ok = [s for s in success_by_ip.get(ip, []) if s.seq > first_seq]
        times = [e.time for e in everything if e.time]
        targets = Counter(e.target for e in everything)
        suspects.append({
            "ip": ip,
            "reasons": reasons,
            "failures": len(evs),
            "probes": len(probes),
            "peak_in_window": max(peak_fail, peak_probe),
            "first_seen": min(times).isoformat() if times else None,
            "last_seen": max(times).isoformat() if times else None,
            "distinct_targets": len(targets),
            "targets": [t for t, _ in targets.most_common(5)],
            "possible_compromise": bool(later_ok),
            "accepted_users": sorted({s.target for s in later_ok}),
        })
    suspects.sort(key=lambda s: (-(s["failures"] + s["probes"]), s["ip"]))

    def counter(kind, key):
        return Counter(key(e) for e in events if e.kind == kind)

    return {
        "tool": "logsentry",
        "version": __version__,
        "format": fmt,
        "settings": {"threshold": threshold, "window_minutes": window},
        "lines_read": line_count,
        "failed_total": sum(len(v) for v in failed_by_ip.values()),
        "success_total": sum(len(v) for v in success_by_ip.values()),
        "unique_failing_ips": len(failed_by_ip),
        "top_ips": counter("failed", lambda e: e.ip).most_common(top),
        "top_targets": counter("failed", lambda e: e.target).most_common(top),
        "invalid_users": counter("invalid", lambda e: e.target).most_common(top),
        "probing_ips": counter("probe", lambda e: e.ip).most_common(top),
        "suspects": suspects,
    }


# --------------------------------------------------------------------------
# Output
# --------------------------------------------------------------------------

def render_text(report: dict, files: Sequence[str]) -> str:
    """Human-readable report."""
    web = report["format"] == "web"
    s = report["settings"]
    window_txt = f"within {s['window_minutes']} min" if s["window_minutes"] else "in total"
    out = [
        f"LogSentry v{report['version']} - {report['format']} log analysis",
        f"Files: {', '.join(files)}",
        f"Lines read: {report['lines_read']} | Failed: {report['failed_total']} | "
        f"{'Successful: ' + str(report['success_total']) + ' | ' if not web else ''}"
        f"Unique failing IPs: {report['unique_failing_ips']}",
    ]

    def table(title, rows):
        out.append(f"\n=== {title} ===")
        if not rows:
            out.append("  (none found)")
        for name, count in rows:
            out.append(f"  {name:<30} {count}")

    table("Top source IPs (failed)", report["top_ips"])
    table("Top targeted paths" if web else "Top targeted usernames", report["top_targets"])
    if web:
        table("Top probing IPs (404 scans)", report["probing_ips"])
    else:
        table("Non-existent usernames tried", report["invalid_users"])

    out.append(f"\n=== Suspicious IPs (>= {s['threshold']} events {window_txt}) ===")
    if not report["suspects"]:
        out.append("  No suspicious IPs detected.")
    for sus in report["suspects"]:
        when = f"  {sus['first_seen']} -> {sus['last_seen']}" if sus["first_seen"] else ""
        counts = ", ".join(x for x in (f"{sus['failures']} failures" if sus["failures"] else "",
                                       f"{sus['probes']} probes" if sus["probes"] else "") if x)
        out.append(f"  [!] {sus['ip']:<18} {'+'.join(sus['reasons'])}: {counts} "
                   f"(peak {sus['peak_in_window']}){when}")
        out.append(f"      targets: {', '.join(sus['targets'])}")
        if sus["possible_compromise"]:
            users = ", ".join(sus["accepted_users"])
            out.append(f"      [!!] POSSIBLE COMPROMISE: successful login as {users} after failures")
    return "\n".join(out) + "\n"


def render_json(report: dict, files: Sequence[str]) -> str:
    return json.dumps({**report, "files": list(files)}, indent=2) + "\n"


def render_csv(report: dict, files: Sequence[str]) -> str:
    """One row per suspect IP (opens nicely in a spreadsheet)."""
    buf = io.StringIO()
    cols = ["ip", "reasons", "failures", "probes", "peak_in_window", "first_seen", "last_seen",
            "distinct_targets", "targets", "possible_compromise", "accepted_users"]
    writer = csv.writer(buf, lineterminator="\n")
    writer.writerow(cols)
    for sus in report["suspects"]:
        writer.writerow([";".join(map(str, sus[c])) if isinstance(sus[c], list) else sus[c]
                         for c in cols])
    return buf.getvalue()


RENDERERS = {"text": render_text, "json": render_json, "csv": render_csv}


# --------------------------------------------------------------------------
# Input helpers
# --------------------------------------------------------------------------

def read_lines(path: str) -> List[str]:
    """Read a log file (plain or .gz) or stdin ('-'), with friendly errors."""
    try:
        if path == "-":
            return sys.stdin.read().splitlines()
        opener = gzip.open if path.endswith(".gz") else open
        with opener(path, "rt", encoding="utf-8", errors="replace") as handle:
            return handle.read().splitlines()
    except FileNotFoundError:
        raise LogSentryError(f"File not found: {path}")
    except PermissionError:
        raise LogSentryError(f"Permission denied: {path} (try sudo)")
    except IsADirectoryError:
        raise LogSentryError(f"'{path}' is a directory, not a file.")
    except (OSError, EOFError) as exc:          # e.g. corrupt .gz
        raise LogSentryError(f"Could not read {path}: {exc}")


def parse_allow(values: Sequence[str]) -> list:
    """Convert --allow values (IP or CIDR) into network objects."""
    nets = []
    for value in values:
        try:
            nets.append(ipaddress.ip_network(value, strict=False))
        except ValueError:
            raise LogSentryError(f"Invalid --allow value: {value!r} (use an IP or CIDR)")
    return nets


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="logsentry",
        description="LogSentry - detect brute-force and scanning activity in SSH and web logs.",
        epilog="Exit codes: 0 clean, 1 suspicious activity found, 2 error.",
    )
    p.add_argument("logfiles", nargs="+", help="log file(s); .gz supported; '-' reads stdin")
    p.add_argument("-f", "--format", choices=("auto",) + FORMATS, default="auto",
                   help="log format (default: auto-detect)")
    p.add_argument("-t", "--threshold", type=int, default=5,
                   help="failures needed to flag an IP (default: 5)")
    p.add_argument("-w", "--window", type=int, default=10,
                   help="time window in minutes; 0 = count whole file (default: 10)")
    p.add_argument("-n", "--top", type=int, default=5, help="rows in top lists (default: 5)")
    p.add_argument("--allow", action="append", default=[], metavar="IP/CIDR",
                   help="ignore this IP or network (repeatable), e.g. --allow 10.0.0.0/8")
    p.add_argument("--year", type=int, default=datetime.now().year,
                   help="year for syslog timestamps, which have none (default: current)")
    p.add_argument("-r", "--report", choices=tuple(RENDERERS), default="text",
                   help="output style (default: text)")
    p.add_argument("-o", "--output", help="write the report to this file instead of the screen")
    p.add_argument("--blocklist", metavar="FILE",
                   help="also write the suspect IPs, one per line, to FILE")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------

def run(args: argparse.Namespace) -> int:
    if args.threshold < 1 or args.top < 1 or args.window < 0:
        raise LogSentryError("--threshold and --top must be >= 1, --window must be >= 0.")
    allow = parse_allow(args.allow)

    lines: List[str] = []
    for path in args.logfiles:
        lines.extend(read_lines(path))

    fmt = detect_format(lines) if args.format == "auto" else args.format
    events = parse_lines(lines, fmt, args.year)
    report = analyze(events, len(lines), fmt, args.threshold, args.window, args.top, allow)
    text = RENDERERS[args.report](report, args.logfiles)

    try:
        if args.output:
            with open(args.output, "w", encoding="utf-8", newline="") as handle:
                handle.write(text)
            print(f"[+] Report written to {args.output}", file=sys.stderr)
        else:
            sys.stdout.write(text)
        if args.blocklist:
            with open(args.blocklist, "w", encoding="utf-8") as handle:
                handle.writelines(f"{s['ip']}\n" for s in report["suspects"])
            print(f"[+] {len(report['suspects'])} IP(s) written to {args.blocklist}",
                  file=sys.stderr)
    except OSError as exc:
        raise LogSentryError(f"Could not write output: {exc}")

    return 1 if report["suspects"] else 0


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return run(args)
    except LogSentryError as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
