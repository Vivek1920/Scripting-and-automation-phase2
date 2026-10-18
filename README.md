# LogSentry

[![tests](https://github.com/Vivek1920/logsentry/actions/workflows/ci.yml/badge.svg)](https://github.com/Vivek1920/logsentry/actions)
![python](https://img.shields.io/badge/python-3.8%2B-blue)
![license](https://img.shields.io/badge/license-MIT-green)

**A small, dependency-free command-line tool that reads your SSH and web server logs and tells you who is trying to break in.**

Every internet-facing server gets hit by password guessing and scanners within hours. Reading `auth.log` by hand is slow, and `grep | sort | uniq -c` can't tell a burst of 50 guesses from five typos spread over a month. LogSentry does the counting for you, flags attackers by **how fast** they try, and warns you if an attacker **got in**.

## Two tools in one repo

| Tool | Language | What it does |
|------|----------|--------------|
| **`logsentry.py`** | Python | The analyzer. Reads SSH / web logs and reports brute-force, scanning and possible compromise. |
| **`sentry-watch.sh`** | Bash | The automation. Runs the analyzer on a schedule (cron), keeps dated reports, and alerts you **only about new attackers**. |

Use `logsentry.py` for quick investigations. Add `sentry-watch.sh` when you want it to run by itself and only bother you when something changes.

> This is the Phase 2 upgrade of my Phase 1 *Log Analyzer* (Python) plus a new Bash automation tool. New in the Python tool: time-window detection, web-log support, compromise detection, an allow-list, JSON/CSV output, a blocklist file, gzip support, unit tests and CI.

## Features

- **Two log formats, auto-detected:** SSH (`/var/log/auth.log`, syslog or ISO timestamps) and Apache/Nginx *combined* access logs
- **Sliding-window detection:** "5+ failures within 10 minutes" (both numbers configurable), so slow typos are not flagged but bursts are
- **Possible-compromise warning:** flags an IP that failed repeatedly and then *logged in successfully*
- **Web scanner detection:** repeated 404s (probing for `/.env`, `/.git/config`, `/phpmyadmin`...) and repeated 401/403s (login brute-force)
- **Allow-list** trusted IPs or whole networks (`--allow 10.0.0.0/8`), IPv4 and IPv6
- **Reports as text, JSON or CSV**, to the screen or a file
- **Blocklist export:** suspect IPs, one per line (it never touches your firewall)
- Reads `.gz` rotated logs, several files at once, or stdin
- **Script-friendly exit codes:** `0` clean, `1` suspicious activity, `2` error
- Pure Python standard library, 28 Python unit tests + 33 Bash tests, GitHub Actions CI
- **`sentry-watch.sh`:** scheduled runs, dated report history, "new since last run" alerts, optional email, report cleanup (see below)

## Tools & Technologies

Python 3 (standard library only: `argparse`, `re`, `ipaddress`, `gzip`, `csv`, `json`, `dataclasses`), Bash (`getopts`, `comm`, `find`, `mktemp`), regular expressions, `unittest`, cron, GitHub Actions.

## Requirements

- Python 3.8 or newer (developed and tested on 3.11-3.13; CI also runs 3.8 and 3.10)
- For `sentry-watch.sh`: Bash 4+, plus standard `find`, `comm`, `sort` (and optionally `mail` for email alerts)
- Nothing to `pip install`
- Read access to the log (`sudo` is usually needed for `/var/log/auth.log`)

## Installation

```bash
git clone https://github.com/Vivek1920/logsentry.git
cd logsentry
python3 logsentry.py -h
```

## Usage

```bash
python3 logsentry.py <logfile> [<logfile> ...] [options]
```

| Option | Description | Default |
|--------|-------------|---------|
| `-f, --format {auto,ssh,web}` | Log format | `auto` |
| `-t, --threshold N` | Events needed to flag an IP | `5` |
| `-w, --window MIN` | Time window in minutes (`0` = count the whole file) | `10` |
| `-n, --top N` | Rows in the top lists | `5` |
| `--allow IP/CIDR` | Ignore this IP or network (repeatable) | none |
| `--year YEAR` | Year for syslog timestamps (they don't contain one) | current year |
| `-r, --report {text,json,csv}` | Output style | `text` |
| `-o, --output FILE` | Write the report to a file | screen |
| `--blocklist FILE` | Write suspect IPs, one per line | off |
| `--version` | Show version | |

Use `-` as the file name to read from stdin.

### Examples

```bash
# Analyse the system SSH log
sudo python3 logsentry.py /var/log/auth.log

# Rotated + current logs together (compressed files work)
sudo python3 logsentry.py /var/log/auth.log /var/log/auth.log.2.gz

# Stricter: 3 failures within 2 minutes, ignore my office network
python3 logsentry.py auth.log -t 3 -w 2 --allow 203.0.113.0/24

# Catch slow attackers by counting across the whole file
python3 logsentry.py auth.log -w 0

# Web server log
python3 logsentry.py /var/log/nginx/access.log

# JSON for other tools, CSV for a spreadsheet, blocklist for review
python3 logsentry.py auth.log -r json -o report.json
python3 logsentry.py auth.log -r csv -o report.csv --blocklist blocklist.txt

# Use in a script or cron job
python3 logsentry.py auth.log -r json -o /tmp/report.json || echo "suspicious logins found!"
```

Try it right now with the included sample logs (all IPs are from the reserved documentation ranges, so they are fake):

```bash
python3 logsentry.py samples/auth.log --year 2026
python3 logsentry.py samples/access.log
```

## Automating it: `sentry-watch.sh` (Bash)

Running the analyzer by hand every day is exactly the kind of chore worth automating. `sentry-watch.sh` wraps `logsentry.py` and:

1. Runs LogSentry on your log(s) and saves a **text report, a JSON report and a blocklist**, each with a date and time in the name
2. Compares with the previous run and tells you only about **new** suspicious IPs
3. Remembers if an attacker later got in, and alerts when the number of **possible compromises goes up**, even if the IP was already known
4. Prints **suggested `ufw` commands** for you to review (it never changes your firewall)
5. Optionally **emails** the summary (`-m`), and deletes reports older than `-k` days
6. Uses a lock so two runs can't overlap, and returns script-friendly exit codes (`0` clean, `1` suspicious, `2` error)

```bash
chmod +x sentry-watch.sh
./sentry-watch.sh -h

# One run now
sudo ./sentry-watch.sh -l /var/log/auth.log -d /var/log/sentry

# Both current and rotated log, ignore your own network
sudo ./sentry-watch.sh -l /var/log/auth.log -l /var/log/auth.log.1 -a 203.0.113.0/24

# Try it on the included sample (no sudo needed)
./sentry-watch.sh -l samples/auth.log -d reports -y 2026
```

| Option | Description | Default |
|--------|-------------|---------|
| `-l FILE` | Log file to analyse (repeatable) | required |
| `-d DIR` | Where reports are stored | `./sentry-reports` |
| `-t N` / `-w MIN` | Threshold / time window, same as the Python tool | `5` / `10` |
| `-a CIDR` | Ignore a trusted IP or network (repeatable) | none |
| `-k DAYS` | Delete reports older than DAYS (`0` = keep forever) | `30` |
| `-m EMAIL` | Email new findings (needs the `mail` command) | off |
| `-y YEAR` | Year for syslog timestamps | current year |
| `-q` | Quiet: print only when something new is found | off |

### Run it every hour with cron

```cron
# crontab -e   (use sudo crontab -e if the log needs root)
0 * * * * /opt/logsentry/sentry-watch.sh -q -l /var/log/auth.log -d /var/log/sentry -m you@example.com
```

With `-q` it prints nothing when there is nothing new, so cron stays silent until an attacker actually shows up.

Example (first run on the sample log):

```
$ ./sentry-watch.sh -l samples/auth.log -d reports -y 2026
LogSentry watch - 2026-10-18 17:25:55
  Logs      : samples/auth.log
  Suspicious: 2 IP(s), 2 new since last run
  Report    : reports/report-20261018-172554-2101.txt

NEW suspicious IPs:
  192.0.2.88
  203.0.113.45

Suggested commands (REVIEW before running, nothing was changed):
  sudo ufw deny from 192.0.2.88
  sudo ufw deny from 203.0.113.45

[!!] POSSIBLE COMPROMISE: 1 attacking IP(s) logged in successfully. Open the report now.
```

![watch](screenshots/06_sentry_watch.png)

## Example Output

```
$ python3 logsentry.py samples/auth.log --year 2026
LogSentry v2.0.0 - ssh log analysis
Files: samples/auth.log
Lines read: 43 | Failed: 31 | Successful: 4 | Unique failing IPs: 4

=== Top source IPs (failed) ===
  203.0.113.45                   14
  192.0.2.88                     8
  198.51.100.7                   7
  10.0.0.5                       2

=== Top targeted usernames ===
  root                           13
  deploy                         8
  admin                          2
  ubuntu                         2
  test                           2

=== Non-existent usernames tried ===
  admin                          2
  test                           2
  oracle                         2

=== Suspicious IPs (>= 5 events within 10 min) ===
  [!] 203.0.113.45       brute-force: 14 failures (peak 14)  2026-10-17T10:00:00 -> 2026-10-17T10:01:05
      targets: root, admin, ubuntu, test, oracle
  [!] 192.0.2.88         brute-force: 8 failures (peak 8)  2026-10-17T10:40:00 -> 2026-10-17T10:40:49
      targets: deploy
      [!!] POSSIBLE COMPROMISE: successful login as deploy after failures
```

What to notice: `198.51.100.7` tried 7 times but over 2.5 hours, so it is **not** flagged with the default 10-minute window (add `-w 180` or `-w 0` to catch it). `10.0.0.5` made two typos and then logged in, which is normal and not flagged.

Web log:

```
$ python3 logsentry.py samples/access.log
=== Suspicious IPs (>= 5 events within 10 min) ===
  [!] 198.51.100.23      scanning: 16 probes (peak 16)  2026-10-17T10:00:00 -> 2026-10-17T10:00:30
      targets: /admin, /.env, /phpmyadmin/, /backup.zip, /.git/config
  [!] 203.0.113.99       brute-force: 12 failures (peak 12)  2026-10-17T10:00:00 -> 2026-10-17T10:00:44
      targets: /wp-login.php
```

## Screenshots

| | |
|---|---|
| **SSH analysis** ![ssh](screenshots/01_ssh_analysis.png) | **Web log analysis** ![web](screenshots/02_web_analysis.png) |
| **CSV report + blocklist** ![csv](screenshots/03_csv_and_blocklist.png) | **Unit tests** ![tests](screenshots/04_unit_tests.png) |

**Help screen**

![help](screenshots/05_help.png)

## How Detection Works

1. Each log line is parsed into an event: *failed*, *success*, *invalid user* (SSH) or *failed* (401/403), *probe* (404) (web).
2. Events are grouped per source IP.
3. For each IP, a two-pointer sliding window finds the **largest number of events inside any `--window` minutes**. If it reaches `--threshold`, the IP is flagged `brute-force` and/or `scanning`.
4. If a flagged IP has a successful SSH login **after** its first failure, it is marked `POSSIBLE COMPROMISE`.
5. If a line has no readable timestamp, LogSentry falls back to counting all events for that IP.

Note: sshd logs both `Invalid user x` and `Failed password for invalid user x` for one attempt. Only the *Failed* line counts as a failure; the *Invalid user* line feeds the "Non-existent usernames" list, so attempts are never double counted.

## Acting on the results

LogSentry only reports. To block an IP, review the list first, then use your own firewall, for example:

```bash
# Review blocklist.txt first! Then, on Ubuntu with ufw:
while read ip; do sudo ufw deny from "$ip"; done < blocklist.txt
```

For automatic banning in production, a mature tool such as `fail2ban` is the better choice. LogSentry is for quick analysis and reporting.

## Testing

```bash
python3 -m unittest discover -s tests -v   # Python tool: 28 tests
bash tests/test_watch.sh                   # Bash tool: 33 checks
```

The Python tests cover parsing (including IPv6 and garbage input), the sliding window, compromise detection, the allow-list, web logs, gzip input, JSON/CSV output and error exit codes. The Bash tests cover argument errors, first/second/new-attacker runs, quiet mode, the allow-list, email (with a fake `mail`), report cleanup and the lock. Both run automatically on every push through GitHub Actions.

## Important Notes & Limitations

- Supports OpenSSH (`sshd`) messages and Apache/Nginx **combined** log format only
- Logs are read fully into memory, which is fine for typical logs but not for multi-gigabyte files
- Syslog timestamps have no year, so `--year` (default: current year) is assumed
- Attackers using many different IPs, each below the threshold, will not be flagged
- Detection quality depends on your `--threshold` and `--window`; tune them for your server's normal traffic
- `sentry-watch.sh` is for Linux/WSL (it uses `comm`, `find -delete` and process substitution); it needs a real `mail` command for email alerts
- `sentry-watch.sh` compares against the **last run's** results, so if a log rotates, old attackers drop out of the list and may show as "new" if they return
- If a run is killed, delete `<report dir>/.lock` before the next run
- Analyse only logs from systems you own or are authorised to administer

## Challenges Faced

- Avoiding double-counting, since sshd writes two log lines for one invalid-user attempt
- Telling a burst of guesses from slow typos, which needed the sliding window instead of a simple total
- Handling logs with no year in the timestamp and malformed or non-IP addresses
- Making the tool useful both for humans (text) and for scripts (JSON/CSV, exit codes)
- Alerting without spamming: the Bash tool remembers the last run, so cron only reports what changed
- Writing tests that can really fail: the Bash tests were checked against a deliberately broken script to prove they catch bugs

## Future Improvements

- Streaming input for very large logs
- More formats (journald JSON, Windows Event logs, Postfix)
- Optional GeoIP / reverse-DNS enrichment
- Live "follow" mode (`tail -f`) with alerts
- Package for `pip install logsentry`
- Optional Slack/Telegram webhook alerts from `sentry-watch.sh`

## Contributing

Issues and pull requests are welcome. Please add a test for any change and make sure both `python3 -m unittest discover -s tests` and `bash tests/test_watch.sh` pass.

## License

[MIT](LICENSE)
