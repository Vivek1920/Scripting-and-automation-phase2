#!/usr/bin/env bash
# Tests for sentry-watch.sh. Run with:  bash tests/test_watch.sh
# Plain Bash, no extra tools needed.

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WATCH="$ROOT/sentry-watch.sh"
SAMPLE="$ROOT/samples/auth.log"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

pass=0; fail=0
check() {                       # check "description" <command...>  -> passes if command succeeds
    local desc="$1"; shift
    if "$@"; then pass=$((pass+1)); echo "  ok   - $desc"
    else fail=$((fail+1)); echo "  FAIL - $desc"; fi
}
has()   { grep -q -- "$1" <<<"$OUT"; }        # has "text":   is text in the last output?
lacks() { ! grep -q -- "$1" <<<"$OUT"; }      # lacks "text": is text absent from it?
run() { OUT="$("$@" 2>&1)"; RC=$?; }          # run a command, keep output + exit code

echo "sentry-watch.sh tests"

# ---- help and argument errors ----
run "$WATCH" -h;                         check "-h exits 0" test $RC -eq 0
check "-h prints Usage" has "Usage:"
run "$WATCH";                            check "no -l exits 2" test $RC -eq 2
run "$WATCH" -l "$TMP/missing.log";      check "missing log exits 2" test $RC -eq 2
check "missing log has clear message" has "Log file not found"
run "$WATCH" -l "$SAMPLE" -t abc -d "$TMP/r0"; check "non-numeric -t exits 2" test $RC -eq 2
run "$WATCH" -l "$SAMPLE" -z;            check "unknown option exits 2" test $RC -eq 2

# ---- first run: everything is new ----
R="$TMP/reports"
run "$WATCH" -l "$SAMPLE" -d "$R" -y 2026
check "first run exits 1 (suspicious)" test $RC -eq 1
check "reports 2 new IPs" has "2 new since last run"
check "lists attacker 203.0.113.45" has "203.0.113.45"
check "suggests ufw command" has "sudo ufw deny from 203.0.113.45"
check "warns about compromise" has "POSSIBLE COMPROMISE"
check "text report created" bash -c "ls '$R'/report-*.txt >/dev/null 2>&1"
check "json report created" bash -c "ls '$R'/report-*.json >/dev/null 2>&1"
check "blocklist-latest has 2 IPs" test "$(wc -l < "$R/blocklist-latest.txt" | tr -d ' ')" -eq 2

# ---- second run: nothing new ----
run "$WATCH" -l "$SAMPLE" -d "$R" -y 2026
check "second run exits 1" test $RC -eq 1
check "second run: 0 new" has "0 new since last run"
check "second run: no ufw suggestion" lacks "ufw deny"
run "$WATCH" -q -l "$SAMPLE" -d "$R" -y 2026
check "quiet mode prints nothing when nothing is new" test -z "$OUT"

# ---- a new attacker appears ----
EXTRA="$TMP/extra.log"
cp "$SAMPLE" "$EXTRA"
for i in 1 2 3 4 5 6; do
    echo "Oct 17 11:00:0$i web01 sshd[9]: Failed password for root from 198.18.0.9 port 22 ssh2" >> "$EXTRA"
done
run "$WATCH" -l "$EXTRA" -d "$R" -y 2026
check "new attacker detected: 1 new" has "1 new since last run"
check "new attacker is 198.18.0.9" has "198.18.0.9"
check "old attackers not re-listed as new" lacks "ufw deny from 203.0.113.45"
run "$WATCH" -q -l "$EXTRA" -d "$R" -y 2026
check "quiet + nothing new = silent" test -z "$OUT"

# ---- allow-list makes it clean ----
run "$WATCH" -l "$SAMPLE" -d "$TMP/clean" -y 2026 -a 203.0.113.0/24 -a 192.0.2.0/24
check "allow-listed run exits 0" test $RC -eq 0
check "allow-listed run: 0 suspicious" has "Suspicious: 0 IP"

# ---- quiet mode still alerts on the first run ----
run "$WATCH" -q -l "$SAMPLE" -d "$TMP/q" -y 2026
check "quiet mode alerts when IPs are new" has "NEW suspicious IPs"

# ---- compromise alert for an already-known attacker ----
C="$TMP/comp"; K="$TMP/known.log"
for i in 1 2 3 4 5 6; do echo "Oct 17 10:00:0$i h sshd[1]: Failed password for dev from 192.0.2.50 port 22 ssh2"; done > "$K"
run "$WATCH" -q -l "$K" -d "$C" -y 2026                       # attacker becomes known
echo "Oct 17 10:05:00 h sshd[1]: Accepted password for dev from 192.0.2.50 port 22 ssh2" >> "$K"
run "$WATCH" -q -l "$K" -d "$C" -y 2026                       # now they got in
check "known attacker who logs in triggers a quiet-mode alert" has "POSSIBLE COMPROMISE"

# ---- email via a fake 'mail' command ----
BIN="$TMP/bin"; mkdir -p "$BIN"
printf '#!/usr/bin/env bash\ncat > "%s/mail.out"\necho "$@" > "%s/mail.args"\n' "$TMP" "$TMP" > "$BIN/mail"
chmod +x "$BIN/mail"
PATH="$BIN:$PATH" run "$WATCH" -l "$SAMPLE" -d "$TMP/m" -y 2026 -m admin@example.com
check "email sent when new IPs found" test -s "$TMP/mail.out"
check "email addressed correctly" grep -q "admin@example.com" "$TMP/mail.args"

# ---- pruning old reports ----
P="$TMP/prune"; mkdir -p "$P"
touch -d '40 days ago' "$P/report-20200101-000000-1.txt" 2>/dev/null
if [[ -e "$P/report-20200101-000000-1.txt" && $(find "$P" -mtime +30 | wc -l) -gt 0 ]]; then
    run "$WATCH" -l "$SAMPLE" -d "$P" -y 2026 -k 30
    check "reports older than -k days are deleted" test ! -e "$P/report-20200101-000000-1.txt"
    touch -d '40 days ago' "$P/report-20200101-000000-2.txt"
    run "$WATCH" -l "$SAMPLE" -d "$P" -y 2026 -k 0
    check "-k 0 keeps everything" test -e "$P/report-20200101-000000-2.txt"
else
    echo "  skip - touch -d not supported on this system"
fi

# ---- lock ----
L="$TMP/lock"; mkdir -p "$L/.lock"
run "$WATCH" -l "$SAMPLE" -d "$L" -y 2026
check "refuses to run while locked (exit 2)" test $RC -eq 2
check "lock message is clear" has "Another run is in progress"

echo
echo "passed: $pass  failed: $fail"
[[ $fail -eq 0 ]]
