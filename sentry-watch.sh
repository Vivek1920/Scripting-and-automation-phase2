#!/usr/bin/env bash
# =============================================================================
# sentry-watch.sh - scheduled wrapper around LogSentry (logsentry.py)
#
# Purpose : Automate the boring part. Run LogSentry on your logs, keep a dated
#           history of reports, and tell you ONLY about IPs that are NEW since
#           the previous run. Designed to run from cron.
#
# It never changes your firewall. It prints suggested ufw commands for you to
# review and run yourself.
#
# Exit codes: 0 = nothing suspicious, 1 = suspicious IPs found, 2 = error
# Usage     : ./sentry-watch.sh -h
# =============================================================================

set -u

# ---------- Defaults (can be changed with options) ----------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOGSENTRY="${LOGSENTRY:-$SCRIPT_DIR/logsentry.py}"   # path to the Python tool
PYTHON="${PYTHON:-python3}"
REPORT_DIR="./sentry-reports"
THRESHOLD=5
WINDOW=10
KEEP_DAYS=30
YEAR=""
MAIL_TO=""
QUIET=0
LOGS=()
ALLOW=()

# ---------- Help ----------
usage() {
    cat <<EOF
sentry-watch.sh - scheduled LogSentry runner

Usage:
  $0 -l <logfile> [-l <logfile> ...] [options]

Options:
  -l FILE   Log file to analyse (repeatable; .gz allowed)         [required]
  -d DIR    Directory to store reports            (default: $REPORT_DIR)
  -t N      Events needed to flag an IP           (default: $THRESHOLD)
  -w MIN    Time window in minutes, 0 = whole file (default: $WINDOW)
  -a CIDR   Ignore this IP/network (repeatable), e.g. -a 10.0.0.0/8
  -k DAYS   Delete reports older than DAYS, 0 = keep forever (default: $KEEP_DAYS)
  -m EMAIL  Email the summary when there are NEW suspect IPs (needs 'mail')
  -y YEAR   Year for syslog timestamps (default: current year)
  -q        Quiet: print nothing unless there are NEW suspect IPs (good for cron)
  -h        Show this help

Environment: LOGSENTRY=/path/to/logsentry.py   PYTHON=python3

Examples:
  $0 -l /var/log/auth.log
  $0 -l /var/log/auth.log -l /var/log/auth.log.1 -a 203.0.113.0/24 -d /var/log/sentry
  # cron: every hour, silent unless something new is found
  0 * * * * /opt/logsentry/sentry-watch.sh -q -l /var/log/auth.log -d /var/log/sentry
EOF
}

# ---------- Helpers ----------
die() {                     # print an error and exit with code 2
    echo "[ERROR] $1" >&2
    exit 2
}

is_number() { [[ "$1" =~ ^[0-9]+$ ]]; }

# ---------- Parse options ----------
while getopts ":l:d:t:w:a:k:m:y:qh" opt; do
    case "$opt" in
        l) LOGS+=("$OPTARG") ;;
        d) REPORT_DIR="$OPTARG" ;;
        t) THRESHOLD="$OPTARG" ;;
        w) WINDOW="$OPTARG" ;;
        a) ALLOW+=("$OPTARG") ;;
        k) KEEP_DAYS="$OPTARG" ;;
        m) MAIL_TO="$OPTARG" ;;
        y) YEAR="$OPTARG" ;;
        q) QUIET=1 ;;
        h) usage; exit 0 ;;
        :) die "Option -$OPTARG needs a value (see -h)." ;;
        \?) die "Unknown option -$OPTARG (see -h)." ;;
    esac
done

# ---------- Validate input ----------
[[ ${#LOGS[@]} -gt 0 ]] || { usage >&2; die "Give at least one log file with -l."; }
for n in "$THRESHOLD" "$WINDOW" "$KEEP_DAYS"; do
    is_number "$n" || die "-t, -w and -k must be whole numbers (got '$n')."
done
[[ "$THRESHOLD" -ge 1 ]] || die "-t must be at least 1."
[[ -z "$YEAR" ]] || is_number "$YEAR" || die "-y must be a year like 2026."
command -v "$PYTHON" >/dev/null 2>&1 || die "'$PYTHON' not found. Install Python 3."
[[ -f "$LOGSENTRY" ]] || die "logsentry.py not found at '$LOGSENTRY' (set LOGSENTRY=...)."
for f in "${LOGS[@]}"; do
    [[ -e "$f" ]] || die "Log file not found: $f"
    [[ -r "$f" ]] || die "Cannot read $f (try sudo)."
done
if [[ -n "$MAIL_TO" ]] && ! command -v mail >/dev/null 2>&1; then
    echo "[WARN] 'mail' command not found; email alerts disabled." >&2
    MAIL_TO=""
fi

# ---------- Prepare report directory and a lock ----------
mkdir -p "$REPORT_DIR" 2>/dev/null || die "Cannot create report directory '$REPORT_DIR'."
LOCK="$REPORT_DIR/.lock"
mkdir "$LOCK" 2>/dev/null || die "Another run is in progress (delete '$LOCK' if it is stale)."
trap 'rmdir "$LOCK" 2>/dev/null' EXIT          # always release the lock

STAMP="$(date +%Y%m%d-%H%M%S)-$$"          # $$ (process id) avoids name clashes
TXT="$REPORT_DIR/report-$STAMP.txt"
JSON="$REPORT_DIR/report-$STAMP.json"
BLOCK_NOW="$REPORT_DIR/blocklist-$STAMP.txt"
BLOCK_LATEST="$REPORT_DIR/blocklist-latest.txt"

# ---------- Build the LogSentry command ----------
ARGS=("${LOGS[@]}" -t "$THRESHOLD" -w "$WINDOW")
[[ -n "$YEAR" ]] && ARGS+=(--year "$YEAR")
for net in ${ALLOW[@]+"${ALLOW[@]}"}; do ARGS+=(--allow "$net"); done

# Run twice: a readable text report (+ blocklist) and a JSON report for other tools.
# stdout is empty because of -o, so $err holds only status/error messages.
err=$("$PYTHON" "$LOGSENTRY" "${ARGS[@]}" -r text -o "$TXT" --blocklist "$BLOCK_NOW" 2>&1 >/dev/null)
rc=$?
[[ $rc -le 1 ]] || die "LogSentry failed: ${err#\[ERROR\] }"
"$PYTHON" "$LOGSENTRY" "${ARGS[@]}" -r json -o "$JSON" >/dev/null 2>&1

# ---------- Which suspect IPs are new since the last run? ----------
touch "$BLOCK_LATEST"                                      # first run: empty history
NEW_IPS="$(comm -13 <(sort "$BLOCK_LATEST") <(sort "$BLOCK_NOW"))"
TOTAL="$(wc -l < "$BLOCK_NOW" | tr -d ' ')"
NEW_COUNT=0
[[ -n "$NEW_IPS" ]] && NEW_COUNT="$(printf '%s\n' "$NEW_IPS" | wc -l | tr -d ' ')"
cp "$BLOCK_NOW" "$BLOCK_LATEST"                            # remember for next time

# Compromise check: count suspects that later logged in. Alert when the count GOES UP,
# so an already-known attacker who finally gets in still triggers an alert.
COMP_FILE="$REPORT_DIR/compromise-latest.count"
COMP_NOW="$(grep -c '"possible_compromise": true' "$JSON" || true)"
COMP_PREV="$(cat "$COMP_FILE" 2>/dev/null || echo 0)"
echo "$COMP_NOW" > "$COMP_FILE"
COMP_NEW=0
[[ "$COMP_NOW" -gt "$COMP_PREV" ]] && COMP_NEW=1

# ---------- Build the summary ----------
SUMMARY="LogSentry watch - $(date '+%Y-%m-%d %H:%M:%S')
  Logs      : ${LOGS[*]}
  Suspicious: $TOTAL IP(s), $NEW_COUNT new since last run
  Report    : $TXT"
if [[ $NEW_COUNT -gt 0 ]]; then
    SUMMARY+=$'\n\nNEW suspicious IPs:\n'"$(printf '%s\n' "$NEW_IPS" | sed 's/^/  /')"
    SUMMARY+=$'\n\nSuggested commands (REVIEW before running, nothing was changed):'
    SUMMARY+=$'\n'"$(printf '%s\n' "$NEW_IPS" | sed 's/^/  sudo ufw deny from /')"
fi
if [[ "$COMP_NOW" -gt 0 ]]; then
    SUMMARY+=$'\n\n[!!] POSSIBLE COMPROMISE: '"$COMP_NOW"$' attacking IP(s) logged in successfully. Open the report now.'
fi

# ---------- Show / send it ----------
if [[ $QUIET -eq 0 || $NEW_COUNT -gt 0 || $COMP_NEW -eq 1 ]]; then
    echo "$SUMMARY"
fi
if [[ -n "$MAIL_TO" && ( $NEW_COUNT -gt 0 || $COMP_NEW -eq 1 ) ]]; then
    { echo "$SUMMARY"; echo; cat "$TXT"; } | mail -s "LogSentry: $NEW_COUNT new suspicious IP(s)" "$MAIL_TO" \
        || echo "[WARN] Could not send email to $MAIL_TO" >&2
fi

# ---------- Delete old reports ----------
if [[ "$KEEP_DAYS" -gt 0 ]]; then
    find "$REPORT_DIR" -maxdepth 1 -type f \
        \( -name 'report-*' -o -name 'blocklist-[0-9]*' \) -mtime +"$KEEP_DAYS" -delete 2>/dev/null
fi

exit "$rc"
