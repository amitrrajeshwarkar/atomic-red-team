#!/usr/bin/env bash
# smoke.sh - syntax-check every tool, verify --help/--version, then run each tool on this host
# (Linux or macOS) and fail on non-zero exit or bash error output. Safe: tools are read-only.
set -u
HERE="$(cd "$(dirname "$0")/.." && pwd)"
fail=0; pass=0
say() { printf '%s\n' "$*"; }
for t in "$HERE"/bin/nfx-*; do
  n=$(basename "$t")
  if ! bash -n "$t" 2>/dev/null; then say "FAIL syntax   $n"; fail=$((fail+1)); continue; fi
  if ! "$t" --help 2>/dev/null | grep -q "^$n"; then say "FAIL --help   $n"; fail=$((fail+1)); continue; fi
  if ! "$t" --version 2>/dev/null | grep -qE "^$n [0-9]"; then say "FAIL --version $n"; fail=$((fail+1)); continue; fi
  pass=$((pass+1))
done
say "static checks: $pass ok, $fail failed"

TMP=$(mktemp -d 2>/dev/null || mktemp -d -t nfx)
trap 'rm -rf "$TMP"' EXIT
run() { # run <label> <cmd...> : non-zero rc or "line N:" bash errors fail the test
  local lbl="$1"; shift
  local out="$TMP/$lbl.out" rc
  "$@" > "$out" 2>&1; rc=$?
  if [ "$rc" -ne 0 ] || grep -qE '^[^ ]*nfx-[a-z-]+: line [0-9]+: ' "$out"; then
    say "FAIL run      $lbl (rc=$rc)"; grep -E '^[^ ]*nfx-[a-z-]+: line [0-9]+: ' "$out" | head -5 | sed 's/^/      /'; fail=$((fail+1))
  else say "ok   run      $lbl ($(wc -l < "$out" | tr -d ' ') lines, $(grep -c '^\[!\]' "$out") flags)"; pass=$((pass+1)); fi
}
B="$HERE/bin"
run sysinfo     "$B/nfx-sysinfo"
run users       "$B/nfx-users"
run auth        "$B/nfx-auth" --since 1d
run persistence "$B/nfx-persistence" --since 7d
run procs       "$B/nfx-procs" --no-hidden-scan
run procs-csv   "$B/nfx-procs" --csv --no-hidden-scan
run network     "$B/nfx-network"
run ssh         "$B/nfx-ssh"
run shellhist   "$B/nfx-shellhist" --tail 3
run shellhist-csv "$B/nfx-shellhist" --csv
run recent      "$B/nfx-recent" --since 1h --limit 20 --path /etc --path /tmp
run recent-csv  "$B/nfx-recent" --since 1h --csv --limit 20 --path /etc
run timeline    "$B/nfx-timeline" --limit 20 /etc
run timeline-body "$B/nfx-timeline" --bodyfile --limit 20 /etc
run suid        "$B/nfx-suid" --path /usr --save "$TMP/suid.txt"
run suid-cmp    "$B/nfx-suid" --path /usr --compare "$TMP/suid.txt"
run kernel      "$B/nfx-kernel"
run mounts      "$B/nfx-mounts"
run packages    "$B/nfx-packages" --since 30d
run logs        "$B/nfx-logs" --since 1h
run containers  "$B/nfx-containers"
mkdir -p "$TMP/www/uploads"; printf '<?php eval(base64_decode($_POST["x"])); ?>' > "$TMP/www/uploads/a.php"
run webshell    "$B/nfx-webshell" --path "$TMP/www"
grep -q 'WEBSHELL-LIKELY' "$TMP/webshell.out" || { say "FAIL detect   webshell sample not flagged"; fail=$((fail+1)); }
run hash        "$B/nfx-hash" "$TMP/www"
run hash-procs  "$B/nfx-hash" --procs
h=$(awk -F, 'NR==2{print $1}' "$TMP/hash.out")
printf '%s\n127.0.0.1\na.php\n' "$h" > "$TMP/iocs.txt"
run ioc         "$B/nfx-ioc" -i "$TMP/iocs.txt" --path "$TMP/www"
grep -q 'IOC-sha256' "$TMP/ioc.out" || { say "FAIL detect   ioc hash not matched"; fail=$((fail+1)); }
run mac         "$B/nfx-mac-artifacts"
run diff        "$B/nfx-diff" "$TMP/sysinfo.out" "$TMP/users.out"
run triage      "$B/nfx-triage" -d "$TMP/triage" --quick --tools sysinfo,users,ssh --no-tar
[ -s "$TMP/triage/manifest.csv" ] && [ -s "$TMP/triage/findings.txt" ] || { say "FAIL triage   manifest/findings missing"; fail=$((fail+1)); }
say "----"
say "total: $pass ok, $fail failed"
[ "$fail" -eq 0 ]
