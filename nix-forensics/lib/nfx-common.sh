#!/usr/bin/env bash
# nfx-common.sh - shared helpers for the nix-forensics (nfx) toolkit.
#
# Sourced by every nfx-* tool. Must stay compatible with bash 3.2 (macOS
# default) and must not depend on anything beyond POSIX + coreutils-ish
# tools that ship with Linux and macOS.

NFX_VERSION="1.0.0"

# ---------------------------------------------------------------------------
# OS detection
# ---------------------------------------------------------------------------
case "$(uname -s 2>/dev/null)" in
  Darwin) NFX_OS="macos" ;;
  Linux)  NFX_OS="linux" ;;
  *)      NFX_OS="other" ;;
esac
export NFX_OS

nfx_is_linux() { [ "$NFX_OS" = "linux" ]; }
nfx_is_macos() { [ "$NFX_OS" = "macos" ]; }
nfx_have()     { command -v "$1" >/dev/null 2>&1; }
nfx_is_root()  { [ "$(id -u)" = "0" ]; }

# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------
NFX_COLOR=0
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then NFX_COLOR=1; fi
NFX_FINDINGS_FILE=$(mktemp -t nfx-findings.XXXXXX 2>/dev/null || echo "/tmp/nfx-findings.$$")
NFX_TMPFILES="$NFX_FINDINGS_FILE"
nfx_cleanup() { rm -f $NFX_TMPFILES 2>/dev/null; }
trap nfx_cleanup EXIT
# nfx_mktemp -> path of a temp file that is removed on exit
nfx_mktemp() {
  local t; t=$(mktemp -t nfx.XXXXXX 2>/dev/null || echo "/tmp/nfx.$$.$RANDOM"); : > "$t"
  NFX_TMPFILES="$NFX_TMPFILES $t"; printf '%s' "$t"
}

nfx_c() { # nfx_c <color> <text>
  if [ "$NFX_COLOR" = 1 ]; then printf '\033[%sm%s\033[0m' "$1" "$2"; else printf '%s' "$2"; fi
}

nfx_header() {
  printf '\n%s\n' "$(nfx_c '1;36' "==================== $* ====================")"
}

nfx_section() {
  printf '\n%s\n' "$(nfx_c '1;33' "--- $* ---")"
}

nfx_info() { printf '[*] %s\n' "$*"; }
nfx_warn() { printf '%s %s\n' "$(nfx_c '1;35' '[-]')" "$*" >&2; }
nfx_die()  { nfx_warn "$*"; exit 1; }

# nfx_flag <TAG> <message>  - a noteworthy finding for the analyst.
# Findings are appended to a file so counts survive subshells/pipelines.
nfx_flag() {
  printf '%s [%s] %s\n' "$(nfx_c '1;31' '[!]')" "$1" "$2"
  printf '[%s] %s\n' "$1" "$2" >> "$NFX_FINDINGS_FILE" 2>/dev/null
}

nfx_findings_summary() {
  local n=0
  [ -r "$NFX_FINDINGS_FILE" ] && n=$(wc -l < "$NFX_FINDINGS_FILE" | tr -d ' ')
  printf '\n%s\n' "$(nfx_c '1;36' "==================== Findings recap: $n flagged by ${NFX_TOOL:-nfx} ====================")"
  [ "$n" -gt 0 ] && cat "$NFX_FINDINGS_FILE"
  printf '[*] Flags are leads, not verdicts - verify each one against the raw output above.\n'
}

nfx_root_hint() {
  nfx_is_root || nfx_warn "Not running as root: some artifacts will be unreadable or incomplete."
}

# Print a file with a header if it exists and is readable.
nfx_cat_if() { # nfx_cat_if <file> [max_lines]
  local f="$1" max="${2:-0}"
  if [ -r "$f" ]; then
    nfx_section "$f"
    if [ "$max" -gt 0 ] 2>/dev/null; then head -n "$max" "$f"; else cat "$f"; fi
  fi
}

# Run a command and print its output under a section header, if the command exists.
nfx_run() { # nfx_run <section title> <cmd> [args...]
  local title="$1"; shift
  nfx_have "$1" || { nfx_info "$title: '$1' not available"; return 1; }
  nfx_section "$title"
  "$@" 2>&1
}

# ---------------------------------------------------------------------------
# Time helpers
# ---------------------------------------------------------------------------
nfx_now_iso()   { date -u +%Y-%m-%dT%H:%M:%SZ; }
nfx_now_epoch() { date +%s; }
nfx_now_tag()   { date -u +%Y%m%dT%H%M%SZ; }

# nfx_epoch_to_iso <epoch> -> ISO-8601 UTC
nfx_epoch_to_iso() {
  local e="$1"
  [ -z "$e" ] && { printf '%s' ""; return; }
  if nfx_is_macos; then date -u -r "$e" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null
  else date -u -d "@$e" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null; fi
}

# nfx_since_to_minutes <spec> -> minutes ago.  spec: 30m | 12h | 7d | 2w | YYYY-MM-DD
nfx_since_to_minutes() {
  local spec="$1" n unit epoch
  case "$spec" in
    *m) n="${spec%m}"; echo "$n" ;;
    *h) n="${spec%h}"; echo $((n * 60)) ;;
    *d) n="${spec%d}"; echo $((n * 1440)) ;;
    *w) n="${spec%w}"; echo $((n * 10080)) ;;
    [0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9])
      if nfx_is_macos; then epoch=$(date -j -f %Y-%m-%d "$spec" +%s 2>/dev/null)
      else epoch=$(date -d "$spec" +%s 2>/dev/null); fi
      [ -z "$epoch" ] && nfx_die "Cannot parse date: $spec"
      echo $(( ( $(nfx_now_epoch) - epoch ) / 60 ))
      ;;
    *) nfx_die "Bad time spec '$spec' (use 30m, 12h, 7d, 2w or YYYY-MM-DD)" ;;
  esac
}

# ---------------------------------------------------------------------------
# File metadata (cross-platform stat)
# ---------------------------------------------------------------------------
# nfx_stat <file> -> "mtime_epoch|atime_epoch|ctime_epoch|birth_epoch|size|uid|gid|mode_octal|inode|nlink|path"
nfx_stat() {
  if nfx_is_macos; then
    stat -f '%m|%a|%c|%B|%z|%u|%g|%Lp|%i|%l|%N' "$1" 2>/dev/null
  else
    # GNU stat: %W (birth) may be 0 or '-' on old kernels/filesystems
    stat -c '%Y|%X|%Z|%W|%s|%u|%g|%a|%i|%h|%n' "$1" 2>/dev/null
  fi
}

# nfx_stat_line <file> -> human readable one-liner with ISO times
nfx_stat_line() {
  local s; s=$(nfx_stat "$1") || return 1
  local m a c b sz u g md ino nl p
  IFS='|' read -r m a c b sz u g md ino nl p <<EOS
$s
EOS
  printf 'mtime=%s ctime=%s atime=%s size=%s uid=%s gid=%s mode=%s inode=%s %s\n' \
    "$(nfx_epoch_to_iso "$m")" "$(nfx_epoch_to_iso "$c")" "$(nfx_epoch_to_iso "$a")" \
    "$sz" "$u" "$g" "$md" "$ino" "$p"
}

# Cross-platform sha256 of a file (prints hash only)
nfx_sha256() {
  if nfx_have sha256sum; then sha256sum "$1" 2>/dev/null | awk '{print $1}'
  elif nfx_have shasum; then shasum -a 256 "$1" 2>/dev/null | awk '{print $1}'
  elif nfx_have openssl; then openssl dgst -sha256 "$1" 2>/dev/null | awk '{print $NF}'
  else echo "no-hash-tool"; fi
}
nfx_md5() {
  if nfx_have md5sum; then md5sum "$1" 2>/dev/null | awk '{print $1}'
  elif nfx_have md5; then md5 -q "$1" 2>/dev/null
  elif nfx_have openssl; then openssl dgst -md5 "$1" 2>/dev/null | awk '{print $NF}'
  else echo "no-hash-tool"; fi
}

# CSV-escape a single field
nfx_csv() {
  local v="$1"
  case "$v" in
    *[,\"$'\n']*) v=${v//\"/\"\"}; printf '"%s"' "$v" ;;
    *) printf '%s' "$v" ;;
  esac
}

# ---------------------------------------------------------------------------
# Users / homes
# ---------------------------------------------------------------------------
# nfx_user_homes -> lines "user:uid:home:shell" for every account with a real home dir
nfx_user_homes() {
  if nfx_is_macos; then
    dscl . -list /Users NFSHomeDirectory 2>/dev/null | awk '{print $1":"$2}' | while IFS=: read -r u h; do
      [ -d "$h" ] || continue
      uid=$(dscl . -read "/Users/$u" UniqueID 2>/dev/null | awk '{print $2}')
      sh=$(dscl . -read "/Users/$u" UserShell 2>/dev/null | awk '{print $2}')
      printf '%s:%s:%s:%s\n' "$u" "${uid:-?}" "$h" "${sh:-?}"
    done
  else
    { nfx_have getent && getent passwd || cat /etc/passwd; } 2>/dev/null |
      awk -F: '$6 != "" && $6 != "/" && $6 != "/nonexistent" {print $1":"$3":"$6":"$7}' |
      while IFS=: read -r u uid h sh; do [ -d "$h" ] && printf '%s:%s:%s:%s\n' "$u" "$uid" "$h" "$sh"; done
  fi
}

# ---------------------------------------------------------------------------
# Standard argument handling
# ---------------------------------------------------------------------------
# Every tool calls nfx_std_args "$@" after defining usage(). It handles
# -h/--help, -V/--version, -o/--output FILE, --no-color and leaves the rest in NFX_ARGS.
NFX_OUTPUT=""
nfx_std_args() {
  NFX_ARGS=()
  while [ $# -gt 0 ]; do
    case "$1" in
      -h|--help) usage; exit 0 ;;
      -V|--version) echo "${NFX_TOOL:-nfx} $NFX_VERSION"; exit 0 ;;
      -o|--output) [ -n "${2:-}" ] || nfx_die "-o requires a file"; NFX_OUTPUT="$2"; shift ;;
      --no-color) NFX_COLOR=0 ;;
      *) NFX_ARGS+=("$1") ;;
    esac
    shift
  done
  if [ -n "$NFX_OUTPUT" ]; then
    NFX_COLOR=0
    exec > >(tee "$NFX_OUTPUT") 2>&1
  fi
}

nfx_banner() {
  printf '%s v%s | host=%s | os=%s | user=%s | utc=%s\n' \
    "${NFX_TOOL:-nfx}" "$NFX_VERSION" "$(hostname 2>/dev/null)" "$NFX_OS" "$(id -un 2>/dev/null)" "$(nfx_now_iso)"
}

# Locate the toolkit bin dir for tools that call siblings (nfx-triage).
NFX_BIN_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../bin" 2>/dev/null && pwd)"
export NFX_BIN_DIR

# ---------------------------------------------------------------------------
# Shared detection content
# ---------------------------------------------------------------------------
# Regex of command-line / script fragments that deserve an analyst's attention.
# Deliberately broad: it produces leads, not verdicts.
NFX_SUSP_RE='(curl|wget)[^|;]*\|[[:space:]]*(ba|z|da|k)?sh|base64[[:space:]]+(-d|-D|--decode)|/dev/tcp/|/dev/udp/|\bnc(at)?[[:space:]]+-[a-zA-Z]*[el]|\bsocat\b|python[0-9.]*[[:space:]]+-c[[:space:]]|perl[[:space:]]+-e[[:space:]]|ruby[[:space:]]+-e[[:space:]]|php[[:space:]]+-r[[:space:]]|/dev/shm/|/var/tmp/|/tmp/\.|LD_PRELOAD|DYLD_INSERT_LIBRARIES|\bmkfifo\b|\bnohup\b|\bsetsid\b|xmrig|minerd|kinsing|kdevtmpfsi|stratum\+tcp|\.onion\b|bash[[:space:]]+-i|0<&[0-9]|>&[[:space:]]*/dev/(tcp|udp)/|chmod[[:space:]]+[0-7]*[+]?[xs]|chattr[[:space:]]+[-+]i|history[[:space:]]+-c|unset[[:space:]]+HIST|HISTFILE=|HISTSIZE=0|shred[[:space:]]|\bwipe\b|rm[[:space:]]+-rf[[:space:]]+/var/log|>[[:space:]]*/var/log/|useradd|adduser|usermod[[:space:]]+-aG|visudo|NOPASSWD|authorized_keys|crontab[[:space:]]+-|systemctl[[:space:]]+(enable|daemon-reload)|launchctl[[:space:]]+(load|bootstrap)|osascript|tclsh|msfvenom|meterpreter|\bmimipenguin\b|linpeas|LinEnum|pspy|\bnmap\b|masscan|\bhydra\b|sqlmap|chisel|ligolo|ngrok|\bfrpc?\b|plink|proxychains|tor2web|/etc/ld\.so\.preload|\binsmod\b|kexec|gdb[[:space:]]+-p|memfd_create|\bsu[[:space:]]+-|sudo[[:space:]]+-u|gcc[[:space:]].*-o[[:space:]]*/tmp|tar[[:space:]].*(shadow|\.ssh)|scp[[:space:]].*(shadow|\.ssh|id_rsa)|(/etc/)?shadow\b|\.bash_history|\bxxd\b|\btcpdump\b|tshark'

# nfx_grep_susp <file> [max] -> "line:text" matches of NFX_SUSP_RE, skipping comment lines
nfx_grep_susp() {
  grep -nE "$NFX_SUSP_RE" "$1" 2>/dev/null | grep -vE '^[0-9]+:[[:space:]]*#' | head -"${2:-10}"
}

# awk snippet: iso(epoch) -> "YYYY-MM-DDTHH:MM:SSZ" (UTC), portable across awk flavours.
# Usage: awk "$NFX_AWK_ISO"'{ print iso($1) }'
NFX_AWK_ISO='function iso(e,  d,s,z,era,doe,yoe,y,doy,mp,dd,m,h,mi,ss){
  if (e=="" || e+0<=0) return "";
  e=int(e); d=int(e/86400); s=e-d*86400;
  z=d+719468; era=int((z>=0?z:z-146096)/146097); doe=z-era*146097;
  yoe=int((doe-int(doe/1460)+int(doe/36524)-int(doe/146096))/365);
  y=yoe+era*400; doy=doe-(365*yoe+int(yoe/4)-int(yoe/100));
  mp=int((5*doy+2)/153); dd=doy-int((153*mp+2)/5)+1; m=(mp<10)?mp+3:mp-9;
  if (m<=2) y++;
  h=int(s/3600); mi=int((s%3600)/60); ss=s%60;
  return sprintf("%04d-%02d-%02dT%02d:%02d:%02dZ",y,m,dd,h,mi,ss) }'

# Read a (possibly rotated / gzipped) family of log files, oldest first.
# nfx_read_logs /var/log/auth.log  -> auth.log.4.gz ... auth.log.1 auth.log
nfx_read_logs() {
  local base="$1" f
  for f in $(ls -1 "$base"* 2>/dev/null | sort -r); do
    [ -r "$f" ] || continue
    case "$f" in
      *.gz)  gzip -dc "$f" 2>/dev/null ;;
      *.xz)  xz -dc "$f" 2>/dev/null ;;
      *.bz2) bzip2 -dc "$f" 2>/dev/null ;;
      *)     cat "$f" 2>/dev/null ;;
    esac
  done
}

# Portable "safe" directory listing with times: nfx_ls_l <dir>
nfx_ls_l() { ls -la"$(nfx_is_macos && echo T)" "$1" 2>/dev/null; }
