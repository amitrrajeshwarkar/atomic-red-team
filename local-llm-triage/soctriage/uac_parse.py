"""Stage 2 - parse one UAC collection into flat per-artifact CSV files.

Input : a UAC output archive (uac-<host>-linux-<ts>.tar.gz) or the extracted folder.
Output: <outdir>/<hostname>/<artifact>.csv, one CSV per artifact, plus meta.json.

UAC layout we rely on (verified against tclahr/uac artifact definitions):
  [root]/...                 copies of collected files, mirroring the original path
                             e.g. [root]/home/amit/.ssh/known_hosts
  bodyfile/bodyfile.txt      TSK "bodyfile" - one line per file on disk:
                             0|path|inode|mode_string|uid|gid|size|atime|mtime|ctime|crtime
  live_response/...          output of commands run on the live box (ps, netstat, ...)
  uac.log                    UAC's own log

SOC bridge for each artifact is in the docstring of its parser.
"""

import re
import shlex
import tarfile
import tempfile
from pathlib import Path

from .common import (
    epoch_to_iso,
    hostname_from_collection,
    log,
    read_text,
    sha256_fingerprint,
    write_csv,
    dump_json,
)

# ----------------------------------------------------------------------------
# Opening the collection
# ----------------------------------------------------------------------------


def open_collection(src: Path, work: Path) -> Path:
    """Return a directory that contains [root]/ and bodyfile/. Extract if needed.

    A .tar.gz is a "zipped folder" - tar bundles files into one, gzip compresses.
    Python's tarfile handles both in one step so you never need the tar command.
    """
    src = Path(src)
    if src.is_dir():
        return _find_collection_root(src)
    if not src.is_file():
        raise FileNotFoundError(src)
    dest = work / src.name.replace(".tar.gz", "").replace(".tgz", "").replace(".tar", "")
    if not dest.exists():
        log(f"extracting {src.name} -> {dest}")
        dest.mkdir(parents=True, exist_ok=True)
        with tarfile.open(src) as tf:
            _safe_extract(tf, dest)
    return _find_collection_root(dest)


def _safe_extract(tf: tarfile.TarFile, dest: Path) -> None:
    """Refuse members that would escape dest (a classic tar path-traversal trick)."""
    dest_resolved = dest.resolve()
    for m in tf.getmembers():
        target = (dest / m.name).resolve()
        if dest_resolved not in target.parents and target != dest_resolved:
            raise RuntimeError(f"unsafe path in archive: {m.name}")
    tf.extractall(dest)


def _find_collection_root(d: Path) -> Path:
    """UAC archives usually contain a single top folder. Find the one with [root]/."""
    if (d / "[root]").is_dir() or (d / "bodyfile").is_dir():
        return d
    for child in sorted(d.iterdir()):
        if child.is_dir() and ((child / "[root]").is_dir() or (child / "bodyfile").is_dir()):
            return child
    raise RuntimeError(f"no [root]/ or bodyfile/ under {d} - is this a UAC collection?")


# ----------------------------------------------------------------------------
# Artifact parsers. Each yields dicts; keys become CSV columns.
# ----------------------------------------------------------------------------

BODYFILE_FIELDS = [
    "host", "path", "inode", "mode", "uid", "gid", "size",
    "atime", "mtime", "ctime", "crtime", "category",
]

# Where attackers drop things on Linux. Think: %TEMP%, ProgramData, Run keys.
INTERESTING_PREFIXES = (
    "/tmp/", "/var/tmp/", "/dev/shm/",              # world-writable scratch (Windows: %TEMP%)
    "/etc/cron", "/var/spool/cron",                 # scheduled tasks
    "/etc/systemd/system/", "/usr/lib/systemd/system/", "/lib/systemd/system/",  # services
    "/etc/init.d/", "/etc/rc.local", "/etc/rc.d/",  # legacy autostart
    "/etc/ld.so.preload",                           # DLL-injection equivalent
    "/etc/profile.d/", "/etc/bash.bashrc", "/etc/profile",  # logon scripts
    "/root/.ssh/", "/etc/ssh/",                     # SSH trust
    "/etc/passwd", "/etc/shadow", "/etc/sudoers", "/etc/group",  # accounts
    "/usr/local/bin/", "/usr/local/sbin/",          # unmanaged binaries
    "/opt/",
)


def parse_bodyfile(root: Path, host: str, recent_days: int, collected_at: int):
    """The bodyfile is the Linux equivalent of an MFT parse (a full file timeline).

    One line per file, pipe-separated:
        0|/etc/passwd|1234|-rw-r--r--|0|0|2043|atime|mtime|ctime|crtime
    Column 4 is the mode string you know from `ls -l`. First char: '-' file,
    'd' directory, 'l' symlink. An 's' in the owner-execute slot = setuid
    (runs as the file owner, usually root - the classic privilege-escalation
    foothold).

    We do NOT keep every line (hundreds of thousands). We keep lines that fall
    into a category worth stacking:
      suid / sgid            - setuid/setgid executables anywhere
      exec_in_tmp            - executable files in /tmp, /var/tmp, /dev/shm
      hidden_in_home         - dot-files/dirs under /home or /root that are not the usual ones
      interesting_path       - anything under INTERESTING_PREFIXES
      recent_mod             - mtime/ctime within `recent_days` of collection
    """
    bf = root / "bodyfile" / "bodyfile.txt"
    if not bf.is_file():
        log(f"{host}: no bodyfile/bodyfile.txt - skipping bodyfile")
        return
    cutoff = collected_at - recent_days * 86400 if collected_at else None
    usual_dotfiles = {
        ".bashrc", ".bash_profile", ".profile", ".bash_logout", ".bash_history", ".ssh",
        ".cache", ".config", ".local", ".viminfo", ".lesshst", ".sudo_as_admin_successful",
        ".gnupg", ".vim", ".zshrc", ".zsh_history", ".gitconfig", ".python_history",
    }
    with bf.open(encoding="utf-8", errors="replace") as fh:
        for line in fh:
            parts = line.rstrip("\n").split("|")
            if len(parts) < 11:
                continue
            _, path, inode, mode, uid, gid, size, atime, mtime, ctime, crtime = parts[:11]
            cats = []
            is_file = mode.startswith("-")
            if is_file and len(mode) >= 10:
                if mode[3] in "sS":
                    cats.append("suid")
                if mode[6] in "sS":
                    cats.append("sgid")
                if path.startswith(("/tmp/", "/var/tmp/", "/dev/shm/")) and "x" in mode[1:10]:
                    cats.append("exec_in_tmp")
            if path.startswith(("/home/", "/root/")):
                segs = path.split("/")
                # /home/<user>/.<name> or /root/.<name>
                idx = 3 if path.startswith("/home/") else 2
                if len(segs) > idx and segs[idx].startswith(".") and segs[idx] not in usual_dotfiles:
                    cats.append("hidden_in_home")
            if path.startswith(INTERESTING_PREFIXES):
                cats.append("interesting_path")
            if cutoff is not None:
                try:
                    if max(int(mtime), int(ctime)) >= cutoff and not path.startswith(("/proc/", "/sys/", "/run/", "/var/log/", "/var/cache/")):
                        cats.append("recent_mod")
                except ValueError:
                    pass
            if not cats:
                continue
            yield {
                "host": host, "path": path, "inode": inode, "mode": mode, "uid": uid, "gid": gid,
                "size": size, "atime": epoch_to_iso(atime), "mtime": epoch_to_iso(mtime),
                "ctime": epoch_to_iso(ctime), "crtime": epoch_to_iso(crtime),
                "category": "+".join(cats),
            }


KNOWN_HOSTS_FIELDS = ["host", "user", "source_file", "hostnames", "hashed", "key_type", "fingerprint"]


def parse_known_hosts(root: Path, host: str):
    """~/.ssh/known_hosts = every server this account has SSH'd *to*.

    It is a lateral-movement trail written by the victim's own ssh client.
    Line format:  hostname[,ip] key-type base64-key [comment]
    Hashed form:  |1|salt|hash key-type base64-key   (hostname hidden, key still stackable)

    Stack on `fingerprint`: a destination that only one server in the fleet has
    ever connected to is exactly the "rare = suspicious" case.
    """
    for f in _glob_root(root, "**/.ssh/known_hosts*"):
        user = _user_from_path(f)
        for raw in read_text(f).splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("@"):  # @cert-authority / @revoked marker
                line = line.split(None, 1)[1] if " " in line else line
            parts = line.split()
            if len(parts) < 3:
                continue
            hostnames, key_type, key = parts[0], parts[1], parts[2]
            yield {
                "host": host, "user": user, "source_file": _orig_path(root, f),
                "hostnames": hostnames, "hashed": str(hostnames.startswith("|1|")).lower(),
                "key_type": key_type, "fingerprint": sha256_fingerprint(key),
            }


AUTH_KEYS_FIELDS = ["host", "user", "source_file", "options", "key_type", "fingerprint", "comment"]

KEY_TYPES = ("ssh-rsa", "ssh-ed25519", "ssh-dss", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384",
             "ecdsa-sha2-nistp521", "sk-ssh-ed25519@openssh.com", "sk-ecdsa-sha2-nistp256@openssh.com")


def parse_authorized_keys(root: Path, host: str):
    """~/.ssh/authorized_keys = a stored credential that lets a key holder log in as this user.

    Windows bridge: an extra line here is like an unknown account added to a local
    Administrators group - persistence with no password and often no logging.
    Line format:  [options] key-type base64-key [comment]
    Stack on `fingerprint`; a key present on one host only, or a `comment` that
    doesn't match your naming convention, is the finding.
    """
    for f in _glob_root(root, "**/.ssh/authorized_keys*"):
        user = _user_from_path(f)
        for raw in read_text(f).splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            opts = ""
            # options come first and contain no key type; find where the key type starts
            for i, tok in enumerate(parts):
                if tok in KEY_TYPES and i + 1 < len(parts):
                    opts = " ".join(parts[:i])
                    key_type, key = tok, parts[i + 1]
                    comment = " ".join(parts[i + 2:])
                    break
            else:
                continue
            yield {
                "host": host, "user": user, "source_file": _orig_path(root, f), "options": opts,
                "key_type": key_type, "fingerprint": sha256_fingerprint(key), "comment": comment,
            }


CRON_FIELDS = ["host", "source_file", "run_as", "schedule", "command", "raw"]

CRON_PATHS = ("etc/crontab", "etc/cron.d", "etc/cron.hourly", "etc/cron.daily", "etc/cron.weekly",
              "etc/cron.monthly", "var/spool/cron", "etc/anacrontab")


def parse_cron(root: Path, host: str):
    """cron = Windows Scheduled Tasks. Files, not a database, so they diff cleanly.

    /etc/crontab and /etc/cron.d/*   system jobs, 7 fields: m h dom mon dow USER command
    /var/spool/cron/crontabs/<user>  per-user jobs, 6 fields: m h dom mon dow command
    /etc/cron.{hourly,daily,...}/    scripts run by a stock job - we record the file, not lines
    """
    base = root / "[root]"
    for rel in CRON_PATHS:
        p = base / rel
        if p.is_file():
            yield from _cron_lines(root, host, p, system=(rel in ("etc/crontab", "etc/anacrontab")))
        elif p.is_dir():
            for f in sorted(p.rglob("*")):
                if not f.is_file():
                    continue
                if rel.startswith("etc/cron.") and rel != "etc/cron.d":
                    # scripts in cron.daily etc - record presence + first non-comment line
                    first = next((l for l in read_text(f).splitlines() if l.strip() and not l.startswith("#")), "")
                    yield {"host": host, "source_file": _orig_path(root, f), "run_as": "root",
                           "schedule": rel.split(".")[-1], "command": first.strip(), "raw": first.strip()}
                else:
                    system = rel == "etc/cron.d"
                    yield from _cron_lines(root, host, f, system=system)


def _cron_lines(root, host, f, system):
    user_from_spool = "" if system else f.name
    for raw in read_text(f).splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" in line.split()[0]:
            continue  # blank, comment, or VAR=value
        parts = line.split(None, 6 if system else 5)
        if line.startswith("@"):  # @reboot, @daily shorthand
            parts = line.split(None, 2 if system else 1)
            sched = parts[0]
            if system and len(parts) >= 3:
                run_as, cmd = parts[1], parts[2]
            elif not system and len(parts) >= 2:
                run_as, cmd = user_from_spool, parts[1]
            else:
                continue
        elif system and len(parts) == 7:
            sched, run_as, cmd = " ".join(parts[:5]), parts[5], parts[6]
        elif not system and len(parts) == 6:
            sched, run_as, cmd = " ".join(parts[:5]), user_from_spool, parts[5]
        else:
            continue
        yield {"host": host, "source_file": _orig_path(root, f), "run_as": run_as,
               "schedule": sched, "command": cmd, "raw": line}


USERS_FIELDS = ["host", "username", "uid", "gid", "home", "shell", "flags"]


def parse_passwd(root: Path, host: str):
    """/etc/passwd = the local SAM, in plain text. Seven colon-separated fields.

    Flags we raise: uid 0 that is not 'root' (a second admin), a login shell on a
    service account, a home under /tmp or /dev/shm.
    """
    f = root / "[root]" / "etc" / "passwd"
    if not f.is_file():
        return
    nologin = ("/usr/sbin/nologin", "/sbin/nologin", "/bin/false", "/usr/bin/false")
    for line in read_text(f).splitlines():
        parts = line.split(":")
        if len(parts) < 7 or line.startswith("#"):
            continue
        name, _, uid, gid, _, home, shell = parts[:7]
        flags = []
        if uid == "0" and name != "root":
            flags.append("uid0_not_root")
        if shell not in nologin and shell and uid.isdigit() and 1 <= int(uid) < 1000 and name not in ("sync", "root"):
            flags.append("service_account_with_shell")
        if home.startswith(("/tmp", "/dev/shm", "/var/tmp")):
            flags.append("home_in_tmp")
        yield {"host": host, "username": name, "uid": uid, "gid": gid, "home": home,
               "shell": shell, "flags": "+".join(flags)}


SERVICES_FIELDS = ["host", "unit", "source_file", "exec_start", "user", "description"]


def parse_systemd(root: Path, host: str):
    """systemd units = Windows Services (services.msc). One INI-style file per service.

    /etc/systemd/system/      admin-created units  <- attackers write here (T1543.002)
    /usr/lib/systemd/system/  package-installed units (vendor baseline)
    We record ExecStart (the binary that runs). Stack on exec_start.
    """
    base = root / "[root]"
    for rel in ("etc/systemd/system", "usr/lib/systemd/system", "lib/systemd/system",
                "run/systemd/system", "root/.config/systemd/user", "home"):
        p = base / rel
        if not p.is_dir():
            continue
        for f in sorted(p.rglob("*.service")):
            if not f.is_file() or f.is_symlink():
                continue
            if rel == "home" and "/.config/systemd/" not in f.as_posix():
                continue
            exec_start = user = desc = ""
            for line in read_text(f).splitlines():
                if line.startswith("ExecStart=") and not exec_start:
                    exec_start = line.split("=", 1)[1].strip()
                elif line.startswith("User="):
                    user = line.split("=", 1)[1].strip()
                elif line.startswith("Description="):
                    desc = line.split("=", 1)[1].strip()
            yield {"host": host, "unit": f.name, "source_file": _orig_path(root, f),
                   "exec_start": exec_start, "user": user or "root", "description": desc}


HISTORY_FIELDS = ["host", "user", "source_file", "line_no", "command", "flags"]

SUSPICIOUS_HISTORY = re.compile(
    r"(curl|wget)\s.*\|\s*(ba)?sh|chmod\s+\+x|base64\s+-d|nc\s+-|ncat|socat|/dev/tcp/|"
    r"authorized_keys|useradd|usermod|passwd\s|visudo|crontab\s+-|systemctl\s+(enable|start)|"
    r"history\s+-c|unset\s+HISTFILE|>\s*~/.bash_history|chattr|setenforce\s+0|iptables\s+-F|"
    r"ld\.so\.preload|nohup|python[23]?\s+-c|perl\s+-e|mkfifo|xmrig|minerd",
    re.IGNORECASE,
)


def parse_shell_history(root: Path, host: str):
    """~/.bash_history = a poor man's command-line audit log (Windows: 4688 / Sysmon 1).

    No timestamps unless HISTTIMEFORMAT was set, and the attacker can wipe it
    (T1070.003). An EMPTY or MISSING history for an account that has a shell and
    recent logins is itself a finding - we emit a marker row for that.
    """
    home_dirs = list((root / "[root]" / "home").glob("*")) if (root / "[root]" / "home").is_dir() else []
    if (root / "[root]" / "root").is_dir():
        home_dirs.append(root / "[root]" / "root")
    for home in home_dirs:
        if not home.is_dir():
            continue
        user = home.name
        found = False
        for hist in ("bash_history", "zsh_history", "sh_history", "ash_history", "python_history"):
            f = home / f".{hist}"
            if not f.is_file():
                continue
            found = True
            text = read_text(f)
            if not text.strip():
                yield {"host": host, "user": user, "source_file": _orig_path(root, f), "line_no": 0,
                       "command": "", "flags": "empty_history"}
                continue
            for i, line in enumerate(text.splitlines(), 1):
                cmd = line.strip()
                if not cmd or cmd.startswith(": ") and ";" in cmd:  # zsh extended format ": ts:0;cmd"
                    cmd = cmd.split(";", 1)[1] if ";" in cmd else cmd
                flags = "suspicious_pattern" if SUSPICIOUS_HISTORY.search(cmd) else ""
                yield {"host": host, "user": user, "source_file": _orig_path(root, f), "line_no": i,
                       "command": cmd, "flags": flags}
        if not found and user != "lost+found":
            yield {"host": host, "user": user, "source_file": _orig_path(root, home) + "/.bash_history",
                   "line_no": 0, "command": "", "flags": "missing_history"}


LISTEN_FIELDS = ["host", "proto", "local_addr", "port", "process", "raw"]


def parse_listening(root: Path, host: str):
    """live_response/network/ss*.txt or netstat*.txt = `netstat -ano` at collection time.

    We only keep LISTEN sockets - a port open on one server that the other 49
    do not have is a bind shell, a miner, or an unapproved service.
    """
    lr = root / "live_response" / "network"
    if not lr.is_dir():
        return
    for f in sorted(lr.glob("*")):
        if not f.is_file() or not (f.name.startswith("ss") or f.name.startswith("netstat")):
            continue
        for line in read_text(f).splitlines():
            if "LISTEN" not in line:
                continue
            parts = line.split()
            if len(parts) < 4:
                continue
            proto = parts[0]
            # ss: Netid State Recv-Q Send-Q Local:Port Peer:Port Process
            # netstat: Proto Recv-Q Send-Q Local Foreign State PID/Program
            local = parts[4] if f.name.startswith("ss") and len(parts) > 4 else parts[3]
            port = local.rsplit(":", 1)[-1] if ":" in local else ""
            proc = " ".join(parts[6:]) if f.name.startswith("ss") else (parts[6] if len(parts) > 6 else "")
            yield {"host": host, "proto": proto, "local_addr": local, "port": port, "process": proc, "raw": line.strip()}


# ----------------------------------------------------------------------------
# helpers
# ----------------------------------------------------------------------------


def _glob_root(root: Path, pattern: str):
    base = root / "[root]"
    if not base.is_dir():
        return []
    return sorted(p for p in base.glob(pattern) if p.is_file())


def _orig_path(root: Path, f: Path) -> str:
    """Turn <collection>/[root]/home/x/.ssh/known_hosts back into /home/x/.ssh/known_hosts."""
    try:
        return "/" + f.relative_to(root / "[root]").as_posix()
    except ValueError:
        return f.as_posix()


def _user_from_path(f: Path) -> str:
    s = f.as_posix()
    m = re.search(r"/\[root\]/home/([^/]+)/", s)
    if m:
        return m.group(1)
    if "/[root]/root/" in s:
        return "root"
    return "unknown"


def _collection_epoch(root: Path) -> int:
    """Best effort: timestamp in the folder name, else newest mtime in bodyfile dir."""
    m = re.search(r"-(\d{14})$", root.name)
    if m:
        from datetime import datetime, timezone
        try:
            return int(datetime.strptime(m.group(1), "%Y%m%d%H%M%S").replace(tzinfo=timezone.utc).timestamp())
        except ValueError:
            pass
    bf = root / "bodyfile" / "bodyfile.txt"
    return int(bf.stat().st_mtime) if bf.is_file() else 0


ARTIFACTS = {
    # name: (parser, fieldnames)
    "bodyfile": (None, BODYFILE_FIELDS),  # special-cased (needs recent_days)
    "known_hosts": (parse_known_hosts, KNOWN_HOSTS_FIELDS),
    "authorized_keys": (parse_authorized_keys, AUTH_KEYS_FIELDS),
    "cron": (parse_cron, CRON_FIELDS),
    "users": (parse_passwd, USERS_FIELDS),
    "services": (parse_systemd, SERVICES_FIELDS),
    "shell_history": (parse_shell_history, HISTORY_FIELDS),
    "listening": (parse_listening, LISTEN_FIELDS),
}


def parse_collection(src: Path, outdir: Path, work: Path, recent_days: int = 30, only=None) -> dict:
    """Parse one collection. Returns {artifact: row_count}."""
    root = open_collection(Path(src), work)
    host = hostname_from_collection(root)
    collected_at = _collection_epoch(root)
    dest = Path(outdir) / host
    counts = {}
    for name, (fn, fields) in ARTIFACTS.items():
        if only and name not in only:
            continue
        if name == "bodyfile":
            rows = parse_bodyfile(root, host, recent_days, collected_at)
        else:
            rows = fn(root, host)
        counts[name] = write_csv(dest / f"{name}.csv", rows, fields)
    dump_json({"host": host, "source": str(src), "collection_root": str(root),
               "collected_at_epoch": collected_at, "rows": counts}, dest / "meta.json")
    log(f"{host}: " + ", ".join(f"{k}={v}" for k, v in counts.items()))
    return counts


def parse_many(sources, outdir: Path, recent_days: int = 30, only=None) -> dict:
    """Parse a list of archives/folders. Also accepts a directory full of archives."""
    work = Path(tempfile.mkdtemp(prefix="soctriage-extract-"))
    expanded = []
    for s in sources:
        s = Path(s)
        if s.is_dir() and not ((s / "[root]").is_dir() or (s / "bodyfile").is_dir()):
            kids = sorted(s.glob("uac-*"))
            expanded.extend(kids if kids else [s])
        else:
            expanded.append(s)
    results = {}
    for s in expanded:
        try:
            results[str(s)] = parse_collection(s, outdir, work, recent_days, only)
        except Exception as e:  # keep going - one bad archive shouldn't kill the sweep
            log(f"FAILED {s}: {e}")
            results[str(s)] = {"error": str(e)}
    return results
