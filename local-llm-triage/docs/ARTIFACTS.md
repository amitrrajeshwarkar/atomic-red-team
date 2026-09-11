# The artifacts this tool parses, and why each one matters

Stage 1 of the task is *learning* these. This is the reference. Each section maps a
Linux forensic artifact to the Windows concept you already know, says where UAC puts
it in its output, and says what "rare across the fleet" means for it.

## How UAC lays out its output

UAC (Unix-like Artifacts Collector) is a shell script that copies forensic artifacts
off a Unix/Linux host that cannot run an EDR agent. You run it like:

```bash
./uac -p ir_triage /tmp        # collect the ir_triage profile into /tmp
```

It produces one archive named `uac-<hostname>-<os>-<timestamp>.tar.gz`. Inside:

| Path in the archive | What it holds |
|---------------------|---------------|
| `[root]/…` | **copies of collected files**, mirroring their original path. `[root]/etc/passwd` was `/etc/passwd` on the host. |
| `bodyfile/bodyfile.txt` | a full **file-system timeline** (see below) |
| `live_response/…` | output of **commands run on the live box** (`ps`, `ss`, `netstat`, `lsof`) |
| `uac.log` | UAC's own run log |

This tool reads `[root]/` and `bodyfile/` and `live_response/`. The layout above is
what the parser relies on; it was verified against the UAC artifact definitions.

---

## bodyfile — the Linux MFT/timeline

`bodyfile.txt` has one line per file on disk, pipe-separated, in the TSK "bodyfile"
format:

```
0|/etc/passwd|1234|-rw-r--r--|0|0|2043|<atime>|<mtime>|<ctime>|<crtime>
```

Fields: `MD5(unused) | path | inode | mode | uid | gid | size | atime | mtime | ctime | crtime`.
The timestamps are **epoch seconds** (seconds since 1 Jan 1970). Field 4 is the mode
string from `ls -l`: first char is the type (`-` file, `d` dir, `l` symlink), and an
`s` in the owner-execute position means **setuid** — the file runs with its owner's
privileges, usually root. That is the classic Linux privilege-escalation foothold, so
the parser tags every setuid/setgid file.

This is the closest Linux equivalent to parsing the Windows **MFT**: a complete
inventory with timestamps. We do not keep every line (there are hundreds of thousands).
We keep lines in categories worth stacking: `suid`, `sgid`, `exec_in_tmp` (executables
in `/tmp`, `/var/tmp`, `/dev/shm` — the Linux `%TEMP%`), `hidden_in_home` (unusual
dot-files under a home directory), `interesting_path` (cron, systemd, ssh, passwd…),
and `recent_mod` (changed within `--recent-days`).

## known_hosts — the outbound lateral-movement trail

`~/.ssh/known_hosts` records every server this account has **SSH'd to**. It is written
by the victim's own ssh client, so it is a trail of where that account has been —
outbound lateral movement, in your terms. Format: `hostname[,ip] key-type base64-key`.
Sometimes the hostname is hashed (`|1|salt|hash …`); the key is still there and still
stackable. We stack on the key **fingerprint** (a SHA256 of the key blob, the same
value `ssh-keygen -lf` prints). A destination that only one server in a uniform fleet
has ever connected to is exactly the "rare = suspicious" case Sajjad wants swept.

## authorized_keys — a stored credential for inbound access

`~/.ssh/authorized_keys` lists public keys that are **allowed to log in as this user**,
with no password. Adding a line here is persistence — the Windows equivalent is adding
an unknown account to the local Administrators group, except it often leaves less of a
trail. Format: `[options] key-type base64-key [comment]`. We stack on fingerprint; a
key present on one host only, or with a `comment` that does not match your naming
convention, is the finding. (ATT&CK T1098.004.)

## cron — Linux Scheduled Tasks

cron is the job scheduler. Unlike Windows Task Scheduler it is **plain-text files**, so
it diffs cleanly across a fleet:

- `/etc/crontab` and `/etc/cron.d/*` — system jobs, 7 fields: `m h dom mon dow USER command`
- `/var/spool/cron/crontabs/<user>` — per-user jobs, 6 fields (no USER column)
- `/etc/cron.{hourly,daily,weekly,monthly}/` — scripts run by a stock job

`/etc/cron.d` is where attackers drop persistence (ATT&CK T1053.003). We stack on
`run_as + command`, so a job that fetches a script from the internet and pipes it into
a shell shows up as a rare command no clean host has.

## systemd services — Linux Services (services.msc)

systemd units are the modern Linux equivalent of Windows services. One INI-style file
per service:

- `/etc/systemd/system/` — admin-created units. **Attackers write here** (T1543.002).
- `/usr/lib/systemd/system/` — package-installed units (your vendor baseline).

We record `ExecStart` (the binary the service runs) and stack on it. A service whose
`ExecStart` points into `/tmp` or a user home is a strong signal.

## /etc/passwd — the local account database

`/etc/passwd` is the local user list, in plain text. Seven colon-separated fields:
`name:x:uid:gid:gecos:home:shell`. We flag a **uid 0 that is not `root`** (a second
admin / backdoor, T1136.001), a service account that has a real login shell, and a home
directory under `/tmp`.

## shell history — a poor man's command-line audit log

`~/.bash_history` (and `.zsh_history`) records commands the user typed — the nearest
thing to Windows **4688 / Sysmon 1** without extra tooling. Caveats: usually no
timestamps, and the attacker can wipe it (T1070.003). So an **empty or missing** history
for an account that has a shell and recent logins is itself a finding, and we emit a
marker row for it. We also flag lines matching known attacker patterns (download-piped-
to-shell, `chmod +x`, `history -c`, `useradd`, reverse shells, miners).

## listening sockets — `netstat -ano` at collection time

From `live_response/network/ss*.txt` or `netstat*.txt`. We keep only `LISTEN` sockets.
A port open on one server that the other forty-nine do not have is a bind shell, a
miner, or an unapproved service.
