# nix-forensics (nfx) - live-response & DFIR toolkit for Linux and macOS

Small, single-purpose command-line tools for SOC / CSIRT investigators, in the spirit of
Eric Zimmerman's Windows tools: one artifact per tool, consistent flags, plain-text or CSV
output you can grep, diff, or drop into a timeline. Pure bash 3.2+ (the macOS default) with
no dependencies beyond what ships with the OS, so the checkout can be copied to a USB stick
or `scp`'d to a suspect host and run immediately.

Every tool is **read-only** on the host (the only writes are the output files you ask for)
and prints `[!] [TAG] ...` lines for things an analyst should look at. Flags are leads, not
verdicts; each tool ends with a recap of what it flagged.

```
nix-forensics/
├── bin/           the nfx-* tools (chmod +x, run directly or via install.sh symlinks)
├── lib/           nfx-common.sh: OS detection, cross-platform stat/date, findings, CSV, regexes
├── data/          suid-baseline.txt (expected SUID/SGID names)
├── tests/         smoke.sh - syntax + runtime test of every tool on the current host
└── install.sh     symlink the tools into /usr/local/bin (optional)
```

## Quick start

```bash
git clone <this repo> && cd atomic-red-team/nix-forensics
sudo bin/nfx-triage --case IR-2024-042           # everything, packaged as tar.gz + manifest
sudo bin/nfx-persistence --since 7d              # just one question
sudo bin/nfx-procs --csv > procs.csv             # machine-readable
sudo bin/nfx-diff baseline-dir/ suspect-dir/     # what changed vs. a known-good host
tests/smoke.sh                                   # verify the toolkit on this OS
```

Run as root for complete results (shadow, other users' homes, /proc/*/environ, TCC.db, journal).
Each tool supports `-h`, `-V`, `-o FILE` (tee output to a file) and `--no-color`.
Time windows use one syntax everywhere: `30m`, `12h`, `7d`, `2w` or `YYYY-MM-DD`.

## The tools

| Tool | What it answers | Key flags raised | ATT&CK |
|------|-----------------|------------------|--------|
| `nfx-triage` | Run everything in order of volatility, copy raw artifacts, aggregate findings, sha256 manifest, tar.gz | - | - |
| `nfx-sysinfo` | Who is this host? OS, kernel, boot time, timezone, virtualization, IPs, logged-in users | - | T1082 |
| `nfx-users` | Accounts, UID 0 clones, shells on system accounts, password state, sudoers, admin groups, hidden macOS users | `UID0` `DUP-UID` `EMPTY-PASSWORD` `SUDO-NOPASSWD` `HIDDEN-USER` `RECENT-PASSWD` | T1136.001 T1078.003 T1098 T1548.003 |
| `nfx-auth` | SSH logins/failures, brute force, sudo/su usage, account changes, wtmp/btmp, cleared auth logs | `BRUTE-FORCE` `BRUTE-THEN-SUCCESS` `ROOT-SSH` `SUDO-INTERESTING` `ACCOUNT-CHANGE` `EMPTY-LOG` | T1110 T1021.004 T1078 T1070.002 |
| `nfx-persistence` | cron/at, systemd units+timers, init/rc, shell rc files, ld.so.preload, XDG autostart, udev, PAM, apt hooks, python .pth; LaunchAgents/Daemons, login items, login hooks, periodic, emond, profiles | `SUSPICIOUS` `RECENT` `TEMP-EXEC` `LD_PRELOAD` `PAM-BACKDOOR` `UDEV-RUN` `UNSIGNED` `APPLE-MASQ` `LOGINHOOK` | T1053 T1543 T1546.004 T1547 T1574.006 T1556.003 T1037 |
| `nfx-procs` | Process inventory with deleted/anonymous binaries, temp-dir execution, kernel-thread masquerading, comm/exe mismatch, LD_PRELOAD env, ptrace, hidden PIDs, miners, unsigned macOS binaries | `DELETED-EXE` `ANON-EXE` `TEMP-EXE` `KTHREAD-NAME-WITH-EXE` `HIDDEN-PID` `LD-ENV` `MINER-NAME` `TRACED-BY-*` | T1055 T1036 T1014 T1574.006 T1496 T1059 |
| `nfx-network` | Listeners and connections with owning process, odd ports, shells holding sockets, raw sockets, promiscuous NICs, ARP, DNS, /etc/hosts, proxies, firewall, shares | `ODD-LISTEN-PORT` `SHELL-WITH-SOCKET` `PROMISC` `RAW-SOCKET` `HOSTS-ENTRY` `HOSTS-BLOCK` `NAT-REDIRECT` | T1049 T1071 T1571 T1090 T1040 T1565.001 |
| `nfx-ssh` | sshd effective config, authorized_keys per user (options, comments, fingerprints), known_hosts, client config hooks, private keys anywhere, agent sockets, global CA/keys | `SSHD-ROOT` `SSHD-KEYCMD` `AUTHKEYS-RECENT` `AUTHKEY-CMD` `SSHCFG-CMD` `PRIVKEY-RECENT` `SSH-RC` | T1098.004 T1021.004 T1552.004 T1563.001 |
| `nfx-shellhist` | Every user's bash/zsh/fish/python/mysql/... history with timestamps normalised, suspicious commands, credentials in history, tool downloads, history disabled/nulled | `SUSP-CMD` `CRED-IN-HIST` `TOOL-TRANSFER` `HIST-NULL` `HIST-EMPTY` `HIST-CONFIG` `HIST-LIVE` | T1059.004 T1070.003 T1552.003 T1105 |
| `nfx-recent` | Files modified / metadata-changed / created in a window; executables in temp dirs; hidden files in odd places; files in /dev; timestomp indicators; staged archives | `TIMESTOMP` `TIMESTOMP-NS` `TEMP-EXEC` `HIDDEN-DOTS` `DEV-FILE` `STAGED-ARCHIVE` | T1105 T1036.005 T1564.001 T1070.006 T1074.001 |
| `nfx-timeline` | MAC(B) filesystem timeline as CSV (ISO-8601 UTC) or Sleuthkit body file for mactime/Plaso | - | T1070.006 |
| `nfx-suid` | SUID/SGID inventory with hashes vs. a baseline of expected names, gtfobins, capabilities; save & compare inventories | `UNEXPECTED-SUID` `SUID-GTFOBIN` `SUID-ODD-PATH` `SUID-RECENT` `CAPABILITY` `SUID-ADDED` | T1548.001 T1068 |
| `nfx-kernel` | Modules and taint, unsigned/out-of-tree modules, modules hidden from lsmod (sysfs & kallsyms cross-check), modprobe install hooks, eBPF programs, kprobe/ftrace hooks, hardening sysctls; kexts, system extensions, SIP, Gatekeeper | `HIDDEN-MODULE` `MODULE-UNSIGNED` `MODPROBE-INSTALL` `KPROBE` `FTRACE-HOOK` `SIP-DISABLED` `THIRD-PARTY-KEXT` | T1014 T1547.006 T1562.001 |
| `nfx-mounts` | Mounts, bind mounts over /proc/PID, overmounted system dirs, network/fuse FS, loop devices, fstab drift, USB devices and history, disk images | `PROC-BIND-MOUNT` `SYSTEM-OVERMOUNT` `FSTAB-BIND` | T1014 T1052.001 T1091 T1200 |
| `nfx-packages` | Installed software, install history, third-party repos, critical binaries vs. package md5sums, `--verify` full integrity, `--orphans` unowned binaries in system paths; macOS install history, receipts, unsigned apps, brew | `CRITICAL-BIN-MODIFIED` `PKG-MODIFIED` `ORPHAN-BIN` `TOOL-INSTALL` `UNSIGNED-APP` | T1554 T1195 T1072 T1036.005 |
| `nfx-logs` | Log inventory, zero-byte/symlinked/stale logs, journald verify and time gaps, syslog gaps, forwarding, auditd summary; unified-log erasure, crash reports | `LOG-EMPTY` `LOG-SYMLINK` `LOG-STALE` `LOG-GAP` `JOURNAL-CORRUPT` `JOURNAL-VACUUM` `LOG-ERASE` | T1070.002 T1562.001 |
| `nfx-containers` | docker/podman/nerdctl/containerd/k8s inventory: privileged, host PID/net, sensitive mounts, added caps, API on TCP, suspicious in-container processes, am-I-in-a-container | `PRIVILEGED` `HOST-MOUNT` `CAP-ADD` `DOCKER-TCP` `DOCKER-SOCK-INSIDE` `K8S-PRIV` | T1610 T1611 T1613 T1496 |
| `nfx-webshell` | Score server-side scripts in web roots for eval/exec, obfuscation, request-driven execution, known shell signatures, upload-dir placement, double extensions, .htaccess handler tricks | `WEBSHELL-LIKELY` `KNOWN-SHELL` `SCRIPT-IN-UPLOADS` `HANDLER-TRICK` `WEBUSER-WROTE-SCRIPT` | T1505.003 T1027 |
| `nfx-hash` | sha256/md5/sha1 of files or of every running process binary, CSV; `--check` against a known-bad list | `IOC-HASH-MATCH` | any |
| `nfx-ioc` | Sweep IPs, domains, URLs, hashes, file names, strings across connections, hosts/DNS, history, persistence configs, logs/journal, file contents, process cmdlines and hashes | `IOC-*` | any |
| `nfx-mac-artifacts` | macOS: quarantine DB (downloads + source URLs), quarantine xattrs, TCC grants, Gatekeeper/SIP/XProtect, BTM login items, profiles/MDM, Wi-Fi networks, recent items, Dock, Spotlight exclusions, install.log, browser history/downloads | `GATEKEEPER-OFF` `TCC-SENSITIVE-GRANT` `DOWNLOADED-INSTALLER` `NO-QUARANTINE` `DOCK-ODD-APP` | T1553.001 T1548.006 T1204.002 T1105 T1547.015 |
| `nfx-diff` | Diff two outputs or two triage directories; surfaces new `[!]` findings | `NEW-FINDING` | - |

## Typical workflows

**Live triage of a suspect host** (order of volatility is built in):

```bash
sudo bin/nfx-triage -d /mnt/usb/case-42-host01 --case 42 --since 14d
# -> case-42-host01/{sysinfo,procs,network,...}.txt, *.csv, raw/ copies, findings.txt,
#    manifest.csv (sha256 of every file), triage.log, and a .tar.gz with its own sha256
```

`--quick` skips the slower collectors (timeline, webshell, process hashing); `--full` adds a
whole-disk body file, hashes of every system binary, package verification and orphan detection.

**Hunt a specific TTP** across a fleet: each tool is independent, so the directory can be
pushed with scp/Ansible/Jamf and one tool run per host:

```bash
for h in $(cat hosts); do
  scp -rq nix-forensics "$h:/tmp/nfx" && ssh "$h" 'sudo /tmp/nfx/bin/nfx-persistence --no-color --since 7d' > "out/$h.txt"
done
grep -h '^\[!\]' out/*.txt | sort | uniq -c | sort -rn | head      # fleet-wide view of flags
```

**Baseline and compare** a gold image against production:

```bash
sudo bin/nfx-suid --save gold-suid.txt                  # on the gold image
sudo bin/nfx-suid --compare gold-suid.txt               # on the suspect
sudo bin/nfx-triage -d gold/ --quick --no-tar ; sudo bin/nfx-triage -d prod/ --quick --no-tar
bin/nfx-diff --flags-only gold/ prod/
```

**IOC sweep** from a threat-intel report:

```bash
cat > iocs.txt <<X
185.220.101.5
update-cdn.example.net
5d41402abc4b2a76b9719d911017c592
kdevtmpfsi
/tmp/.x/
X
sudo bin/nfx-ioc -i iocs.txt --csv > ioc-hits.csv
```

**Timeline** around a pivot time, feed to mactime/Plaso if needed:

```bash
sudo bin/nfx-timeline --since 2024-05-01 /etc /home /tmp /var/tmp /opt > tl.csv
sudo bin/nfx-timeline --bodyfile / > host.body && mactime -b host.body -d > host-mactime.csv
```

## Design notes

* **One artifact, one tool.** Each script is under ~300 lines and can be read in a few minutes,
  which matters when you have to explain in court what the tool did.
* **Portable by construction.** bash 3.2 syntax only; GNU vs. BSD differences (`stat`, `date`,
  `find`, `ps`, `ls`) are wrapped in `lib/nfx-common.sh`. Epoch to ISO conversion is done in
  awk so timelines are fast without gawk.
* **Consistent output.** `====` headers, `---` sections, `[*]` info, `[-]` warnings on stderr,
  `[!] [TAG] message` findings, and a recap at the end. CSV modes use RFC 4180 quoting.
* **Findings survive pipelines.** Flags are appended to a temp file so counts are right even
  when raised inside `while read` subshells; the file is removed on exit.
* **No host modification.** Nothing is installed, no packages are touched, atime is only
  affected by reads (mount `noatime` or image first when that matters).

## Caveats

* Reading `/proc/*/environ`, `/etc/shadow`, other users' homes, `TCC.db`, the journal and
  `sfltool dumpbtm` needs root; macOS additionally needs **Full Disk Access** for the terminal
  running the tools to read TCC, Safari and Mail data.
* Rootkit checks (`HIDDEN-PID`, `HIDDEN-MODULE`, bind mounts) are heuristics that a kernel-level
  rootkit can defeat; treat a clean result as "nothing found", not "nothing there".
* `nfx-webshell` and the suspicious-command regex trade precision for recall. Tune
  `NFX_SUSP_RE` in `lib/nfx-common.sh` and `data/suid-baseline.txt` to your environment.
* Tested on Ubuntu 22.04/24.04 (bash 5) and written against the bash 3.2 / BSD userland on
  macOS; `tests/smoke.sh` runs every tool on the current host and should be run on each
  platform you deploy to.
