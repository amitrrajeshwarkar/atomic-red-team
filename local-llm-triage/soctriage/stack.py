"""Stage 3 - stack per-host CSVs across the fleet and surface the rare rows.

The premise your manager gave you: on a fleet of near-identical servers,
whatever is common is the build; whatever is rare is worth a look. This is
frequency analysis / least-frequency-of-occurrence, the same move as stacking
autoruns across a Windows estate.

For each artifact we pick a "stack key" - the field whose value should repeat
across hosts if the fleet is uniform. We count how many DISTINCT hosts show each
value, then flag values seen on <= --rare-threshold hosts.

  artifact        stack key (what we group identical rows by)
  ----------------------------------------------------------------
  authorized_keys fingerprint            (same key trusted on how many hosts?)
  known_hosts     fingerprint            (same destination server key seen where?)
  cron            run_as + command       (same scheduled job on how many hosts?)
  services        exec_start             (same service binary on how many hosts?)
  users           username + uid         (same local account on how many hosts?)
  listening       proto + port + process (same open port on how many hosts?)
  bodyfile        category + path        (same suid/tmp/hidden file on how many hosts?)
  shell_history   command                (same command typed on how many hosts?)

Output: stacked_<artifact>.csv (every distinct value with its host count) and
outliers.csv (only the rare ones, all artifacts together), sorted rarest-first.
"""

from collections import defaultdict
from pathlib import Path

from .common import log, read_csv, write_csv

# artifact -> (key columns, extra columns to carry into the report for context)
STACK_KEYS = {
    "authorized_keys": (["fingerprint"], ["user", "key_type", "comment", "options"]),
    "known_hosts": (["fingerprint"], ["user", "key_type", "hostnames"]),
    "cron": (["run_as", "command"], ["schedule", "source_file"]),
    "services": (["exec_start"], ["unit", "user", "description"]),
    "users": (["username", "uid"], ["gid", "home", "shell", "flags"]),
    "listening": (["proto", "port", "process"], ["local_addr"]),
    "bodyfile": (["category", "path"], ["mode", "uid", "gid", "size", "mtime"]),
    "shell_history": (["command"], ["user", "flags"]),
}

# Rows that are inherently interesting even if common - never hide these.
ALWAYS_KEEP = {
    "bodyfile": lambda r: any(c in r.get("category", "") for c in ("suid", "exec_in_tmp")),
    "users": lambda r: bool(r.get("flags")),
    "shell_history": lambda r: "suspicious_pattern" in r.get("flags", ""),
    "authorized_keys": lambda r: False,
    "known_hosts": lambda r: False,
    "cron": lambda r: False,
    "services": lambda r: False,
    "listening": lambda r: False,
}


def _iter_host_csvs(parsed_dir: Path, artifact: str):
    """Yield (host, rows) for every <host>/<artifact>.csv under parsed_dir."""
    for host_dir in sorted(p for p in parsed_dir.iterdir() if p.is_dir()):
        csv_path = host_dir / f"{artifact}.csv"
        if csv_path.is_file():
            yield host_dir.name, list(read_csv(csv_path))


def stack_artifact(parsed_dir: Path, artifact: str, total_hosts: int, rare_threshold: int):
    """Return (stacked_rows, outlier_rows) for one artifact."""
    key_cols, extra_cols = STACK_KEYS[artifact]
    hosts_by_key = defaultdict(set)          # key tuple -> set of hosts
    example_by_key = {}                      # key tuple -> a representative row
    always_hosts_by_key = defaultdict(set)   # keys that hit an ALWAYS_KEEP rule

    keep_fn = ALWAYS_KEEP.get(artifact, lambda r: False)
    for host, rows in _iter_host_csvs(parsed_dir, artifact):
        for r in rows:
            key = tuple(r.get(c, "") for c in key_cols)
            if key == tuple("" for _ in key_cols):
                continue
            hosts_by_key[key].add(host)
            example_by_key.setdefault(key, r)
            if keep_fn(r):
                always_hosts_by_key[key].add(host)

    stacked, outliers = [], []
    for key, hosts in sorted(hosts_by_key.items(), key=lambda kv: (len(kv[1]), kv[0])):
        n = len(hosts)
        ex = example_by_key[key]
        row = {"artifact": artifact, "host_count": n, "total_hosts": total_hosts,
               "hosts": ",".join(sorted(hosts))}
        for c in key_cols:
            row[c] = ex.get(c, "")
        for c in extra_cols:
            row[c] = ex.get(c, "")
        stacked.append(row)
        is_rare = n <= rare_threshold
        is_forced = key in always_hosts_by_key
        if is_rare or is_forced:
            o = dict(row)
            o["reason"] = ("always_interesting" if is_forced and not is_rare
                           else ("rare_and_interesting" if is_forced else "rare"))
            outliers.append(o)
    return stacked, outliers


def stack_all(parsed_dir: Path, outdir: Path, rare_threshold: int = 1):
    """Stack every artifact. Writes stacked_*.csv and a combined outliers.csv."""
    parsed_dir, outdir = Path(parsed_dir), Path(outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    hosts = sorted(p.name for p in parsed_dir.iterdir() if p.is_dir() and (p / "meta.json").is_file())
    total = len(hosts)
    if total == 0:
        raise RuntimeError(f"no parsed host folders under {parsed_dir} - run 'parse' first")
    log(f"stacking {total} hosts, rare = seen on <= {rare_threshold} host(s)")
    all_outliers = []
    for artifact in STACK_KEYS:
        stacked, outliers = stack_artifact(parsed_dir, artifact, total, rare_threshold)
        cols = ["artifact", "host_count", "total_hosts"] + STACK_KEYS[artifact][0] + \
               STACK_KEYS[artifact][1] + ["hosts"]
        write_csv(outdir / f"stacked_{artifact}.csv", stacked, cols)
        all_outliers.extend(outliers)
        log(f"  {artifact}: {len(stacked)} distinct, {len(outliers)} outliers")
    out_cols = ["artifact", "reason", "host_count", "total_hosts", "fingerprint", "exec_start",
                "command", "run_as", "path", "category", "username", "uid", "port", "process",
                "proto", "unit", "user", "key_type", "comment", "options", "hostnames", "schedule",
                "flags", "mode", "gid", "home", "shell", "size", "mtime", "local_addr",
                "description", "source_file", "hosts"]
    all_outliers.sort(key=lambda r: (r["host_count"], r["artifact"]))
    n = write_csv(outdir / "outliers.csv", all_outliers, out_cols)
    log(f"wrote {n} outlier rows -> {outdir/'outliers.csv'}")
    return {"total_hosts": total, "outliers": n}
