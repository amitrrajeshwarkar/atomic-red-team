"""Small helpers shared by every stage. Nothing clever lives here."""

import csv
import hashlib
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path


def log(msg: str) -> None:
    """Print progress to stderr so stdout stays clean for data."""
    print(f"[soctriage] {msg}", file=sys.stderr)


def epoch_to_iso(value) -> str:
    """Bodyfile timestamps are seconds since 1970 (epoch). Make them readable."""
    try:
        return datetime.fromtimestamp(int(value), tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    except (ValueError, TypeError, OSError, OverflowError):
        return ""


def sha256_fingerprint(b64_key: str) -> str:
    """OpenSSH-style fingerprint of a public key: SHA256 over the decoded key blob.

    Two hosts with the same fingerprint trust the same key. That is the value
    you stack on - the key itself is long and noisy, the fingerprint is stable.
    """
    import base64

    try:
        blob = base64.b64decode(b64_key, validate=True)
    except Exception:
        # Malformed key material still has to stay DISTINCT, or two different
        # bad keys would stack together and hide a rogue one. Hash the raw text.
        digest = hashlib.sha256(b64_key.encode("utf-8", "replace")).digest()
        return "SHA256-raw:" + base64.b64encode(digest).decode().rstrip("=")
    digest = hashlib.sha256(blob).digest()
    return "SHA256:" + base64.b64encode(digest).decode().rstrip("=")


def write_csv(path: Path, rows, fieldnames) -> int:
    """Write a list of dicts to CSV. Returns row count. Always writes a header."""
    path.parent.mkdir(parents=True, exist_ok=True)
    n = 0
    with path.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=fieldnames, extrasaction="ignore")
        w.writeheader()
        for r in rows:
            w.writerow(r)
            n += 1
    return n


def read_csv(path: Path):
    with path.open(newline="", encoding="utf-8") as fh:
        yield from csv.DictReader(fh)


def read_text(path: Path) -> str:
    """Read a collected file leniently - forensic copies may contain junk bytes."""
    return path.read_text(encoding="utf-8", errors="replace")


HOSTNAME_FROM_DIR = re.compile(r"^uac-(?P<host>.+?)-(?P<os>[a-z]+)-(?P<ts>\d{8,14})$")


def hostname_from_collection(root: Path) -> str:
    """UAC names its output uac-<hostname>-<os>-<timestamp>. Fall back to /etc/hostname."""
    m = HOSTNAME_FROM_DIR.match(root.name)
    if m:
        return m.group("host")
    etc_hostname = root / "[root]" / "etc" / "hostname"
    if etc_hostname.is_file():
        return read_text(etc_hostname).strip() or root.name
    return root.name


def dump_json(obj, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2), encoding="utf-8")


def env_default(name: str, default: str) -> str:
    return os.environ.get(name, default)
