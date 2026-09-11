"""Stage 5 - review Windows event logs exported to Excel from the SIEM, locally.

This is the separate deliverable: analysts pull a slice of Windows events out of
Splunk or Sentinel into an .xlsx, and a LOCAL model reviews each row so no
subscriber data touches a cloud API.

We do not assume a fixed column layout - Splunk and Sentinel export different
headers. We detect the useful columns by name (case/space-insensitive) and build
a compact one-line summary per event for the model. Rows the model or heuristic
flags are written to a new sheet, sorted worst-first, with a verdict column your
analysts can filter in Excel.

openpyxl is the one third-party dependency. Install in the Ubuntu terminal with:
    pip install openpyxl
"""

import re
from pathlib import Path

from .common import log

# canonical field -> list of header spellings we accept (lowercased, spaces/underscores stripped)
COLUMN_ALIASES = {
    "time": ["time", "timestamp", "_time", "timegenerated", "timecreated", "eventtime", "date"],
    "event_id": ["eventid", "eventcode", "id", "event"],
    "computer": ["computer", "host", "hostname", "computername", "device", "src_host", "machine"],
    "account": ["account", "user", "username", "accountname", "targetusername", "subjectusername", "src_user"],
    "source_ip": ["sourceip", "srcip", "ipaddress", "clientip", "src", "sourceaddress", "src_ip"],
    "process": ["process", "processname", "newprocessname", "image", "processpath", "commandline", "cmdline"],
    "message": ["message", "eventdata", "description", "details", "raw", "_raw", "renderedmessage"],
    "logon_type": ["logontype", "logon_type"],
}

# Event IDs that carry weight in triage. Bridges to what Amit already knows.
NOTABLE_EVENTS = {
    "4624": "successful logon", "4625": "failed logon", "4634": "logoff",
    "4648": "explicit-credential logon (runas / lateral)", "4672": "special privileges assigned (admin logon)",
    "4688": "process creation", "4720": "user account created", "4722": "account enabled",
    "4724": "password reset attempt", "4728": "member added to security-enabled global group",
    "4732": "member added to security-enabled local group", "4738": "user account changed",
    "4740": "account locked out", "4768": "Kerberos TGT requested", "4769": "Kerberos service ticket",
    "4776": "NTLM credential validation", "5140": "network share accessed", "7045": "service installed",
    "1102": "audit log cleared", "104": "event log cleared", "4698": "scheduled task created",
    "4697": "service installed", "1": "Sysmon process create", "3": "Sysmon network connect",
    "11": "Sysmon file create", "13": "Sysmon registry set",
}


def _norm(h):
    return re.sub(r"[^a-z0-9]", "", str(h).lower())


def _map_columns(header_row):
    """Return {canonical: column_index} using alias matching. Unmatched fields absent."""
    norm_to_idx = {_norm(h): i for i, h in enumerate(header_row) if h is not None}
    mapping = {}
    for canon, aliases in COLUMN_ALIASES.items():
        for a in aliases:
            if a in norm_to_idx:
                mapping[canon] = norm_to_idx[a]
                break
    return mapping


def load_events(xlsx_path: Path, sheet=None, max_rows=None):
    """Read events from an .xlsx. Returns (headers, list_of_row_dicts, colmap)."""
    from openpyxl import load_workbook

    wb = load_workbook(filename=str(xlsx_path), read_only=True, data_only=True)
    ws = wb[sheet] if sheet else wb.active
    rows = ws.iter_rows(values_only=True)
    header = next(rows, None)
    if header is None:
        raise RuntimeError("empty spreadsheet - no header row")
    colmap = _map_columns(header)
    if "event_id" not in colmap and "message" not in colmap:
        log("WARNING: could not find an Event ID or Message column - check your export headers")
    events = []
    for i, r in enumerate(rows):
        if max_rows and i >= max_rows:
            break
        events.append({canon: (r[idx] if idx < len(r) else None) for canon, idx in colmap.items()})
    wb.close()
    return list(header), events, colmap


def summarize_event(ev: dict) -> str:
    """One compact line for the model - Event ID meaning first, then the who/where."""
    eid = str(ev.get("event_id", "") or "").strip()
    meaning = NOTABLE_EVENTS.get(eid, "")
    bits = []
    if eid:
        bits.append(f"EventID {eid}" + (f" ({meaning})" if meaning else ""))
    for f, label in (("time", "time"), ("computer", "host"), ("account", "account"),
                     ("source_ip", "src_ip"), ("logon_type", "logon_type"), ("process", "process")):
        v = ev.get(f)
        if v not in (None, ""):
            bits.append(f"{label}={str(v).strip()[:120]}")
    msg = ev.get("message")
    if msg not in (None, ""):
        bits.append("msg=" + re.sub(r"\s+", " ", str(msg)).strip()[:300])
    return "; ".join(bits) if bits else "(empty event row)"


def prefilter_notable(events):
    """Optional narrowing: keep only rows whose Event ID is in NOTABLE_EVENTS.

    Useful when the export has 50k rows and the model is slow. Returns indices kept.
    """
    keep = []
    for i, ev in enumerate(events):
        eid = str(ev.get("event_id", "") or "").strip()
        if eid in NOTABLE_EVENTS or not eid:
            keep.append(i)
    return keep


def write_reviewed_xlsx(src_headers, events, verdicts, out_path: Path):
    """Write a workbook: 'Triage' sheet (flagged, worst-first) + 'All Events' with verdicts.

    verdicts is a list aligned to events: each is {verdict, confidence, rationale, mitre}.
    """
    from openpyxl import Workbook
    from openpyxl.styles import Font, PatternFill

    order = {"malicious": 0, "suspicious": 1, "needs_review": 2, "benign": 3}
    fills = {
        "malicious": PatternFill("solid", fgColor="F4C7C3"),
        "suspicious": PatternFill("solid", fgColor="FCE8B2"),
        "needs_review": PatternFill("solid", fgColor="D9E1F2"),
        "benign": PatternFill("solid", fgColor="E2EFDA"),
    }
    verdict_cols = ["verdict", "confidence", "mitre", "rationale"]
    wb = Workbook()

    ws_all = wb.active
    ws_all.title = "All Events"
    all_header = verdict_cols + [str(h) for h in src_headers]
    ws_all.append(all_header)
    for c in ws_all[1]:
        c.font = Font(bold=True)

    flagged = []
    for ev_row_vals, v in zip(events, verdicts):
        line = [v["verdict"], v["confidence"], v.get("mitre", ""), v["rationale"]] + list(ev_row_vals)
        ws_all.append(line)
        cell = ws_all.cell(row=ws_all.max_row, column=1)
        cell.fill = fills.get(v["verdict"], fills["needs_review"])
        if v["verdict"] != "benign":
            flagged.append((order.get(v["verdict"], 9), line))

    ws_tr = wb.create_sheet("Triage", 0)
    ws_tr.append(all_header)
    for c in ws_tr[1]:
        c.font = Font(bold=True)
    for _, line in sorted(flagged, key=lambda x: x[0]):
        ws_tr.append(line)
        ws_tr.cell(row=ws_tr.max_row, column=1).fill = fills.get(line[0], fills["needs_review"])

    for ws in (ws_tr, ws_all):
        ws.freeze_panes = "A2"
        ws.column_dimensions["A"].width = 13
        ws.column_dimensions["D"].width = 70
    out_path.parent.mkdir(parents=True, exist_ok=True)
    wb.save(str(out_path))
    return {"total": len(events), "flagged": len(flagged), "out": str(out_path)}
