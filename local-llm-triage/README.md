# soctriage — stack UAC collections, sweep for outliers, triage with a local LLM

A proof-of-concept for the workflow Sajjad described: pull forensic artifacts off
Linux hosts with **UAC**, flatten each artifact, **stack** them across the fleet
to find what is rare, and hand the rare rows to a **local LLM** that never sends
data off the box. A second command reviews **Windows event logs exported to Excel**
the same way, locally.

Everything here is pure Python 3.9+. The only third-party package is `openpyxl`
(Excel read/write). No cloud API, no data leaves the machine.

---

## The five stages (and where each lives)

| Stage | What it does | Command | Code |
|------|---------------|---------|------|
| 1 | Learn the artifacts | *read `docs/ARTIFACTS.md`* | — |
| 2 | Parse one UAC collection into per-artifact CSVs | `parse` | `soctriage/uac_parse.py` |
| 3 | Stack CSVs across hosts, flag outliers | `stack` | `soctriage/stack.py` |
| 4 | Triage the outliers with a local LLM | `triage` | `soctriage/triage.py` + `llm.py` |
| 5 | Review Windows event-log Excel with a local LLM | `winlogs` | `soctriage/winlogs.py` |

---

## Prove it works in 30 seconds (no UAC data, no Ollama needed)

Type this in your **Ubuntu terminal** (WSL2), from inside the `local-llm-triage`
folder:

```bash
python3 -m soctriage selftest -o /tmp/st
```

`python3 -m soctriage` means "run the `soctriage` package as a program". `-o /tmp/st`
is the output folder. This builds a fake fleet of five near-identical Linux web
servers, compromises one of them (`web03`), runs the whole pipeline offline, and
checks that every planted attacker artifact was surfaced. You should see a block of
`[PASS]` lines and `SELFTEST PASSED`.

That fake `web03` is your demo for Sajjad: it plants a second uid-0 account, a rogue
SSH key, a `curl | sh` cron job, a setuid binary in `/tmp`, a service running from
`/tmp`, a bind shell on port 4444, and a wiped-then-suspicious bash history —
one of each thing the stacker is designed to catch.

---

## Using it on real UAC output

### Stage 2 — parse

```bash
python3 -m soctriage parse /path/to/uac-*.tar.gz -o parsed/
```

- Takes UAC archives (`.tar.gz`), already-extracted folders, or a directory full of
  archives. `tar.gz` is a "zipped folder": `tar` bundles many files into one, `gzip`
  compresses it. Python unpacks both for you, so you never need the `tar` command.
- Writes `parsed/<hostname>/<artifact>.csv` — one CSV per artifact per host.
- `--only bodyfile known_hosts` parses just those two (the ones Sajjad named).
- `--recent-days 30` flags files whose contents changed in the last 30 days.

### Stage 3 — stack

```bash
python3 -m soctriage stack parsed/ -o stacked/
```

- For each artifact it groups identical rows and counts **how many distinct hosts**
  show each value. On a uniform fleet, common = the build, rare = worth a look.
- `--rare-threshold 1` (default) flags anything seen on one host only. Raise it to
  `2` on a small fleet.
- Writes `stacked_<artifact>.csv` (everything, with host counts) and `outliers.csv`
  (just the rare rows, all artifacts, rarest first).

### Stage 4 — triage the outliers locally

```bash
python3 -m soctriage triage stacked/outliers.csv -o triaged/            # uses Ollama if running
python3 -m soctriage triage stacked/outliers.csv -o triaged/ --offline  # heuristic, no model
```

- With Ollama running (see `docs/OLLAMA_SETUP.md`), each outlier goes to your local
  model, which returns a verdict, confidence, one-line rationale, and an ATT&CK id.
- Without Ollama, `--offline` uses a built-in rule set so the pipeline still runs and
  you have a deterministic baseline to compare the model against.
- Writes `triaged_outliers.csv`, worst verdict first.

### One-shot

```bash
python3 -m soctriage run /path/to/uac-*.tar.gz -o triage_run/ --offline
```

Runs parse + stack + triage in sequence.

---

## Stage 5 — review Windows event logs (the local-LLM-for-Excel deliverable)

Export the events from Splunk or Sentinel to `.xlsx`, then:

```bash
python3 -m soctriage winlogs events.xlsx -o reviewed.xlsx --offline
python3 -m soctriage winlogs events.xlsx -o reviewed.xlsx            # uses Ollama
python3 -m soctriage winlogs events.xlsx -o reviewed.xlsx --notable-only
```

- Column names differ between Splunk and Sentinel exports, so the tool **detects**
  the useful columns by name (Time, EventID, Computer, Account, Source IP, Process,
  Message) instead of assuming a fixed layout.
- Output workbook has a **Triage** sheet (flagged events, worst first, colour-coded)
  and an **All Events** sheet with a verdict column your analysts can filter.
- `--notable-only` reviews just the events with a security-relevant Event ID (4624,
  4688, 4720, 1102, 7045, and the rest) when the export is huge and the model is slow.

Why local: e& handles UAE subscriber data on critical national infrastructure, so
these rows cannot go to a cloud API. The model runs under Ollama on the analyst
laptop and every byte stays inside the perimeter.

---

## Requirements

```bash
pip install openpyxl        # in the Ubuntu terminal
```

`pip` is Python's package manager (the `apt` of Python libraries). That is the only
dependency for the tool itself. `pytest` is needed only to run the test suite.

## Tests

```bash
python3 -m pytest -q
```

## What this PoC is and is not

- It **is** a working end-to-end demonstration of the pipeline, with a reproducible
  synthetic case that proves the outlier logic finds planted attacker artifacts.
- It is **not** a replacement for UAC, a SIEM, or an EDR. It processes UAC *output*.
- The offline heuristic is a floor, not the product. The point is the local model;
  the heuristic exists so the pipeline is demonstrable and testable without one.
