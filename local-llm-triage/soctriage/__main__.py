"""Command-line entry point.  Run:  python3 -m soctriage <command> --help

Commands:
  parse    UAC collection(s)  -> per-host per-artifact CSVs      (stage 2)
  stack    per-host CSVs       -> stacked_*.csv + outliers.csv    (stage 3)
  triage   outliers.csv        -> triaged_outliers.csv via LLM    (stage 4)
  winlogs  events.xlsx         -> reviewed.xlsx via LLM           (stage 5)
  run      parse + stack + triage in one go
  selftest generate a synthetic 5-host fleet and run the whole pipeline offline
"""

import argparse
import sys
from pathlib import Path


def _add_llm_flags(p):
    p.add_argument("--offline", action="store_true",
                   help="use the built-in heuristic instead of the model (no Ollama needed)")
    p.add_argument("--model", default=None, help="Ollama model tag (default llama3.1:8b or $SOCTRIAGE_MODEL)")
    p.add_argument("--url", default=None, help="Ollama base URL (default http://localhost:11434)")


def main(argv=None):
    ap = argparse.ArgumentParser(prog="soctriage", description="Stack UAC collections, sweep outliers, triage with a local LLM.")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p_parse = sub.add_parser("parse", help="parse UAC archive(s)/folder(s) into per-artifact CSVs")
    p_parse.add_argument("sources", nargs="+", help="UAC .tar.gz files, extracted folders, or a dir of archives")
    p_parse.add_argument("-o", "--out", default="parsed", help="output dir (default: parsed/)")
    p_parse.add_argument("--recent-days", type=int, default=30, help="bodyfile: flag files modified within N days")
    p_parse.add_argument("--only", nargs="+", help="parse only these artifacts (e.g. bodyfile known_hosts)")

    p_stack = sub.add_parser("stack", help="stack per-host CSVs and write outliers")
    p_stack.add_argument("parsed_dir", nargs="?", default="parsed", help="dir from 'parse' (default: parsed/)")
    p_stack.add_argument("-o", "--out", default="stacked", help="output dir (default: stacked/)")
    p_stack.add_argument("--rare-threshold", type=int, default=1, help="flag values seen on <= N hosts (default 1)")

    p_tri = sub.add_parser("triage", help="triage outliers.csv with the local LLM")
    p_tri.add_argument("outliers", nargs="?", default="stacked/outliers.csv")
    p_tri.add_argument("-o", "--out", default="triaged", help="output dir (default: triaged/)")
    p_tri.add_argument("--limit", type=int, help="triage only the first N outliers")
    _add_llm_flags(p_tri)

    p_win = sub.add_parser("winlogs", help="review a Windows event-log Excel export with the local LLM")
    p_win.add_argument("xlsx", help="input .xlsx exported from Splunk/Sentinel")
    p_win.add_argument("-o", "--out", default="reviewed.xlsx", help="output .xlsx (default: reviewed.xlsx)")
    p_win.add_argument("--notable-only", action="store_true", help="only review rows with a notable Event ID")
    p_win.add_argument("--limit", type=int, help="review only the first N rows")
    _add_llm_flags(p_win)

    p_run = sub.add_parser("run", help="parse + stack + triage in one command")
    p_run.add_argument("sources", nargs="+")
    p_run.add_argument("-o", "--out", default="triage_run", help="output dir (default: triage_run/)")
    p_run.add_argument("--rare-threshold", type=int, default=1)
    p_run.add_argument("--recent-days", type=int, default=30)
    _add_llm_flags(p_run)

    p_st = sub.add_parser("selftest", help="build a synthetic fleet and run the pipeline offline")
    p_st.add_argument("-o", "--out", default="selftest_out")

    args = ap.parse_args(argv)

    if args.cmd == "parse":
        from .uac_parse import parse_many
        parse_many(args.sources, Path(args.out), recent_days=args.recent_days, only=args.only)
    elif args.cmd == "stack":
        from .stack import stack_all
        stack_all(Path(args.parsed_dir), Path(args.out), rare_threshold=args.rare_threshold)
    elif args.cmd == "triage":
        from .triage import triage_outliers
        from . import llm
        triage_outliers(Path(args.outliers), Path(args.out), offline=args.offline,
                        model=args.model or llm.DEFAULT_MODEL, url=args.url or llm.DEFAULT_URL, limit=args.limit)
    elif args.cmd == "winlogs":
        from .triage import triage_winlogs
        from . import llm
        triage_winlogs(Path(args.xlsx), Path(args.out), offline=args.offline,
                       model=args.model or llm.DEFAULT_MODEL, url=args.url or llm.DEFAULT_URL,
                       notable_only=args.notable_only, limit=args.limit)
    elif args.cmd == "run":
        from .uac_parse import parse_many
        from .stack import stack_all
        from .triage import triage_outliers
        from . import llm
        out = Path(args.out)
        parse_many(args.sources, out / "parsed", recent_days=args.recent_days)
        stack_all(out / "parsed", out / "stacked", rare_threshold=args.rare_threshold)
        triage_outliers(out / "stacked" / "outliers.csv", out / "triaged", offline=args.offline,
                        model=args.model or llm.DEFAULT_MODEL, url=args.url or llm.DEFAULT_URL)
        print(f"\nDone. Start here: {out/'triaged'/'triaged_outliers.csv'}", file=sys.stderr)
    elif args.cmd == "selftest":
        from .selftest import run_selftest
        run_selftest(Path(args.out))


if __name__ == "__main__":
    main()
