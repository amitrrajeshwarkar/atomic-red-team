"""Stage 4/5 - talk to a LOCAL LLM. No data leaves the box.

Why local: e& handles UAE subscriber data on critical national infrastructure.
Sending event-log rows to a cloud API (OpenAI, Anthropic, Azure OpenAI) would
move regulated data outside the perimeter. A model running under Ollama on the
analyst laptop keeps every byte on-prem. That is the whole point of this tool.

Default backend is Ollama's HTTP API on http://localhost:11434 (no API key,
no internet). On a 16 GB laptop with no GPU, a 7-8B model quantised to 4-bit
(e.g. llama3.1:8b or qwen2.5:7b-instruct) is the realistic ceiling - it fits in
RAM and answers in tens of seconds, not seconds. We keep prompts small and force
JSON output so the model has little room to ramble or hallucinate structure.

This module NEVER calls out to the network except to localhost. It also has an
--offline heuristic mode so the pipeline is demonstrable before Ollama is set up.
"""

import json
import re
import urllib.request
import urllib.error

from .common import env_default, log

DEFAULT_URL = env_default("SOCTRIAGE_OLLAMA_URL", "http://localhost:11434")
DEFAULT_MODEL = env_default("SOCTRIAGE_MODEL", "llama3.1:8b")

SYSTEM_PROMPT = (
    "You are a SOC triage assistant reviewing forensic artifacts from Linux servers "
    "and Windows event logs. You are running locally and offline. For each item you "
    "are given, decide a verdict and explain it in one or two sentences using SOC "
    "terminology. Be conservative: rare does not always mean malicious, but rare plus "
    "a suspicious property (setuid, world-writable exec, key with no comment, cron "
    "pulling from the internet, a service running from /tmp) is worth escalating. "
    "You must answer ONLY with a JSON object, no prose before or after."
)

VERDICTS = ("benign", "suspicious", "malicious", "needs_review")


def _http_post(url: str, payload: dict, timeout: int) -> dict:
    data = json.dumps(payload).encode()
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # localhost only
        return json.loads(resp.read().decode())


def ollama_available(base_url: str = DEFAULT_URL, timeout: int = 3) -> bool:
    try:
        with urllib.request.urlopen(base_url + "/api/tags", timeout=timeout):
            return True
    except Exception:
        return False


def ask_ollama(item_text: str, base_url: str, model: str, timeout: int = 120) -> dict:
    """Send one triage item, get back {verdict, confidence, rationale, mitre}."""
    prompt = (
        f"{item_text}\n\n"
        "Respond with JSON exactly like:\n"
        '{"verdict": "benign|suspicious|malicious|needs_review", '
        '"confidence": "low|medium|high", '
        '"rationale": "one or two sentences", '
        '"mitre": "ATT&CK technique id if any, else empty"}'
    )
    payload = {
        "model": model,
        "system": SYSTEM_PROMPT,
        "prompt": prompt,
        "stream": False,
        "format": "json",
        "options": {"temperature": 0.1, "num_ctx": 4096},
    }
    resp = _http_post(base_url + "/api/generate", payload, timeout)
    raw = resp.get("response", "").strip()
    return _coerce_verdict(raw)


def _coerce_verdict(raw: str) -> dict:
    """Models sometimes wrap JSON in text. Pull the first {...} out and validate."""
    out = {"verdict": "needs_review", "confidence": "low", "rationale": raw[:400], "mitre": ""}
    m = re.search(r"\{.*\}", raw, re.DOTALL)
    if m:
        try:
            parsed = json.loads(m.group(0))
            out["verdict"] = parsed.get("verdict", "needs_review")
            out["confidence"] = parsed.get("confidence", "low")
            out["rationale"] = str(parsed.get("rationale", ""))[:600]
            out["mitre"] = str(parsed.get("mitre", ""))[:80]
        except json.JSONDecodeError:
            pass
    if out["verdict"] not in VERDICTS:
        out["verdict"] = "needs_review"
    return out


# ---------------------------------------------------------------------------
# Offline heuristic fallback - deterministic, no model. Lets the pipeline run
# and be demonstrated end-to-end before Ollama is installed, and doubles as a
# sanity baseline for whatever the model says.
# ---------------------------------------------------------------------------

def heuristic_verdict(item_text: str) -> dict:
    t = item_text.lower()
    hi = [
        ("exec_in_tmp", "malicious", "T1059", "executable staged in a world-writable temp dir"),
        ("suid", "suspicious", "T1548.001", "setuid binary - privilege-escalation primitive"),
        ("suspicious_pattern", "suspicious", "T1059", "shell history matches a known attacker pattern"),
        ("uid0_not_root", "malicious", "T1136.001", "second uid-0 account is a backdoor admin"),
        ("home_in_tmp", "suspicious", "T1136.001", "account home under a temp dir"),
        ("/dev/tcp/", "malicious", "T1059.004", "reverse-shell redirection"),
        ("| sh", "suspicious", "T1059.004", "piping a download straight into a shell"),
        ("ld.so.preload", "malicious", "T1574.006", "shared-object preload hijack"),
        ("exec_start=/tmp", "malicious", "T1543.002", "systemd service runs a binary from /tmp"),
        ("exec_start=/dev/shm", "malicious", "T1543.002", "systemd service runs a binary from shared memory"),
        ("port=4444", "suspicious", "T1571", "listening on 4444 - common Metasploit bind-shell port"),
        ("port=1337", "suspicious", "T1571", "listening on a commonly abused backdoor port"),
        ("port=31337", "suspicious", "T1571", "listening on a commonly abused backdoor port"),
    ]
    # Windows event-log signals (winlogs path). Summaries carry "EventID N (meaning)".
    win = [
        ("audit log cleared", "malicious", "T1070.001", "audit log cleared - classic anti-forensics"),
        ("event log cleared", "malicious", "T1070.001", "event log cleared - classic anti-forensics"),
        ("-enc ", "suspicious", "T1059.001", "encoded PowerShell command line"),
        ("-encodedcommand", "suspicious", "T1059.001", "encoded PowerShell command line"),
        ("security-enabled local group", "suspicious", "T1098", "account added to a privileged local group"),
        ("security-enabled global group", "suspicious", "T1098", "account added to a privileged global group"),
        ("user account created", "suspicious", "T1136.001", "new account created"),
        ("service installed", "suspicious", "T1543.003", "new Windows service installed"),
        ("scheduled task created", "suspicious", "T1053.005", "scheduled task created"),
        ("explicit-credential logon", "needs_review", "T1021", "explicit-credential logon - possible lateral movement"),
    ]
    for needle, verdict, mitre, why in hi + win:
        if needle in t:
            return {"verdict": verdict, "confidence": "medium", "rationale": why + " (heuristic)", "mitre": mitre}
    if "host_count=1" in t.replace(" ", ""):
        return {"verdict": "needs_review", "confidence": "low",
                "rationale": "unique to one host in the fleet; no malicious property matched (heuristic)", "mitre": ""}
    return {"verdict": "needs_review", "confidence": "low", "rationale": "no heuristic matched (heuristic)", "mitre": ""}


def triage_items(items, base_url=DEFAULT_URL, model=DEFAULT_MODEL, offline=False, timeout=120,
                 progress_every=10):
    """Triage a list of {id, text} dicts. Yields the same dict enriched with a verdict.

    Falls back to the heuristic per-item if the model errors, so one bad call
    never aborts a batch of 300 outliers.
    """
    use_model = not offline and ollama_available(base_url)
    if offline:
        log("triage mode: OFFLINE heuristic (no model)")
    elif use_model:
        log(f"triage mode: Ollama model '{model}' at {base_url}")
    else:
        log(f"triage mode: Ollama not reachable at {base_url} - falling back to heuristic")
    for i, item in enumerate(items, 1):
        if use_model:
            try:
                verdict = ask_ollama(item["text"], base_url, model, timeout)
            except (urllib.error.URLError, TimeoutError, OSError) as e:
                log(f"item {item.get('id')}: model error ({e}); using heuristic")
                verdict = heuristic_verdict(item["text"])
        else:
            verdict = heuristic_verdict(item["text"])
        merged = dict(item)
        merged.update(verdict)
        if i % progress_every == 0:
            log(f"  triaged {i} items")
        yield merged
