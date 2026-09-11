# Running the local LLM (Ollama) on your Windows laptop

The tool talks to a **local** model so no data leaves the machine. On Windows the
simplest path is the native Ollama app; it also works from inside WSL2 Ubuntu.

## Your hardware reality first

16 GB RAM, no dedicated GPU. Be honest about the ceiling: you can run a **7–8B**
parameter model quantised to 4-bit (roughly 4–5 GB in RAM). It answers in **tens of
seconds per prompt on CPU**, not instantly. A 70B model will not run. That is fine —
triage prompts here are small and structured, and the tool forces JSON output, so a
7–8B model is enough for a PoC. Do not tell Sajjad this runs a frontier model; it
runs a small local one, and that is the correct trade for keeping data on-prem.

## Install (native Windows — recommended)

1. Download the Windows installer from the Ollama website and run it. This installs a
   background service listening on `http://localhost:11434`.
2. Open **Windows PowerShell** and pull a model:

   ```powershell
   ollama pull llama3.1:8b
   ```

   `pull` downloads the model once (a few GB). `llama3.1:8b` is the 8-billion-parameter
   Llama 3.1. `qwen2.5:7b-instruct` is a good alternative and a little lighter.

3. Test it:

   ```powershell
   ollama run llama3.1:8b "say hello in one word"
   ```

## Point the tool at it

Ollama listens on `localhost:11434` whether you call it from PowerShell or from the
Ubuntu terminal (WSL2 forwards localhost to Windows). So from your **Ubuntu terminal**:

```bash
python3 -m soctriage triage stacked/outliers.csv -o triaged/
```

The tool auto-detects Ollama. If it cannot reach it, it prints a message and falls back
to the offline heuristic — it never fails silently.

Override the defaults with flags or environment variables:

```bash
python3 -m soctriage triage stacked/outliers.csv -o triaged/ --model qwen2.5:7b-instruct
export SOCTRIAGE_MODEL=llama3.1:8b
export SOCTRIAGE_OLLAMA_URL=http://localhost:11434
```

## If `localhost:11434` is not reachable from WSL2

Newer WSL2 forwards localhost automatically. If yours does not, find the Windows host
IP from inside Ubuntu and point the tool at it:

```bash
cat /etc/resolv.conf | grep nameserver          # prints the Windows host IP
python3 -m soctriage triage stacked/outliers.csv -o triaged/ --url http://<that-ip>:11434
```

You may also need to set `OLLAMA_HOST=0.0.0.0` for the Windows service so it accepts
connections from the WSL2 network, not just from Windows itself.

## Confirming nothing leaves the box

This is the claim you are actually making to e&, so be able to demonstrate it. The
`soctriage/llm.py` module only ever opens connections to the URL you pass, which
defaults to `localhost`. There is no cloud SDK, no API key, no telemetry. You can prove
it live by running the triage with your network cable unplugged / Wi-Fi off — it still
works against local Ollama.
