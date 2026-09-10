# Clevr endpoint agent

A light, **userland**, cross-platform (macOS / Windows / Linux) agent that discovers
the AI clients and agents running on a machine and flags **shadow AI**: an AI client
running with no evidence it is governed by Clevr.

Requires **Node 18+**. Zero dependencies.

## Run

```bash
node clevr-endpoint.mjs            # print a posture report for this machine
node clevr-endpoint.mjs --report   # also send it to Clevr
node clevr-endpoint.mjs --json     # machine-readable output
```

**Windows (PowerShell):**

```powershell
$env:CLEVR_URL="https://acme.clevrsecurity.com"
$env:CLEVR_API_KEY="clevr_sk_..."
node clevr-endpoint.mjs --report
```

Config (env):

| Var | Purpose |
|-----|---------|
| `CLEVR_URL` | Your engine, e.g. `https://<tenant>.clevrsecurity.com`. |
| `CLEVR_API_KEY` | A fleet key (`clevr_sk_...`). Only needed for `--report`. |
| `CLEVR_GATEWAY_URL` | Your LLM gateway base URL (defaults to `CLEVR_URL`). Used to decide whether a client's `ANTHROPIC_BASE_URL` / `OPENAI_BASE_URL` routes through Clevr. |
| `CLEVR_MCP_MARKER` | Substring identifying a Clevr-fronted MCP server in a client's config (default `clevr`). |

## What it detects

Claude Desktop, Cursor, Windsurf, ChatGPT desktop, Claude Code, Ollama / LM Studio
(local models), plus heuristic Python / Node agents. For each it reports:

- **GOVERNED** — routes through Clevr (an LLM gateway base URL, or a Clevr-fronted MCP server in the client's config).
- **LOCAL** — a local model runner (Ollama / LM Studio); there is no cloud gateway to route through, so govern its tool use via a local MCP proxy.
- **SHADOW** — running, with no evidence it is governed.

Reports land at `POST /v1/endpoints` and roll up into a fleet shadow-AI view.

## Deploy to a fleet

Push it with your MDM (Intune, Jamf, …) as a scheduled task / `launchd` / `systemd`
timer running `node clevr-endpoint.mjs --report` every few minutes.

## Standalone executables (no runtime)

For machines with no Node, build one self-contained binary per OS with
[`build.sh`](build.sh) (needs [Go](https://go.dev/dl); source in [`go/`](go/)):

```bash
./build.sh   # -> dist/clevr-endpoint-{macos-arm64,macos-x64,windows-x64.exe,linux-x64}
```

Each is a **~6 MB static binary** (Go, stdlib only) that runs with **nothing installed**:

```bash
./dist/clevr-endpoint-macos-arm64 --report        # macOS
dist\clevr-endpoint-windows-x64.exe --report       # Windows (PowerShell)
```

The Go binary and the `.mjs` are behaviourally identical and share the same signed
wire contract and the same device key (stored as a raw seed, so a machine can switch
between them with no key change). Use the `.mjs` (~10 KB) where Node 18+ is already
present; use the binary for MDM push to machines with no runtime.

## Honest scope

Userland and **detection-only**. It sees processes and config files, **not kernel
syscalls**, and it does **not block**. It answers "is there an ungoverned AI client
on this machine?" — it does not turn a laptop into a hard chokepoint. Enforcement is
the MDM-locked gateway / MCP config it checks for; deep syscall capture is the job of
your EDR. Clevr is the semantic agent-governance layer, meant to sit above or
alongside an EDR, not to replace one.
