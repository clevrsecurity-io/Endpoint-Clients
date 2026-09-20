# clevr-scan

A single file you can send to someone who does not know you yet. They run it once on a machine and get a list of the AI assistants installed there, what each one is wired to, and which of them have nothing checking their actions.

This is not the fleet agent in `../go`. That one reports to a Clevr engine and needs a key. This one has no URL, no key, and opens no network connection at all.

## Build

```bash
./build.sh
```

Four static binaries land in `dist/`, around 2.5 MB each: macOS Apple silicon, macOS Intel, Windows, Linux. Nothing to install on the target machine.

## Run

```bash
./clevr-scan-macos-arm64
```

```powershell
.\clevr-scan-windows.exe
```

It prints the inventory and writes `clevr-scan-<host>-<date>.txt` next to itself, so the person can forward the report without a screenshot.

| Flag | Effect |
| --- | --- |
| `--json` | machine-readable output |
| `--quiet` | print only, do not write the report file |
| `--en` / `--fr` | language, French by default |

## What it reports

For each assistant found: whether it is installed or currently running, where it was found, how many connectors (MCP servers) it can reach and their names, and whether anything checks its tool calls before they run.

Detected today: Claude Code, Cursor, Codex CLI, GitHub Copilot, Cline, Roo Code, Continue, Gemini CLI, Windsurf, Claude Desktop, ChatGPT, VS Code, Ollama, LM Studio.

## Three properties that are not negotiable

**It sends nothing.** No URL, no key, no telemetry, no network call of any kind. The person running it can verify that in the source, which is why it is short.

**It prints no secret.** MCP server configs carry API keys in their `env` blocks. Only the server names are read out; the values are never touched.

**It reports a competitor's gate as a gate.** If a machine is governed by someone else's hook or proxy, the scan says so. A scan that calls every rival install "ungoverned" is an advert, and the reader can tell in ten seconds.

Local model runners and the editor itself are listed but not counted as ungoverned: a local model has no outbound tool call of its own to gate, and an editor is governed through the assistants it hosts.

## What it cannot tell you

It reads what is on the machine at the moment it runs. It does not watch over time, it does not see what the assistant actually did, and it cannot tell whether a gate it found is enforcing or only recording. Those need the engine.
