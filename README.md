# Clevr endpoint agent

A light, **userland**, cross-platform (macOS / Windows / Linux) agent that discovers
the AI clients and agents running on a machine, flags **shadow AI** (an AI client
running with no evidence it is governed by Clevr), and can **point those clients at
Clevr** by writing a Clevr MCP server into their own configuration. Discovery, then
remediation, from the machine itself.

Requires **Node 18+**. Zero dependencies.

## Run

```bash
node clevr-endpoint.mjs            # print a posture report for this machine
node clevr-endpoint.mjs --report   # also send it to Clevr
node clevr-endpoint.mjs --json     # machine-readable output
node clevr-endpoint.mjs --govern   # show how each client would be pointed at Clevr
node clevr-endpoint.mjs --govern --apply   # write it
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
| `CLEVR_MCP_URL` | The MCP server written into a client's config by `--govern` (defaults to `CLEVR_GATEWAY_URL` + `/mcp`). |
| `CLEVR_MCP_NAME` | The name of that entry in the client's config (default `clevr`). |

A client's config counts as governed when an MCP entry points at the host of
`CLEVR_GATEWAY_URL` **or** of `CLEVR_MCP_URL`, so the Clevr MCP server can be published
on its own host without the machines reading as ungoverned.

## What it detects

Claude Desktop, ChatGPT desktop, Cursor, Windsurf, Claude Code, Gemini CLI, GitHub
Copilot CLI, Augment, Codex, Ollama and LM Studio, plus heuristic Python and Node
agents. For each it reports:

- **GOVERNED**: something actually gates this client. A hook in its harness, the MCP guard wrapping its servers, or an LLM gateway base URL on our host.

  **The Clevr MCP server configured as a server is NOT this.** It exposes two tools, one to ask for a verdict and one to look a resource up. The client can ask; nothing obliges it to and nothing stops it when it does not. A machine with only the Clevr MCP server reads as shadow, with the Clevr MCP server named on its line, because calling it governed puts a green tag where Clevr gates nothing. What gates a client's own tools is the guard, which wraps the servers it already has.
- **LOCAL**: a local model runner (Ollama / LM Studio); there is no cloud gateway to route through, so govern its tool use via a local MCP proxy.
- **SHADOW**: running, with no evidence it is governed.

The command-line harnesses are listed after the desktop applications on purpose,
and matched on the end of the executable path. ChatGPT desktop ships a binary
literally named `codex` inside its own bundle, so a looser rule reported one
product as two. A harness that runs as a script rather than a binary is seen by
its install directory instead of by its process: missing a line in an inventory
costs less than inventing a client that is not there.

Governance is reported at the depth it was found, because the three are not the
same control. A **hook** runs inside the harness before the tool call, in a
separate process outside the model, so an injection cannot talk its way past it
and the client rewriting its own configuration does not remove it. An **MCP**
entry governs only what crosses that one server, and the client can take it back.
A **gateway** base URL governs the model hop and not the tool hop, and so does a
harness whose own configuration points its model traffic at Clevr.

**Codex is read at gateway depth and never at hook depth. It exposes no
synchronous pre-tool hook, so what Clevr installs for it records and signals but
cannot deny a call inline. Crediting it with a hook would overstate the control
by a wide margin.**

It also lists clients that are **installed but not running**, since a person can
install an AI client and open it once a month while the machine carries it all
the same. Those are counted beside the shadow figure rather than folded into it,
so that number keeps its original meaning.

## Browser extensions

An AI assistant living in the browser is an agent on this machine too, and a
browser process does not say which site is open. What is readable in userland is
the extension's own manifest, and two things come out of it with deliberately
different weight:

- what it can **reach** is a fact, read from the declaration (`every site`, or a
  count of site patterns);
- **"looks like an AI assistant"** is a name match, printed as the heuristic it
  is. A name list misses a new product and can catch an unrelated one, so it
  never becomes a silent verdict.

Extensions with no AI in the name are summarised rather than listed, because a
security screen showing every browser extension is a screen nobody reads.

Whether an extension is actually **enabled** is a third thing, and the three
browser families answer it differently, so the record carries the answer rather
than assuming one:

| Family | Extensions read from | Enabled state | Reach |
|---|---|---|---|
| Chromium (Chrome, Brave, Edge, Arc, Vivaldi, Opera, Chromium) | each profile's `Extensions` directory | yes, from the profile's disable reasons | from the manifest |
| Firefox | each profile's `extensions.json` | yes, from `active` and `userDisabled` | from the granted origins, when the profile records them |
| Safari | `pluginkit`, the tool Apple ships | **no**, Safari keeps it in a container the OS protects | only for a converted web extension, which carries a manifest |

A disabled extension is listed and marked, never counted as something reading
pages today. Safari says **installed**, and the output states that it is not
claiming to know what Safari has switched on. Firefox's own bundled add-ons are
dropped, but `app-profile` is the user's own profile, so anything unrecognised is
kept: listing one extra beats hiding a real one.

The Firefox reader is written to the format Mozilla documents and is **not
verified against a live profile**, since none existed on the machine it was built
on. It can therefore only add a find, never remove one, and a missing field
degrades to "not declared" rather than to a claim.

The verdict reads the client's **MCP server list and nothing else**. The word
"clevr" in a folder path, a plugin name, or an entry left pointing at a host that no
longer exists does **not** count as governance. A config that cannot be parsed is an
unknown, and unknown is reported as shadow with the reason on the line, so a machine
cannot turn itself green by corrupting its own file.

Reports land at `POST /v1/endpoints` and roll up into a fleet shadow-AI view.

## Remediate (`--govern`)

For each client it can reach, `--govern` prints what it would change. Nothing is
written without `--apply`.

```
[PLANNED ] Claude Desktop
           - would add "clevr" in ~/Library/Application Support/Claude/claude_desktop_config.json
           - leaves 2 other MCP server(s) untouched: filesystem, github
[OK      ] Cursor
           - already routed through Clevr (https://acme.clevrsecurity.com/mcp)
[SKIP    ] ChatGPT desktop
           - no user-editable MCP configuration is documented for this client
```

Writing is deliberately conservative:

- it adds or repoints **only** the Clevr entry, and names the other MCP servers it leaves alone;
- it copies the original to a timestamped `.clevr-backup-…` file first;
- it writes to a temporary file and renames, so an interrupted run cannot truncate a client's config;
- it **refuses** a file it cannot parse, and says so rather than overwriting it;
- it recognises an existing local-guard entry and leaves that working configuration in place;
- it is idempotent: a second run changes nothing and makes no second backup.

## Did it hold?

Writing a setting is not the same as it holding, so the agent keeps a note in
`~/.clevr/endpoint-state.json` (mode 0600, beside the device key) and checks on
**every** run, with or without `--govern`, whether it is still there.

It records **everything it observes configured**, not only what it wrote itself.
A hook installed by the CLI, by an administrator or by hand is exactly as worth
watching, and a setting the agent never wrote used to vanish in silence: its
removal read as plain shadow, with nothing to say the machine had ever been
configured. Each record says whether this agent put it there, and the report
repeats it rather than implying we did.

One client can carry two settings at once, a hook and an MCP entry for instance,
and losing either one is its own event:

```
Settings undone since Clevr was applied
----------------------------------------------------------------------
[UNDONE  ] Claude Desktop
           - the Clevr entry is gone from ~/Library/.../claude_desktop_config.json
           - applied 2026-09-17T23:25:12Z, undone 2026-09-17T23:32:41Z
           - likely cause: Claude Desktop rewrites this file while running and
             drops entries added underneath it
```

It reads the configuration file, not the list of running clients, because a
client can be closed and still have had its setting taken back. An entry now
aimed at another address is reported as that, not as a removal.

**What this says, and what it does not.** It knows Clevr was configured here and
is not now. It does **not** know who undid it: the client rewriting its own file,
someone editing it by hand and an administrator changing the target look the same
on disk. A client already known to rewrite its own configuration is offered as a
likely cause and labelled as one.

The count moves only when a setting crosses from holding to gone, so a machine
that stays undone is one reversal, not one per scan. Putting it back clears the
finding and keeps the history, which is what separates an accident from a habit.

Remediable today: Claude Desktop, Cursor, Claude Code, Windsurf. Anything else is
listed with the reason it cannot be reached from the machine. Each client must be
restarted for a new entry to take effect.

**Apply while the client is closed.** Some clients rewrite their own configuration
while running. Reading, editing and writing such a file can drop a write the client
made in between; the backup protects the file from corruption, not from a lost
update, and closing the client also satisfies the restart the new entry needs anyway.

One client is known to go further and **revert the change**: Claude Desktop holds its
configuration in memory and writes the whole file back while running, dropping an
entry added underneath it. Measured 2026-09-17: an entry written at 23:25 was gone at
23:32. So it is **refused by default** with the reason on its line, rather than
written and silently lost, which would put "pointed at Clevr" on a console screen for
a machine that is ungoverned again minutes later. Quit the app and run again, or pass
`--force` if you mean it. Claude Code, checked the same way, keeps the entry.

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

The Go binary and the `.mjs` share the same signed wire contract, the same device key
(stored as a raw seed, so a machine can switch between them with no key change), the
same **detection** verdict and the same **undone** check, all verified case by case in
`test_govern.mjs`. That last one matters for a fleet: apply once with the `.mjs` or the
CLI, then let the MDM-pushed binary scan on a schedule, and it reads the same note and
reports the same reversal, counter included.

**`--govern` itself is Node-only for now**: the binary discovers, checks and reports,
it does not write. Use the `.mjs` (~10 KB) where Node 18+ is already present; use the
binary for MDM push to machines with no runtime.

## Honest scope

Userland. It sees processes and configuration files, **not kernel syscalls**, and it
blocks nothing itself. It answers "is there an ungoverned AI client on this machine?"
and can then point that client at Clevr, but it does not turn a laptop into a hard
chokepoint: enforcement happens at the Clevr MCP server it points the client at, and a user who
edits their own config can undo it. Lock the configuration with your MDM where that
matters. Deep syscall capture is the job of your EDR. Clevr is the semantic
agent-governance layer, meant to sit above or alongside an EDR, not to replace one.

Two limits worth stating plainly. A client with no user-editable MCP configuration
cannot be remediated from the machine at all, and the report names each one rather
than omitting it. And the remediation block attached to a posted report is **not**
covered by the device signature, and `POST /v1/endpoints` does not yet store it, so
it does not appear in the fleet view.
