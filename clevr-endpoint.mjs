// Clevr endpoint agent — userland, cross-platform (macOS / Windows / Linux).
// Requires Node 18+ (built-in fetch). Zero dependencies.
//
//   node clevr-endpoint.mjs            # print a posture report for this machine
//   node clevr-endpoint.mjs --report   # also POST it to Clevr (needs CLEVR_URL + CLEVR_API_KEY)
//   node clevr-endpoint.mjs --json     # machine-readable output
//   node clevr-endpoint.mjs --watch    # re-run every CLEVR_INTERVAL seconds (default 300)
//   node clevr-endpoint.mjs --govern   # show how each shadow client would be pointed at Clevr
//   node clevr-endpoint.mjs --govern --apply   # write it
//
// Every run also checks whether a setting this agent wrote earlier is still
// there, and reports it as undone if it is not.
//
// What it does: it lists the AI clients / agents running on this machine and, for
// each, whether there is evidence it routes through Clevr (an LLM gateway base URL,
// or a Clevr-fronted MCP server in the client's config). Anything running with no
// such evidence is flagged as SHADOW AI.
//
// With --govern it also REMEDIATES: it writes a Clevr MCP server entry into the
// shadow client's own configuration, so the client starts routing its tool calls
// through Clevr. Nothing is written without --apply.
//
// What it is NOT: it is userland. It sees processes and configuration, not kernel
// syscalls, and it blocks nothing itself. Enforcement happens at the Clevr MCP server it
// points the client at. This closes the visibility gap ("is there an ungoverned
// agent on this laptop?") and then closes the gap itself, without becoming an EDR.

import { execFileSync, spawnSync } from 'node:child_process'
import crypto from 'node:crypto'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'

const VERSION = '0.3.0'
const args = new Set(process.argv.slice(2))
const CLEVR_URL = process.env.CLEVR_URL || ''
const CLEVR_KEY = process.env.CLEVR_API_KEY || ''
const GATEWAY_URL = process.env.CLEVR_GATEWAY_URL || CLEVR_URL
const MCP_MARKER = (process.env.CLEVR_MCP_MARKER || 'clevr').toLowerCase()

const hostOf = (u) => { try { return new URL(u).host } catch { return '' } }
const CLEVR_HOST = hostOf(GATEWAY_URL)
// The Clevr MCP server does not have to sit on the engine's host: CLEVR_MCP_URL exists
// precisely so it can be published separately. An entry aimed at either one is
// aimed at us, and comparing only against the engine would report a correctly
// configured machine as shadow.
const clevrHosts = () => new Set([CLEVR_HOST, hostOf(MCP_URL)].filter(Boolean))

// ── AI-client catalog. Ordered specific → generic; each process is assigned to
// the first entry it matches.
//
// An installed application is identified by its EXECUTABLE, never by its
// arguments. Matching the whole command line turned any process that merely
// mentioned a client's name into that client: a shell running a script with the
// word in it, a grep for it, an editor opening a folder named after it. On a
// security screen that is invented shadow AI, which is worse than missing a real
// one. So `re` is tested against the executable, which listProcesses reads from
// ps rather than guessing, because neither splitting on whitespace nor cutting
// at the first flag is right: an application path can contain spaces, and a
// process with no flags at all leaks its arguments into the guess.
//
// `inArgs: true` is the deliberate exception, for the entries whose identity
// genuinely lives in the arguments: an interpreter running an agent is `node
// .../claude-code/cli.js` or `python -m crewai`, and the executable is just the
// interpreter.
const CATALOG = [
  { id: 'claude-code', label: 'Claude Code (CLI)', kind: 'cli-agent', inArgs: true, re: /claude[-_ ]?code|@anthropic-ai[\/\\]claude-code/i },
  { id: 'cursor', label: 'Cursor', kind: 'ide-agent', re: /(?:^|[\/\\ ])cursor(?:\.exe| helper|$|[\/\\ ])/i, names: ['cursor'] },
  { id: 'windsurf', label: 'Windsurf', kind: 'ide-agent', re: /windsurf/i, names: ['windsurf'] },
  // The ChatGPT browser before the ChatGPT application, whose pattern is any
  // path naming ChatGPT.
  { id: 'chatgpt-atlas', label: 'ChatGPT Atlas (AI browser)', kind: 'ai-browser', re: /chatgpt[ ._-]?atlas/i, names: ['chatgpt atlas'] },
  { id: 'chatgpt', label: 'ChatGPT desktop', kind: 'desktop-assistant', re: /chatgpt/i, names: ['chatgpt', 'chatgpt classic'] },
  { id: 'claude-desktop', label: 'Claude Desktop', kind: 'desktop-assistant', re: /(?:^|[\/\\ ])claude(?:\.exe| helper|$|[\/\\ ])/i, names: ['claude'] },
  { id: 'perplexity', label: 'Perplexity', kind: 'desktop-assistant', re: /(?:^|[\/\\ ])perplexity(?:\.exe| helper|$|[\/\\ ])/i, names: ['perplexity'] },
  { id: 'comet', label: 'Comet (AI browser)', kind: 'ai-browser', re: /[\/\\]Comet\.app[\/\\]|(?:^|[\/\\])comet\.exe$/i, names: ['comet'] },
  // Microsoft's assistant before the GitHub command line, which answers to the
  // same word: the application is a bundle (Copilot.app) on a Mac.
  { id: 'microsoft-copilot', label: 'Microsoft Copilot', kind: 'desktop-assistant', re: /[\/\\]Copilot\.app[\/\\]|(?:^|[\/\\])(?:microsoft[ .]?copilot|m365copilot)(?:\.exe)?$/i, names: ['microsoft copilot', 'copilot'] },
  // The command-line harnesses come AFTER the desktop applications on purpose.
  // ChatGPT desktop ships a binary literally named `codex` inside its own bundle
  // (Contents/Resources/codex), and a machine carrying one product must not be
  // reported as carrying two. First match wins, so the application claims its
  // own files and a standalone binary on the PATH still falls through to here.
  // The coding harnesses Clevr ships a hook for. Their executable names come
  // from our own integrations rather than from watching these products run.
  //
  // Anchored to the END of the executable path on purpose: a command-line
  // harness is a binary CALLED codex or gemini, not any path that contains the
  // word. The ChatGPT desktop app ships a framework named "Codex
  // Framework.framework", so a looser pattern reported its crash handler as the
  // Codex CLI. Missing a harness that runs under an unexpected name costs us a
  // line in an inventory; inventing one puts a client on a security screen that
  // is not there, and the install-path check below still finds a real one.
  // Codex's own agent that controls the desktop (installed under ~/.codex), a
  // bundle whose service carries no product word in its name. Found on the
  // founder's Mac on 2026-10-09 by its signature alone.
  { id: 'codex-computer-use', label: 'Codex computer use (controls the desktop)', kind: 'cli-agent', re: /[\/\\]Codex Computer Use\.app[\/\\]/i, names: ['codex computer use'] },
  { id: 'gemini-cli', label: 'Gemini CLI', kind: 'cli-agent', re: /(?:^|[\/\\])gemini(?:\.exe)?$/i },
  // A copilot.exe that Microsoft signed is its assistant, not this.
  { id: 'copilot-cli', label: 'GitHub Copilot CLI', kind: 'cli-agent', re: /(?:^|[\/\\])copilot(?:\.exe)?$/i, unless: /\bMicrosoft\b/i },
  { id: 'augment', label: 'Augment', kind: 'cli-agent', re: /(?:^|[\/\\])(?:auggie|augment)(?:\.exe)?$/i },
  { id: 'codex', label: 'Codex (CLI)', kind: 'cli-agent', re: /(?:^|[\/\\])codex(?:\.exe)?$/i },
  { id: 'goose', label: 'Goose', kind: 'cli-agent', re: /(?:^|[\/\\])goose(?:\.exe)?$|[\/\\]Goose\.app[\/\\]/i, names: ['goose'] },
  { id: 'opencode', label: 'OpenCode', kind: 'cli-agent', re: /(?:^|[\/\\])opencode(?:\.exe)?$/i, names: ['opencode'] },
  { id: 'aider', label: 'Aider', kind: 'cli-agent', inArgs: true, re: /(?:^|[\/\\ ])aider(?:\.exe)?(?:\s|$)|\s-m\s+aider\b/i },
  { id: 'kiro', label: 'Kiro', kind: 'ide-agent', re: /[\/\\]Kiro\.app[\/\\]|(?:^|[\/\\])kiro(?:\.exe)?$/i, names: ['kiro'] },
  { id: 'trae', label: 'Trae', kind: 'ide-agent', re: /[\/\\]Trae\.app[\/\\]|(?:^|[\/\\])trae(?:\.exe)?$/i, names: ['trae'] },
  { id: 'ollama', label: 'Ollama (local model)', kind: 'local-model', re: /ollama/i, names: ['ollama'] },
  { id: 'lmstudio', label: 'LM Studio (local model)', kind: 'local-model', re: /lm[-_ ]?studio/i, names: ['lm studio'] },
  { id: 'jan', label: 'Jan (local model)', kind: 'local-model', re: /[\/\\]Jan\.app[\/\\]|(?:^|[\/\\])jan(?:\.exe)?$/i, names: ['jan'] },
  { id: 'gpt4all', label: 'GPT4All (local model)', kind: 'local-model', re: /gpt4all/i, names: ['gpt4all'] },
  { id: 'msty', label: 'Msty (local model)', kind: 'local-model', re: /[\/\\]Msty\.app[\/\\]|(?:^|[\/\\])msty(?:\.exe)?$/i, names: ['msty'] },
  { id: 'anythingllm', label: 'AnythingLLM', kind: 'desktop-assistant', re: /anythingllm/i, names: ['anythingllm'] },
  // Applications that carry AI among other things. Listed, so an inventory is
  // complete, and never counted as shadow AI: whether their AI is used cannot
  // be seen from the machine.
  { id: 'raycast', label: 'Raycast (AI built in)', kind: 'ai-feature', re: /[\/\\]Raycast\.app[\/\\]|(?:^|[\/\\])raycast(?:\.exe)?$/i, names: ['raycast'] },
  { id: 'warp', label: 'Warp (AI built in)', kind: 'ai-feature', re: /[\/\\]Warp\.app[\/\\]|(?:^|[\/\\])warp(?:\.exe)?$/i, names: ['warp'] },
  { id: 'zed', label: 'Zed (AI built in)', kind: 'ai-feature', re: /[\/\\]Zed\.app[\/\\]|(?:^|[\/\\])zed(?:\.exe)?$/i, names: ['zed'] },
  // Heuristic homegrown agents: match on specific agent FRAMEWORKS only (not the
  // bare words "agent"/"mcp", which catch unrelated tooling and cause false positives).
  { id: 'py-agent', label: 'Python agent', kind: 'custom-agent', inArgs: true, re: /python[0-9.]*\b.*(langchain|langgraph|crewai|autogen|llama[_-]?index|pydantic_ai|smolagents|@?modelcontextprotocol[\/\\]server)/i },
  { id: 'node-agent', label: 'Node agent', kind: 'custom-agent', inArgs: true, re: /\bnode\b.*(langchain|@langchain|crewai|@modelcontextprotocol[\/\\]server|ai-sdk|@openai[\/\\]agents)/i },
  // Only reached through an executable's signature or declared company
  // (identityOf below): an application by a maker whose every product is AI.
  // family: the maker's products. Its updater or crash reporter, signed by the
  // same maker, belongs to the product when the product is there, and stands
  // on its own only when none is: a renamed binary, or a product not listed.
  { id: 'openai-app', label: 'An application signed by OpenAI', kind: 'desktop-assistant', re: null, family: ['chatgpt', 'chatgpt-atlas', 'codex', 'codex-computer-use'] },
  { id: 'anthropic-app', label: 'An application signed by Anthropic', kind: 'desktop-assistant', re: null, family: ['claude-desktop', 'claude-code'] },
  { id: 'mistral-app', label: 'An application signed by Mistral AI', kind: 'desktop-assistant', re: null, family: [] }
]

// Where each client keeps its MCP configuration, keyed by the SAME ids as CATALOG
// so detection and remediation can never drift apart on a client name.
//
// `detect` and `write` are deliberately separate lists. Detection reads every
// location the client may have been configured from, including ones left over
// from another OS or an older layout. Remediation writes to the ONE file this
// client actually reads on this platform. Writing anywhere else would leave the
// client ungoverned while the next scan found the entry and called it governed.
function configPaths (home, appData) {
  const pick = (mac, win, linux) => process.platform === 'darwin' ? mac : process.platform === 'win32' ? win : linux
  const desktopMac = path.join(home, 'Library', 'Application Support', 'Claude', 'claude_desktop_config.json')
  const desktopWin = path.join(appData, 'Claude', 'claude_desktop_config.json')
  const desktopLin = path.join(home, '.config', 'Claude', 'claude_desktop_config.json')
  const cursorHome = path.join(home, '.cursor', 'mcp.json')
  const windsurfHome = path.join(home, '.codeium', 'windsurf', 'mcp_config.json')
  return {
    // quitFirst: this client holds its configuration in memory and writes the whole
    // file back while running, dropping anything added underneath it. Observed on
    // 2026-09-17: an entry written at 23:25 was gone at 23:32, with the app up since
    // morning. Writing anyway would put "pointed at Clevr" on a console screen for a
    // machine that is ungoverned again minutes later, which is the one outcome this
    // product cannot have. Claude Code, checked the same way, keeps the entry.
    'claude-desktop': { detect: [desktopMac, desktopWin, desktopLin], write: pick(desktopMac, desktopWin, desktopLin), quitFirst: 'Claude Desktop' },
    cursor: {
      detect: [cursorHome, path.join(home, 'Library', 'Application Support', 'Cursor', 'User', 'mcp.json'), path.join(appData, 'Cursor', 'User', 'mcp.json')],
      write: cursorHome
    },
    // User-scope MCP servers for the CLI live in ~/.claude.json. settings.json is
    // read as well, since a hand-written entry there is worth reporting, but it is
    // not where the CLI picks one up, so it is never the write target.
    'claude-code': { detect: [path.join(home, '.claude', 'settings.json'), path.join(home, '.claude.json')], write: path.join(home, '.claude.json') },
    windsurf: { detect: [windsurfHome], write: windsurfHome }
  }
}

// Where a client leaves a trace when it is NOT running. A person can install an
// AI client and open it once a month; the machine still carries it, and an
// inventory that only lists what happens to be running today misses it.
//
// Two kinds of evidence, both userland. The application itself, whose macOS
// location is verified here; and the data directory the client creates on first
// use, which is the cross-platform half and is already the table the MCP checks
// walk. Windows and Linux application paths follow the documented layout but are
// not verified on this machine, so they can only add a find, never remove one.
function installPaths (home, appData) {
  const local = process.env.LOCALAPPDATA || path.join(home, 'AppData', 'Local')
  const apps = (name) => [
    path.join('/Applications', name + '.app'),
    path.join(home, 'Applications', name + '.app'),
    path.join(local, 'Programs', name),
    path.join(home, '.local', 'share', 'applications', name.toLowerCase() + '.desktop')
  ]
  const sup = (...p) => [path.join(home, 'Library', 'Application Support', ...p), path.join(appData, ...p), path.join(home, '.config', ...p)]
  return {
    'claude-desktop': [...apps('Claude'), ...sup('Claude')],
    chatgpt: [...apps('ChatGPT'), ...sup('ChatGPT'), ...sup('com.openai.chat')],
    cursor: [...apps('Cursor'), ...sup('Cursor'), path.join(home, '.cursor')],
    windsurf: [...apps('Windsurf'), ...sup('Windsurf'), path.join(home, '.codeium', 'windsurf')],
    'claude-code': [path.join(home, '.claude'), path.join(home, '.claude.json')],
    'gemini-cli': [path.join(home, '.gemini')],
    'copilot-cli': [process.env.COPILOT_HOME || path.join(home, '.copilot')],
    augment: [path.join(home, '.augment')],
    codex: [path.join(home, '.codex')],
    ollama: [...apps('Ollama'), path.join(home, '.ollama')],
    lmstudio: [...apps('LM Studio'), path.join(home, '.lmstudio'), ...sup('LM Studio')],
    // The applications added on 2026-10-09, by their bundle on a Mac and the
    // documented per-user layout elsewhere. The data folders of the command
    // lines below are their own documented homes.
    'chatgpt-atlas': apps('ChatGPT Atlas'),
    perplexity: [...apps('Perplexity'), ...sup('Perplexity')],
    comet: apps('Comet'),
    'microsoft-copilot': apps('Copilot'),
    'codex-computer-use': [path.join(home, '.codex', 'computer-use', 'Codex Computer Use.app')],
    goose: [...apps('Goose'), path.join(home, '.config', 'goose')],
    opencode: [path.join(home, '.config', 'opencode')],
    aider: [path.join(home, '.aider.conf.yml')],
    kiro: [...apps('Kiro'), path.join(home, '.kiro')],
    trae: [...apps('Trae'), ...sup('Trae')],
    jan: [...apps('Jan'), ...sup('Jan')],
    gpt4all: [...apps('GPT4All'), ...sup('nomic.ai', 'GPT4All')],
    msty: [...apps('Msty'), ...sup('Msty')],
    anythingllm: [...apps('AnythingLLM'), ...sup('anythingllm-desktop')],
    raycast: apps('Raycast'),
    warp: apps('Warp'),
    zed: apps('Zed')
  }
}

function installedClients (home, appData) {
  const found = {}
  for (const [id, paths] of Object.entries(installPaths(home, appData))) {
    const hit = paths.find(p => fs.existsSync(p))
    if (hit) found[id] = hit
  }
  return found
}

// ── Who an executable is, beyond its name ────────────────────────────────────
// A process is first recognised by its executable's name (CATALOG). A renamed
// binary, or an application by a maker the names do not list, passed unseen
// (founder, 2026-10-09: "tout ce qui n'est pas dans la liste passe"). So an
// executable the names miss is read once more, from what the file carries and a
// rename keeps:
//   macOS    the application it belongs to (its bundle's name and identifier,
//            from Info.plist) and the organisation that signed it (codesign)
//   Windows  the product, original file name and company its version
//            information declares (one PowerShell call for every process)
//   Linux    nothing more: an executable is known by its name only
// Read, never written. System locations are skipped, and each executable is
// read once per scan.
// A function, not a pattern with a lookahead, so the Go agent reads it the same way.
const SYSTEM_PREFIXES = ['/System/', '/sbin/', '/bin/', '/Library/Apple/', '/private/var/db/', '/Library/Developer/CommandLineTools/']
const isSystemExe = (f) => SYSTEM_PREFIXES.some(x => f.startsWith(x)) || (f.startsWith('/usr/') && !f.startsWith('/usr/local/')) || /^[A-Za-z]:\\Windows\\/i.test(f)
// Makers whose signature alone says what an executable is.
const SIGNERS = [
  { re: /\bAnysphere\b/i, id: 'cursor' },
  { re: /\b(?:Exafunction|Codeium)\b/i, id: 'windsurf' },
  { re: /\bPerplexity\b/i, id: 'perplexity' },
  { re: /\bOllama\b/i, id: 'ollama' },
  { re: /\bElement Labs\b/i, id: 'lmstudio' },
  { re: /\bOpenAI\b/i, id: 'openai-app' },
  { re: /\bAnthropic\b/i, id: 'anthropic-app' },
  { re: /\bMistral AI\b/i, id: 'mistral-app' }
]
// Both streams: codesign says what it found on stderr, and succeeds.
const runQuiet = (cmd, argv, timeout = 5000) => {
  const r = spawnSync(cmd, argv, { encoding: 'utf8', timeout, maxBuffer: 16 << 20 })
  return String(r.stdout || '') + String(r.stderr || '')
}

// The bundle an executable belongs to: the innermost .app holding it.
function bundleOf (exe) {
  const i = exe.lastIndexOf('.app/')
  return i > 0 ? exe.slice(0, i + 4) : null
}
function plistKey (bundle, key) {
  const v = runQuiet('/usr/bin/plutil', ['-extract', key, 'raw', '-o', '-', path.join(bundle, 'Contents', 'Info.plist')]).trim()
  return v && !/^(?:<stdin>|Error|.*: )/.test(v) && !v.includes('No value at that key path') ? v : null
}
// The organisation in a code signature's leaf certificate, without the
// certificate kind and the team: "Developer ID Application: OpenAI OpCo, LLC
// (2DC432GLL2)" reads "OpenAI OpCo, LLC".
function signerOf (file) {
  const m = /^Authority=(.+)$/m.exec(runQuiet('/usr/bin/codesign', ['-dv', '--verbose=2', file]))
  if (!m) return null
  return m[1].replace(/^(?:Developer ID Application|Apple Development|Apple Distribution|Mac App Distribution|3rd Party Mac Developer Application): /, '').replace(/ \([A-Z0-9]{10}\)$/, '').trim() || null
}
let winIdentity = null
// Windows: every process's product, original file name and company, at once.
function windowsIdentities () {
  if (winIdentity) return winIdentity
  winIdentity = new Map()
  const ps = 'Get-Process | Where-Object { $_.Path } | ForEach-Object { $v = $_.MainModule.FileVersionInfo; [pscustomobject]@{ pid = [string]$_.Id; path = $_.Path; company = $v.CompanyName; product = $v.ProductName; original = $v.OriginalFilename; description = $v.FileDescription } } | ConvertTo-Json -Compress'
  try {
    const list = JSON.parse(runQuiet('powershell', ['-NoProfile', '-NonInteractive', '-Command', ps], 20000) || '[]')
    for (const x of Array.isArray(list) ? list : [list]) if (x && x.pid) winIdentity.set(String(x.pid), x)
  } catch { /* PowerShell absent or refused: names only */ }
  return winIdentity
}
const identityCache = new Map()
// What the file says it is: { name, org, bundle } or null. name is a product
// or application name, org the signer or declared company.
function identityOf (p) {
  if (process.platform === 'win32') {
    const w = windowsIdentities().get(String(p.pid))
    if (!w || isSystemExe(w.path || '')) return null
    const name = [w.product, w.original, w.description].map(v => String(v || '').replace(/\.exe$/i, '').trim()).find(Boolean) || null
    const names = [...new Set([w.product, w.original, w.description].map(v => String(v || '').replace(/\.exe$/i, '').trim()).filter(Boolean))]
    return name || w.company ? { name, names, org: w.company || null, bundle: null, signed: false } : null
  }
  if (process.platform !== 'darwin') return null
  const exe = p.exe
  if (!exe || !exe.startsWith('/') || isSystemExe(exe)) return null
  if (identityCache.has(exe)) return identityCache.get(exe)
  const bundle = bundleOf(exe)
  const names = bundle ? [...new Set([plistKey(bundle, 'CFBundleDisplayName'), plistKey(bundle, 'CFBundleName')].filter(Boolean))] : []
  const id = bundle ? plistKey(bundle, 'CFBundleIdentifier') : null
  const org = signerOf(exe)
  const out = (names.length || org) ? { name: names[0] || null, names, org, bundle: id, signed: !!org } : null
  identityCache.set(exe, out)
  return out
}
// What one file says it is, without a running process (--identify).
function identityOfFile (file) {
  if (process.platform === 'win32') {
    const ps = `$v = (Get-Item -LiteralPath '${String(file).replace(/'/g, "''")}').VersionInfo; [pscustomobject]@{ company = $v.CompanyName; product = $v.ProductName; original = $v.OriginalFilename; description = $v.FileDescription } | ConvertTo-Json -Compress`
    try {
      const w = JSON.parse(runQuiet('powershell', ['-NoProfile', '-NonInteractive', '-Command', ps], 20000) || 'null')
      if (!w) return null
      const names = [...new Set([w.product, w.original, w.description].map(v => String(v || '').replace(/\.exe$/i, '').trim()).filter(Boolean))]
      return names.length || w.company ? { name: names[0] || null, names, org: w.company || null, bundle: null, signed: false } : null
    } catch { return null }
  }
  return identityOf({ pid: null, exe: file })
}

// The catalog entry an identity names: by an application name first, then by a
// maker whose every product is AI.
function entryOfIdentity (ident) {
  if (!ident) return null
  const wanted = ident.names.map(n => n.toLowerCase())
  const byName = CATALOG.find(e => (e.names || []).some(n => wanted.includes(n)))
  if (byName) return { entry: byName, by: `its application name (${ident.names.find(n => (byName.names || []).includes(n.toLowerCase()))})` }
  const signer = ident.org && SIGNERS.find(s => s.re.test(ident.org))
  // A Mac reads the organisation that signed the file; Windows, the company the
  // file declares, which is weaker and said so.
  if (signer) return { entry: CATALOG.find(e => e.id === signer.id), by: `${ident.signed ? 'its signature' : 'its declared maker'} (${ident.org})` }
  return null
}
// The entry a process is: its name, unless the file says otherwise, then what
// the file says. Returns { entry, by } (by is null for a match on the name).
function entryOfProcess (p) {
  for (const entry of CATALOG) {
    if (!entry.re || !entry.re.test(entry.inArgs ? p.cmd : p.exe)) continue
    if (entry.unless) {
      const ident = identityOf(p)
      if (ident && ident.org && entry.unless.test(ident.org)) continue
    }
    return { entry, by: null }
  }
  return entryOfIdentity(identityOf(p))
}

function listProcesses () {
  try {
    if (process.platform === 'win32') {
      const out = execFileSync('tasklist', ['/fo', 'csv', '/nh'], { encoding: 'utf8', maxBuffer: 8 << 20 })
      return out.split(/\r?\n/).filter(Boolean).map(line => {
        const f = line.match(/"([^"]*)"/g)?.map(s => s.slice(1, -1)) || []
        const name = f[0] || ''
        return { pid: f[1] || '?', cmd: name, exe: name } // Windows: tasklist gives the exe name
      })
    }
    // Two passes on purpose. `command=` is the full line, which is what the
    // interpreter-style entries need. `comm=` is what ps itself considers the
    // executable that was run, and it stays correct where any parse of the
    // command line fails: a path with spaces, or a process with no flags to cut
    // at. Both are rendered last and unbounded, so a single split works.
    const byPid = (args) => {
      const out = execFileSync('ps', args, { encoding: 'utf8', maxBuffer: 16 << 20 })
      const m = new Map()
      for (const line of out.split('\n')) {
        const t = line.trim(); if (!t) continue
        const sp = t.indexOf(' ')
        if (sp > 0) m.set(t.slice(0, sp), t.slice(sp + 1).trim())
      }
      return m
    }
    const cmds = byPid(['-axww', '-o', 'pid=,command='])
    let exes = new Map()
    try { exes = byPid(['-axww', '-o', 'pid=,comm=']) } catch { /* fall back to the command line below */ }
    return [...cmds].map(([pid, cmd]) => ({ pid, cmd, exe: exes.get(pid) || cmd }))
  } catch { return [] }
}

// ── Machine-level signals: is an LLM gateway configured, and does any known
// desktop client route its MCP through Clevr?
function readJson (p) { try { return JSON.parse(fs.readFileSync(p, 'utf8')) } catch { return null } }
// Does this config point the client at Clevr?
//
// NOT "does the word clevr appear somewhere in the file". That question returns
// true for a folder path, a plugin name or a stale entry aimed at a host that no
// longer exists, and answering GOVERNED on any of those is a false green on a
// machine with no governance at all. For a security product that is the worst
// possible error, so the check reads the MCP server list and nothing else.
//
// A file that parses but declares no MCP server is a DEFINITE no, not an unknown:
// there is no server to route through. A file we cannot parse is an unknown, and
// unknown is not governed: otherwise a machine turns itself green by corrupting
// its own config. It is reported as shadow, with the reason on the line.
// Where a client keeps its HOOKS, which is a different and deeper thing than an
// MCP server entry. A hook runs inside the harness, before the tool call, in a
// separate process outside the model, so an injection cannot talk its way past
// it and the client rewriting its own configuration does not silently remove it.
// An MCP entry governs only what goes through that one server, and the client
// can take it back. Reporting both as plain "governed" flattened the difference
// that matters most on a machine.
function hookPaths (home) {
  return {
    'claude-code': [path.join(home, '.claude', 'settings.json')],
    cursor: [path.join(home, '.cursor', 'hooks.json')],
    'copilot-cli': [path.join(process.env.COPILOT_HOME || path.join(home, '.copilot'), 'hooks', 'clevr.json')],
    augment: [path.join(home, '.augment', 'settings.json')],
    'gemini-cli': [path.join(home, '.gemini', 'settings.json')],
    // Codex gained hooks in May 2026 (PreToolUse denies a call before it runs),
    // and the ChatGPT desktop app runs the same Codex from the same file. Before
    // that it was read at gateway depth only, which was the honest depth then.
    codex: [path.join(home, '.codex', 'hooks.json')],
    // The ChatGPT desktop app IS that Codex: same binary, same file. Measured
    // with the hooks trusted and refusing a command inside the app, the app's
    // own line still read shadow because only the CLI entry looked at the file.
    chatgpt: [path.join(home, '.codex', 'hooks.json')]
  }
}

// A gate script: a script Clevr installs for a harness with no hook, which
// governs only the commands a person wraps with it by hand. It is NOT governance
// of the machine, and the verdict does not move for it. It is reported because a
// screen that says nothing right after a successful install reads as a failure,
// and because "installed but nothing calls it" is the honest state.
function wrapperGatePaths (home) {
  // Empty since Codex gained real hooks: no harness Clevr supports is left with
  // only a wrapper gate. Kept as a table so the next hook-less harness has a
  // place to go without reviving the code path.
  void home
  return {}
}

// A harness governed through the gateway rather than a hook. Codex is the case:
// the block we write into its config points its model traffic at Clevr, which
// covers the conversation and not the local command.
function gatewayConfigPaths (home) {
  return {
    codex: [path.join(home, '.codex', 'config.toml')]
  }
}

// The Codex config is TOML, so there is no object to walk. The block we write is
// fenced by markers, and only that fence counts: the word appearing anywhere
// else in the file is not a configuration.
function gatewayGoverns (file) {
  try {
    const raw = fs.readFileSync(file, 'utf8')
    const i = raw.indexOf('# --- clevr begin ---')
    if (i < 0) return { governed: false }
    if (raw.indexOf('# --- clevr end ---', i) < 0) return { governed: false }
    return { governed: true, via: 'model provider block in ' + path.basename(file) }
  } catch { return { governed: false } }
}

// Read the hook and plugin declarations, nothing else. A marker anywhere in the
// file is the mistake this whole component already made once.
function hookGoverns (file) {
  let doc
  try { doc = JSON.parse(fs.readFileSync(file, 'utf8')) } catch { return { governed: false } }
  if (!doc || typeof doc !== 'object' || Array.isArray(doc)) return { governed: false }

  const plugins = doc.enabledPlugins
  if (plugins && typeof plugins === 'object') {
    for (const [name, on] of Object.entries(plugins)) {
      if (on && name.toLowerCase().includes(MCP_MARKER)) return { governed: true, via: 'plugin ' + name }
    }
  }
  // Hook declarations: an object of event -> entries, each naming a command. The
  // key that holds it differs per harness: `command` for most, and `bash` plus
  // `powershell` for the Copilot CLI. Reading only `command` missed a hook our
  // own installer had just written.
  //
  // A whitelist rather than every string in the subtree, because an entry also
  // carries a working directory, and a project path that happened to contain the
  // marker would then read as an installed hook.
  const COMMAND_KEYS = new Set(['command', 'bash', 'powershell', 'sh', 'cmd', 'exec', 'script', 'args'])
  const commands = []
  const walk = (v, depth, underCommandKey) => {
    if (depth > 6 || !v) return
    if (typeof v === 'string') { if (underCommandKey) commands.push(v); return }
    if (Array.isArray(v)) { for (const x of v) walk(x, depth + 1, underCommandKey); return }
    // Sorted, so the command this line names does not depend on the order the
    // harness happens to write its events in, and the two agents agree.
    if (typeof v === 'object') for (const [k, x] of Object.entries(v).sort((a, b) => a[0] < b[0] ? -1 : 1)) walk(x, depth + 1, COMMAND_KEYS.has(k))
  }
  walk(doc.hooks, 0, false)
  const hit = commands.find(c => c.toLowerCase().includes(MCP_MARKER))
  // The line quotes the command; a key someone inlined in it must not travel
  // to the fleet view. Seen on a machine whose hooks carried the env inline.
  return hit ? { governed: true, via: 'hook ' + hit.replace(/clevr_sk_[A-Za-z0-9_-]+/g, 'clevr_sk_…').slice(0, 80) } : { governed: false }
}

// Codex runs a hook only after the person has trusted it once (the TUI asks at
// startup and records a hash per hook under [hooks.state."<file>:<event>:<entry>:
// <handler>"] in config.toml). Until then the hook is listed and skipped without
// a word: measured on the ChatGPT desktop app, the command the gate should have
// refused ran. So a Clevr hook in the file is not governance until its slot has
// a trust record. The hash is Codex's own and not reproducible here; presence
// is what can be read, and Codex re-asks by itself when a hook changes.
const codexEventKey = (event) => event.replace(/([a-z0-9])([A-Z])/g, '$1_$2').toLowerCase()
function codexHooksUntrusted (home, hooksFile) {
  let doc, toml
  try { doc = JSON.parse(fs.readFileSync(hooksFile, 'utf8')) } catch { return false }
  try { toml = fs.readFileSync(path.join(home, '.codex', 'config.toml'), 'utf8') } catch { toml = '' }
  let ours = 0; let missing = 0
  for (const [event, entries] of Object.entries(doc?.hooks || {})) {
    if (!Array.isArray(entries)) continue
    entries.forEach((entry, i) => {
      (Array.isArray(entry?.hooks) ? entry.hooks : []).forEach((h, j) => {
        if (!String(h?.command || '').toLowerCase().includes(MCP_MARKER)) return
        ours++
        const key = '[hooks.state."' + hooksFile + ':' + codexEventKey(event) + ':' + i + ':' + j + '"]'
        const at = toml.indexOf(key)
        if (at < 0 || !/^\s*trusted_hash\s*=\s*"/m.test(toml.slice(at + key.length, at + key.length + 200))) missing++
      })
    })
  }
  return ours > 0 && missing > 0
}

function configPointsAtClevr (file) {
  let raw
  try { raw = fs.readFileSync(file, 'utf8') } catch { return { governed: false } }
  let doc
  try { doc = JSON.parse(raw) } catch {
    return { governed: false, unparsed: true, names: raw.toLowerCase().includes(MCP_MARKER) }
  }
  const servers = doc && typeof doc === 'object' && !Array.isArray(doc) && doc.mcpServers
  if (!servers || typeof servers !== 'object' || Array.isArray(servers)) return { governed: false }

  // Two entries can both name Clevr and they are NOT the same control.
  //
  // The GUARD wraps another server: the client's own tool calls pass through it,
  // and a blocked call never reaches the tool. That is enforcement.
  //
  // The Clevr MCP SERVER, added as one more server, exposes two tools: one to ask
  // for a verdict and one to look a resource up. A client that has it CAN ask;
  // nothing obliges it to and nothing stops it if it does not. That is advisory,
  // and calling it governed put a green tag where Clevr gates nothing.
  //
  // The guard wins when both are present, because it is the one that stops a call.
  let advisory = null
  for (const entry of Object.values(servers)) {
    if (!entry || typeof entry !== 'object') continue
    const url = typeof entry.url === 'string' ? entry.url : ''
    if (url) {
      const ours = clevrHosts()
      const mine = ours.size ? ours.has(hostOf(url)) : url.toLowerCase().includes(MCP_MARKER)
      if (mine && !advisory) advisory = { governed: true, enforcing: false, via: url }
      continue
    }
    const cmd = [entry.command, ...(Array.isArray(entry.args) ? entry.args : [])].join(' ').toLowerCase()
    if (cmd.includes(MCP_MARKER)) return { governed: true, enforcing: true, via: 'local guard command' }
  }
  return advisory || { governed: false }
}

// The MCP servers none of the paths above name.
//
// Claude Code loads them from three places and the agent read one of them:
// ~/.claude.json's top level. The other two are a `.mcp.json`, user-level or
// checked in beside a project, and the per-project LOCAL scope that
// ~/.claude.json itself keeps under projects[<root>].mcpServers, which is where
// `claude mcp add` puts a server by default. Measured on a real machine
// 2026-09-18: ~/.mcp.json had declared an HTTP MCP server since 11 July, the CLI
// listed it as a live server, and this agent reported the machine without it. An
// ungoverned MCP server the inventory calls absent is the exact failure this
// component exists to prevent.
//
// These are reported as SURFACE and never folded into a client's governance
// verdict. A `.mcp.json` entry applies where that file applies, so a Clevr guard
// in one project's file governs that project and not the machine; counting it as
// "Claude Code is governed" would replace a blind spot with a false green. The
// write target stays ~/.claude.json for the same reason.
//
// The roots come from ~/.claude.json's own `projects` map, so this reads a bounded
// list of paths the CLI already knows. It never walks the filesystem looking for
// them: a crawl is slow, needs reach this agent should not have, and would report
// a checked-out repo nobody has opened.
function mcpJsonSources (home) {
  const claudeJson = path.join(home, '.claude.json')
  const cfg = readJson(claudeJson)
  const projects = cfg && typeof cfg.projects === 'object' && !Array.isArray(cfg.projects) ? cfg.projects : {}
  // Sorted, not in the file's own order: Go ranges a map at random, so the two
  // agents only produce comparable reports if both sort. Same for the server
  // names below.
  const roots = Object.keys(projects).filter(r => typeof r === 'string' && r).sort()
  // The home directory is a project root like any other, and on the machine this
  // was measured on it is one. Emitting ~/.mcp.json as the user-level file AND
  // again as that root's shared file put one server on two rows carrying two
  // different approval states, and counted it twice in the fleet total. It is
  // emitted once, carrying the project entry when there is one, because that is
  // where the acceptance is recorded and so it is the only row that can say
  // whether the server actually loads.
  const homeFile = path.join(home, '.mcp.json')
  const out = [{ file: homeFile, project: roots.includes(home) ? home : null, scope: 'user' }]
  for (const root of roots) {
    const shared = path.join(root, '.mcp.json')
    if (shared !== homeFile) out.push({ file: shared, project: root, scope: 'shared' })
    // Local scope: not a file of its own, a branch of ~/.claude.json. Read from
    // the object rather than from disk, and carried here so one loop covers all
    // three origins instead of a second one that could drift from this.
    const local = projects[root] && typeof projects[root].mcpServers === 'object' && !Array.isArray(projects[root].mcpServers)
      ? projects[root].mcpServers : null
    if (local) out.push({ file: claudeJson, project: root, scope: 'local', servers: local })
  }
  return out
}

// A server in one of those files is not live until the person accepts it, and the
// answer sits in ~/.claude.json next to the project. Pending is reported as its
// own state rather than collapsed into yes or no: accepting is one keystroke, so
// calling it inactive understates it, and calling it active claims something that
// has not happened.
function mcpJsonApproval (cfg, project, name, scope) {
  // Local scope is what `claude mcp add` writes for the person who ran it. There
  // is no prompt to accept and no enabled/disabled list to consult: it is theirs
  // and it is live, so reporting it as pending would invent a question nobody
  // was asked.
  if (scope === 'local') return 'enabled'
  const p = project && cfg && cfg.projects ? cfg.projects[project] : null
  const on = Array.isArray(p?.enabledMcpjsonServers) ? p.enabledMcpjsonServers : []
  const off = Array.isArray(p?.disabledMcpjsonServers) ? p.disabledMcpjsonServers : []
  if (off.includes(name)) return 'disabled'
  if (on.includes(name)) return 'enabled'
  return 'pending'
}

function mcpJsonServers (home) {
  const cfg = readJson(path.join(home, '.claude.json'))
  const found = []
  for (const src of mcpJsonSources(home)) {
    let servers = src.servers || null
    if (!servers) {
      if (!fs.existsSync(src.file)) continue
      const doc = readJson(src.file)
      if (!doc) { found.push({ file: src.file, project: src.project, scope: src.scope, clevr: false, unparsed: true }); continue }
      servers = typeof doc.mcpServers === 'object' && !Array.isArray(doc.mcpServers) ? doc.mcpServers : null
    }
    if (!servers) continue
    for (const name of Object.keys(servers).sort()) {
      const entry = servers[name]
      if (!entry || typeof entry !== 'object') continue
      const url = typeof entry.url === 'string' ? entry.url : ''
      const cmd = [entry.command, ...(Array.isArray(entry.args) ? entry.args : [])].filter(Boolean).join(' ')
      const ours = clevrHosts()
      const clevr = url
        ? (ours.size ? ours.has(hostOf(url)) : url.toLowerCase().includes(MCP_MARKER))
        : cmd.toLowerCase().includes(MCP_MARKER)
      found.push({
        file: src.file,
        project: src.project,
        name,
        transport: url ? 'http' : cmd ? 'stdio' : 'unknown',
        target: (url || cmd).slice(0, 120) || null,
        scope: src.scope,
        approval: mcpJsonApproval(cfg, src.project, name, src.scope),
        clevr
      })
    }
  }
  return found
}

// ── Skills on this machine ──────────────────────────────────────────────────
// A skill is a folder holding a SKILL.md: instructions an agent loads to do a
// task its way. The plugins report the skills an agent LOADS; this lists the
// ones INSTALLED, read from the folders each tool reads, so a skill shows up
// before anyone uses it, and on a tool whose loads no hook sees (Copilot hands a
// skill to the model without a tool call). Read, never written. Each one comes
// with the version of its files, the fingerprint the plugins compute (sha256
// over "path\0sha256\n" of every file, in byte order), so the console can say
// which machines hold a version nobody approved.
//
// The roots are the folders each tool documents: a person's own, the
// administrator's, those of the plugins Claude Code and Codex installed and of
// Gemini CLI's extensions, and the projects ~/.claude.json already knows. Never
// a crawl, for the reason the .mcp.json reading gives above.
const SKILL_SKIP = new Set(['.git', 'node_modules', '.DS_Store', '.clevr-skill.json'])
const SKILL_MAX_FILES = 200
const SKILL_MAX_BYTES = 5 * 1024 * 1024
const SKILLS_MAX = 300
const byteOrder = (a, b) => (a < b ? -1 : a > b ? 1 : 0)
const sha256 = (buf) => crypto.createHash('sha256').update(buf).digest('hex')

function subdirs (dir) {
  try {
    return fs.readdirSync(dir, { withFileTypes: true }).filter(e => e.isDirectory() && !e.name.startsWith('.')).map(e => e.name).sort(byteOrder)
  } catch { return [] }
}

function skillRootsOnMachine (home) {
  const roots = [
    { dir: path.join(home, '.claude', 'skills'), scope: 'personal', tools: ['Claude Code', 'Cursor'] },
    { dir: path.join(home, '.agents', 'skills'), scope: 'personal', tools: ['Codex', 'Cursor', 'Copilot', 'Gemini CLI'] },
    { dir: path.join(home, '.codex', 'skills'), scope: 'personal', tools: ['Codex', 'Cursor'] },
    { dir: path.join(home, '.codex', 'skills', '.system'), scope: 'built-in', tools: ['Codex'] },
    { dir: path.join(home, '.cursor', 'skills'), scope: 'personal', tools: ['Cursor'] },
    { dir: path.join(home, '.gemini', 'skills'), scope: 'personal', tools: ['Gemini CLI'] },
    { dir: path.join(home, '.copilot', 'skills'), scope: 'personal', tools: ['Copilot'] },
  ]
  // The administrator's folders, which outrank a person's own.
  if (process.platform === 'darwin') roots.push({ dir: '/Library/Application Support/ClaudeCode/.claude/skills', scope: 'administrator', tools: ['Claude Code'] })
  else if (process.platform === 'win32') roots.push({ dir: 'C:\\Program Files\\ClaudeCode\\.claude\\skills', scope: 'administrator', tools: ['Claude Code'] })
  else roots.push({ dir: '/etc/claude-code/.claude/skills', scope: 'administrator', tools: ['Claude Code'] })
  if (process.platform !== 'win32') roots.push({ dir: '/etc/codex/skills', scope: 'administrator', tools: ['Codex'] })
  // Plugins: Claude Code's own registry, then the newest copy of each plugin in
  // Codex's cache, then Gemini CLI's extensions. A plugin's skill is named
  // plugin:name, as Claude Code names it.
  const reg = readJson(path.join(home, '.claude', 'plugins', 'installed_plugins.json'))
  const plugins = reg && typeof reg.plugins === 'object' && reg.plugins ? reg.plugins : {}
  for (const key of Object.keys(plugins).sort(byteOrder)) {
    const entries = Array.isArray(plugins[key]) ? plugins[key] : [plugins[key]]
    for (const e of entries) {
      if (e && typeof e.installPath === 'string') roots.push({ dir: path.join(e.installPath, 'skills'), scope: 'plugin', tools: ['Claude Code'], plugin: key.split('@')[0] })
    }
  }
  const codexCache = path.join(home, '.codex', 'plugins', 'cache')
  for (const market of subdirs(codexCache)) {
    for (const plugin of subdirs(path.join(codexCache, market))) {
      const versions = subdirs(path.join(codexCache, market, plugin))
      if (versions.length) roots.push({ dir: path.join(codexCache, market, plugin, versions[versions.length - 1], 'skills'), scope: 'plugin', tools: ['Codex'], plugin })
    }
  }
  const gemExt = path.join(home, '.gemini', 'extensions')
  for (const ext of subdirs(gemExt)) roots.push({ dir: path.join(gemExt, ext, 'skills'), scope: 'plugin', tools: ['Gemini CLI'], plugin: ext })
  // The projects Claude Code knows, bounded.
  const cj = readJson(path.join(home, '.claude.json'))
  const projects = cj && typeof cj.projects === 'object' && !Array.isArray(cj.projects) && cj.projects ? Object.keys(cj.projects).filter(Boolean).sort(byteOrder).slice(0, 100) : []
  for (const root of projects) {
    for (const [sub, tools] of [
      [path.join('.claude', 'skills'), ['Claude Code', 'Cursor', 'Copilot']],
      [path.join('.agents', 'skills'), ['Codex', 'Cursor', 'Copilot', 'Gemini CLI']],
      [path.join('.cursor', 'skills'), ['Cursor']],
      [path.join('.github', 'skills'), ['Copilot']],
      [path.join('.gemini', 'skills'), ['Gemini CLI']],
    ]) {
      const dir = path.join(root, sub)
      if (!roots.some(r => r.dir === dir)) roots.push({ dir, scope: 'project', tools, project: root })
    }
  }
  return roots
}

// The description line of a SKILL.md's front matter.
function skillDescription (text) {
  const lines = String(text).slice(0, 64 * 1024).split('\n').map(l => l.replace(/\r$/, ''))
  if (lines[0] !== '---') return null
  for (let i = 1; i < lines.length && lines[i] !== '---'; i++) {
    if (!lines[i].startsWith('description:')) continue
    const v = lines[i].slice('description:'.length).trim().replace(/^["']|["']$/g, '')
    return v ? v.slice(0, 300) : null
  }
  return null
}

// The version of a skill's files, as the plugins compute it.
function skillVersion (dir) {
  const files = []
  let bytes = 0, partial = false
  const walk = (d) => {
    for (const ent of fs.readdirSync(d, { withFileTypes: true }).sort((a, b) => byteOrder(a.name, b.name))) {
      if (SKILL_SKIP.has(ent.name)) continue
      const abs = path.join(d, ent.name)
      const st = fs.lstatSync(abs)
      if (st.isSymbolicLink()) continue
      if (st.isDirectory()) { walk(abs); continue }
      if (!st.isFile()) continue
      if (files.length >= SKILL_MAX_FILES) { partial = true; continue }
      const buf = fs.readFileSync(abs)
      if (bytes + buf.length > SKILL_MAX_BYTES) { partial = true; continue }
      bytes += buf.length
      files.push({ path: path.relative(dir, abs).split(path.sep).join('/'), sha256: sha256(buf) })
    }
  }
  let description = null
  try {
    walk(dir)
    description = skillDescription(fs.readFileSync(path.join(dir, 'SKILL.md'), 'utf8'))
  } catch { return { fingerprint: null, files: files.length, partial: true, description: null } }
  files.sort((a, b) => byteOrder(a.path, b.path))
  return { fingerprint: sha256(files.map(f => `${f.path}\0${f.sha256}\n`).join('')), files: files.length, partial, description }
}

function skillsOnMachine (home) {
  const out = []
  const seen = new Set()
  for (const r of skillRootsOnMachine(home)) {
    for (const n of subdirs(r.dir)) {
      const dir = path.join(r.dir, n)
      if (seen.has(dir)) continue
      let st
      try { st = fs.lstatSync(dir) } catch { continue }
      if (st.isSymbolicLink() || !fs.existsSync(path.join(dir, 'SKILL.md'))) continue
      seen.add(dir)
      out.push({
        name: r.plugin ? `${r.plugin}:${n}` : n,
        scope: r.scope,
        tools: r.tools,
        project: r.project || null,
        path: dir,
        ...skillVersion(dir),
        // Written by the Clevr plugin as the workspace distributed it.
        clevr: fs.existsSync(path.join(dir, '.clevr-skill.json')),
      })
      if (out.length >= SKILLS_MAX) return out
    }
  }
  return out
}

function printSkills (skills) {
  if (!skills.length) return
  console.log(`${'-'.repeat(70)}`)
  console.log('Skills on this machine')
  for (const s of skills.slice(0, 40)) {
    const where = s.scope === 'project' ? `project ${s.project}` : s.scope
    console.log(`[${s.clevr ? 'CLEVR   ' : 'SKILL   '}] ${s.name}  (${where}; ${s.tools.join(', ')})  ${s.fingerprint ? s.fingerprint.slice(0, 12) : 'unreadable'}`)
  }
  if (skills.length > 40) console.log(`and ${skills.length - 40} more`)
  console.log('Read, never written. Each skill is listed with the version of its files; whether that')
  console.log('version is approved, and which agents may load it, is answered in Clevr.')
}

function machineSignals () {
  const home = os.homedir()
  const appData = process.env.APPDATA || path.join(home, 'AppData', 'Roaming')
  const llmBase = process.env.ANTHROPIC_BASE_URL || process.env.OPENAI_BASE_URL || process.env.CLEVR_LLM_BASE_URL || ''
  const llmHost = hostOf(llmBase)
  const llmGateway = {
    configured: !!llmBase,
    url: llmBase || null,
    routesClevr: !!(llmBase && CLEVR_HOST && llmHost === CLEVR_HOST)
  }
  const cfg = configPaths(home, appData)
  const mcp = {}
  for (const [id, c] of Object.entries(cfg)) {
    mcp[id] = { governed: false }
    for (const f of c.detect) {
      if (!fs.existsSync(f)) continue
      const r = configPointsAtClevr(f)
      if (r.governed) { mcp[id] = { ...r, file: f }; break }
      // Not governed, but worth saying why: a config naming Clevr that we could
      // not read is a question mark, and a question mark belongs on the screen.
      if (r.unparsed && r.names && !mcp[id].unparsed) mcp[id] = { ...r, file: f }
    }
  }
  const hook = {}
  for (const [id, files] of Object.entries(hookPaths(home))) {
    hook[id] = { governed: false }
    for (const f of files) {
      if (!fs.existsSync(f)) continue
      const r = hookGoverns(f)
      if (r.governed) { hook[id] = { ...r, file: f, ...((id === 'codex' || id === 'chatgpt') && codexHooksUntrusted(home, f) ? { untrusted: true } : {}) }; break }
    }
  }
  const wrapperGate = {}
  for (const [id, files] of Object.entries(wrapperGatePaths(home))) {
    const hit = files.find(f => fs.existsSync(f))
    if (hit) wrapperGate[id] = hit
  }
  const harnessGateway = {}
  for (const [id, files] of Object.entries(gatewayConfigPaths(home))) {
    harnessGateway[id] = { governed: false }
    for (const f of files) {
      if (!fs.existsSync(f)) continue
      const r = gatewayGoverns(f)
      if (r.governed) { harnessGateway[id] = { ...r, file: f }; break }
    }
  }
  return { llmGateway, mcp, hook, harnessGateway, wrapperGate, mcpJson: mcpJsonServers(home), extensions: browserExtensions(home, appData), skills: skillsOnMachine(home) }
}

function assess (entry, sig) {
  const ev = []; let via = 'none'
  const harnessGw = (sig.harnessGateway?.[entry.id] || { governed: false }).governed
  if (harnessGw) ev.push(`This harness's model traffic points at Clevr (${sig.harnessGateway[entry.id].via}). It covers the conversation, not the local command.`)

  const llm = sig.llmGateway.routesClevr || harnessGw
  if (sig.llmGateway.routesClevr) ev.push(`LLM traffic routed through Clevr gateway (${sig.llmGateway.url})`)
  else if (sig.llmGateway.configured) ev.push(`LLM base URL set but points elsewhere (${sig.llmGateway.url})`)

  // Deepest control first. A hook sees every tool call before it runs; an MCP
  // entry sees only what crosses that server; a gateway base URL sees the model
  // hop and not the tool hop. Saying "governed" for all three hid the difference.
  const hookSig = sig.hook?.[entry.id] || { governed: false }
  const hooked = hookSig.governed && !hookSig.untrusted
  if (hooked) ev.push(`Clevr hook installed in this harness: every tool call is checked before it runs (${hookSig.via})`)
  // Installed is not trusted. Codex skips a hook nobody has reviewed and says
  // nothing, so the line says it, and the verdict does not move on the file alone.
  else if (hookSig.governed && hookSig.untrusted) ev.push(`Clevr hook installed in this harness but not yet trusted by Codex, which skips an untrusted hook without saying so: nothing is checked until someone runs codex once and answers "Trust all and continue" (${hookSig.file})`)
  // Claude Desktop is two things. Its Chat tab reaches tools over MCP and has no
  // hook; its Cowork sessions run the Claude Code plugin's hooks. The verdict
  // stays on what governs the connectors; the Cowork half is stated beside it.
  if (entry.id === 'claude-desktop' && sig.hook?.['claude-code']?.governed) {
    ev.push('Cowork sessions in this app run the Claude Code plugin hooks; the Chat tab reaches its connectors over MCP, governed only where the guard wraps them or the gateway fronts them')
  }

  const found = sig.mcp[entry.id] || { governed: false }
  const mcp = found.governed
  if (mcp && found.enforcing) ev.push(`Clevr MCP guard wraps a server in this client's config: a blocked call never reaches the tool (${found.via})`)
  else if (mcp) ev.push(`The Clevr MCP server is configured in this client (${found.via}). It lets the client ASK for a verdict; it does not gate what the client does.`)
  else if (found.unparsed) ev.push(`Config names Clevr but could not be read, so governance is unconfirmed (${found.file})`)

  // A Clevr entry in a .mcp.json or in a project's local scope is real, and it is
  // real WHERE THAT FILE APPLIES. It does not make the client governed on this
  // machine, because the acceptance is recorded per project: the same entry is
  // live in one directory and pending in the next. So it is said on the line
  // rather than counted in the verdict, which is the difference between a machine
  // that looks green and a machine someone can reason about.
  const perProject = (sig.mcpJson || []).filter(m => m.clevr && !m.unparsed && m.approval !== 'disabled')
  if (entry.id === 'claude-code' && perProject.length) {
    const where = perProject.map(m => m.project || 'the user-level file')
    ev.push(`Clevr is configured in ${perProject.length} .mcp.json entr${perProject.length === 1 ? 'y' : 'ies'} (${where.slice(0, 3).join(', ')}${where.length > 3 ? ', …' : ''}). That governs those projects, not this machine, because acceptance is recorded per project.`)
  }

  if (entry.kind === 'local-model') {
    ev.push('Local model runner: no cloud gateway to route through; govern its tool use via a local MCP proxy')
    return { monitored: false, via: 'local', evidence: ev }
  }
  if (entry.kind === 'ai-feature') {
    ev.push('An application with AI built in: whether its AI is used cannot be seen from the machine, so it is listed, not counted as shadow AI')
    return { monitored: false, via: 'feature', evidence: ev }
  }
  // Stated after the verdict lines and never counted into them: a gate nobody
  // calls governs nothing.
  const gate = sig.wrapperGate?.[entry.id]
  if (gate) ev.push(`A Clevr gate script is installed at ${gate}, but nothing invokes it: it governs only the commands you wrap with it by hand.`)

  // Advisory is not governance. A client that can ask for a verdict, with nothing
  // obliging it to ask and nothing stopping it when it does not, is not governed
  // by that alone; it is listed as shadow with the Clevr MCP server named on its line.
  const enforcingMcp = mcp && found.enforcing
  const monitored = !!(hooked || llm || enforcingMcp)
  if (monitored) via = hooked ? 'hook' : enforcingMcp ? 'mcp' : 'llm-gateway'
  if (!monitored) ev.push('No evidence this client routes through Clevr')
  return { monitored, via, evidence: ev }
}

// ── Build one posture report (fresh scan each call, so --watch re-detects).
function buildReport () {
  const sig = machineSignals()
  const procs = listProcesses()
  // One entry per detected AI client (a desktop app spawns many helper
  // processes — count them, don't list the app ten times). First matching
  // process is the representative; `procs` is how many matched.
  const byId = new Map()
  const named = new Set(), seenBy = new Map()
  for (const p of procs) {
    const hit = entryOfProcess(p)
    if (!hit) continue
    const { entry, by } = hit
    let c = byId.get(entry.id)
    if (!c) {
      c = { id: entry.id, label: entry.label, kind: entry.kind, pid: p.pid, procs: 0, ...assess(entry, sig) }
      byId.set(entry.id, c)
    }
    c.procs += 1
    if (!by) named.add(entry.id)
    else if (!seenBy.has(entry.id)) seenBy.set(entry.id, `Recognised by ${by}, running as ${path.basename(p.exe || p.cmd || '?')}`)
  }
  // A client none of whose processes answered to its name (a renamed
  // executable, or one the names do not list) says how it was recognised. One
  // that did, whose helper was found by its bundle, needs no such line.
  for (const [id, line] of seenBy) if (!named.has(id)) byId.get(id).evidence.unshift(line)
  for (const e of CATALOG) {
    const maker = e.family && byId.get(e.id)
    const product = maker && e.family.map(id => byId.get(id)).find(Boolean)
    if (product) { product.procs += maker.procs; byId.delete(e.id) }
  }
  // A client that is installed but closed still belongs in the inventory. It is
  // added after the running ones so the list keeps ps order at the top.
  const installed = installedClients(os.homedir(), process.env.APPDATA || path.join(os.homedir(), 'AppData', 'Roaming'))
  // Sorted, so the order does not depend on how the table above happens to be
  // written, and the two agents produce the same report byte for byte.
  for (const [id, where] of Object.entries(installed).sort((a, b) => a[0] < b[0] ? -1 : 1)) {
    const c = byId.get(id)
    if (c) { c.running = true; c.installed = true; c.installedAt = where; continue }
    const entry = CATALOG.find(e => e.id === id)
    if (!entry) continue
    byId.set(id, {
      id, label: entry.label, kind: entry.kind, pid: null, procs: 0,
      running: false, installed: true, installedAt: where, ...assess(entry, sig)
    })
  }
  for (const c of byId.values()) { if (c.running === undefined) { c.running = true; c.installed = !!installed[c.id] } }

  const clients = [...byId.values()]
  const live = clients.filter(c => c.running)
  const summary = {
    running: live.length,
    present: clients.length,
    monitored: clients.filter(c => c.monitored).length,
    // Kept to its original meaning, running and ungoverned, so the number does
    // not silently change under anyone reading it. What is installed but closed
    // and ungoverned is counted beside it rather than folded in.
    // A local model and an application with AI built in are listed and never
    // counted as shadow AI, as the Go agent always did for local models.
    shadow: live.filter(c => !c.monitored && c.via !== 'local' && c.via !== 'feature').length,
    shadow_installed: clients.filter(c => !c.running && !c.monitored && c.via !== 'local' && c.via !== 'feature').length,
    // Counted apart because it is the strongest thing this machine can say: a
    // hook in the harness checks every tool call before it runs, and no config
    // rewrite quietly removes it.
    hooked: clients.filter(c => c.via === 'hook').length
  }
  return {
    // The host is the machine's own name. CLEVR_ENDPOINT_HOST overrides it for a
    // test rig that must not collide with the real machine's pinned device key
    // (the server refuses a report for a pinned host signed by another key).
    host: process.env.CLEVR_ENDPOINT_HOST || os.hostname(), os: `${process.platform} ${os.release()}`, user: os.userInfo().username,
    version: VERSION, ts: new Date().toISOString(), machine: sig, clients, summary,
    // WHICH TIER IS ACTUALLY IN FORCE, not which one we sent. A local
    // administrator can remove an MDM profile, and a fleet dashboard that shows
    // the tier it deployed is showing its own intention.
    tier: tierInForce()
  }
}

// The managed-settings file the harness really reads, at the paths Anthropic
// documents. NOT the legacy Windows ProgramData location, which is not read —
// a policy file there looks deployed and governs nothing, so finding one is
// worth reporting as a finding rather than as coverage.
const MANAGED_PATHS = process.platform === 'darwin'
  ? ['/Library/Application Support/ClaudeCode/managed-settings.json']
  : process.platform === 'win32'
    ? ['C:\\Program Files\\ClaudeCode\\managed-settings.json']
    : ['/etc/claude-code/managed-settings.json']
const LEGACY_WIN = 'C:\\ProgramData\\ClaudeCode\\managed-settings.json'

// Name the tier from what the file actually contains, by the few keys that
// separate them. Deliberately structural rather than reading a label we wrote:
// a label survives an edit that removes the protection under it.
function tierInForce () {
  const found = MANAGED_PATHS.find(p => { try { return fs.existsSync(p) } catch { return false } })
  const misplaced = process.platform === 'win32' && (() => { try { return fs.existsSync(LEGACY_WIN) } catch { return false } })()
  if (!found) {
    return {
      name: 'none', managed_settings: null, hooks_locked: false,
      ...(misplaced ? { finding: 'A managed-settings.json exists at the legacy ProgramData path, which Claude Code does not read. It is not in force.' } : {}),
      note: 'No managed policy on this machine. Anything the agent is told not to do, it is told by a file its user can edit.'
    }
  }
  let m = null
  try { m = JSON.parse(fs.readFileSync(found, 'utf8')) } catch {
    return { name: 'unreadable', managed_settings: found, hooks_locked: false,
      note: 'The managed settings file exists but is not valid JSON. Claude Code refuses to start on this, so the machine is not governed and not working.' }
  }
  const sb = m.sandbox || {}
  const name = sb.network?.strictAllowlist && m.allowManagedPermissionRulesOnly ? 'strict'
    : sb.enabled ? 'baseline'
      : m.allowManagedHooksOnly ? 'observe'
        : 'custom'
  return {
    name,
    managed_settings: found,
    // The three facts a fleet view should be able to sort on, read from the
    // file rather than assumed from the tier name.
    hooks_locked: m.allowManagedHooksOnly === true,
    sandbox: !!sb.enabled,
    network_allowlist: !!sb.network?.strictAllowlist,
    bypass_disabled: m.permissions?.disableBypassPermissionsMode === true,
    denied_reads: Array.isArray(m.permissions?.deny) ? m.permissions.deny.length : 0,
    failsafe: m.env?.CLEVR_FAILSAFE || null,
    ...(misplaced ? { finding: 'A second managed-settings.json sits at the legacy ProgramData path and is NOT read. Remove it so nobody reads it as policy.' } : {})
  }
}

// An AI assistant in the browser is an agent on this machine too. What it can
// REACH is a fact read from its own manifest; whether it looks like an AI
// assistant is a name match, and the line says so rather than pretending to a
// verdict. Extensions with no AI in the name are summarised, not listed, because
// a security screen listing every browser extension is a screen nobody reads.
function printExtensions (exts) {
  if (!exts.length) return
  const off = (e) => e.state === 'disabled'
  const ai = exts.filter(e => e.ai)
  const broadOthers = exts.filter(e => !e.ai && e.reach === 'every site' && !off(e))
  if (!ai.length && !broadOthers.length) return
  console.log(`${'-'.repeat(70)}`)
  console.log('Browser extensions')
  for (const e of ai) {
    console.log(`[${off(e) ? 'AI, OFF ' : 'AI      '}] ${e.name}  (${e.browser}) can read ${e.reach}`)
    console.log('           - name matches a known AI assistant, which is a heuristic, not a verdict')
    if (e.state !== 'enabled') console.log(`           - ${e.state}`)
  }
  if (broadOthers.length) {
    console.log(`${broadOthers.length} other extension${broadOthers.length === 1 ? '' : 's'} can read every site: ${broadOthers.map(e => e.name).slice(0, 6).join(', ')}`)
  }
  const seen = [...new Set(exts.map(e => e.browser))].sort()
  console.log(`Read from: ${seen.join(', ')}. Safari reports what is installed, not what Safari has switched on.`)
}

function printMcpJson (rows) {
  if (!rows.length) return
  const real = rows.filter(r => !r.unparsed)
  const bad = rows.filter(r => r.unparsed)
  if (!real.length && !bad.length) return
  console.log(`${'-'.repeat(70)}`)
  console.log('MCP servers declared in .mcp.json')
  const label = (r) => r.project ? r.project : 'user'
  for (const r of real) {
    const tag = r.clevr ? 'CLEVR   ' : r.approval === 'disabled' ? 'OFF     ' : 'SHADOW  '
    console.log(`[${tag}] ${r.name}  (${r.transport}, ${r.approval})  ${label(r)}`)
    if (r.target) console.log(`           - ${r.target}`)
  }
  for (const r of bad) console.log(`[UNREAD  ] ${r.file} could not be parsed, so what it declares is unknown`)
  console.log('These files are read, never written. A .mcp.json entry applies where that file applies,')
  console.log('so it is reported here rather than counted as governance for the whole machine.')
}

function printReport (report) {
  const { clients, summary } = report
  if (args.has('--json')) { console.log(JSON.stringify(report, null, 2)); return }
  console.log(`\nClevr endpoint agent  ${VERSION}   ${report.host}  (${report.os})  user ${report.user}`)
  console.log(`Clevr gateway: ${CLEVR_HOST || '(not configured)'}\n${'-'.repeat(70)}`)
  if (!clients.length) console.log('No known AI clients detected running.')
  for (const c of clients) {
    const tag = c.monitored ? 'GOVERNED' : c.kind === 'local-model' ? 'LOCAL   ' : c.kind === 'ai-feature' ? 'AI APP  ' : 'SHADOW  '
    const depth = c.via === 'hook' ? ' via hook' : c.via === 'mcp' ? ' via MCP' : c.via === 'llm-gateway' ? ' via gateway' : ''
    const where = c.running ? `pid ${c.pid}` : 'installed, not running'
    console.log(`[${tag}] ${c.label}  (${where}, ${c.kind})${c.monitored ? depth : ''}`)
    if (!c.running && c.installedAt) console.log(`           - found at ${c.installedAt}`)
    for (const e of c.evidence) console.log(`           - ${e}`)
  }
  console.log(`${'-'.repeat(70)}`)
  console.log(`Running: ${summary.running}   Governed: ${summary.monitored}${summary.hooked ? ` (${summary.hooked} by hook)` : ''}   Shadow: ${summary.shadow}`)
  if (summary.shadow) console.log('Shadow AI present: an AI client is running with no evidence it is governed by Clevr.')
  if (summary.shadow_installed) console.log(`Plus ${summary.shadow_installed} AI client${summary.shadow_installed === 1 ? '' : 's'} installed on this machine, not running now, with no evidence of governance.`)
  const mj = report.machine?.mcpJson || []
  const shadowJson = mj.filter(r => !r.unparsed && !r.clevr && r.approval !== 'disabled')
  if (shadowJson.length) console.log(`Plus ${shadowJson.length} MCP server${shadowJson.length === 1 ? '' : 's'} declared in a .mcp.json with no evidence of governance.`)
  printMcpJson(mj)
  printExtensions(report.machine?.extensions || [])
  printSkills(report.machine?.skills || [])
  console.log()
}


// ── Browser extensions ──────────────────────────────────────────────────────
// An AI assistant living in the browser is an agent on this machine like any
// other, and until now the agent was blind to it: a browser process does not say
// which site is open, and detecting AI traffic by remote host was dropped long
// ago because the APIs sit behind shared CDNs and it produced nothing but false
// positives.
//
// What IS readable, in userland, from files the signed-in user already owns, is
// the extension's own manifest. Two things come out of it, and they are reported
// with different weight on purpose:
//
//  - REACH is a fact. A manifest that requests every site can read every page
//    the person opens. That is stated plainly and never guessed.
//  - "Looks like an AI assistant" is a HEURISTIC over the declared name, and it
//    is labelled as one. A name list will miss a new product and can catch an
//    unrelated one, so it never turns into a silent verdict.
//
// Whether an extension is actually ENABLED is a third thing, and the three
// browsers answer it differently, so the record carries the answer rather than
// assuming one. Chromium records a disable reason per extension, Firefox records
// active and userDisabled in the profile, and Safari's own state lives in a
// container the OS does not let us read. A disabled extension is listed and
// marked, never counted as something reading pages today.
const AI_EXTENSION_NAME = /\b(chatgpt|openai|claude|anthropic|copilot|gemini|perplexity|mistral|le ?chat|monica|sider|merlin|harpa|jasper|writesonic|poe)\b/i

function chromiumRoots (home, appData) {
  const local = process.env.LOCALAPPDATA || path.join(home, 'AppData', 'Local')
  const mac = (...p) => path.join(home, 'Library', 'Application Support', ...p)
  return {
    Chrome: [mac('Google', 'Chrome'), path.join(local, 'Google', 'Chrome', 'User Data'), path.join(home, '.config', 'google-chrome')],
    Brave: [mac('BraveSoftware', 'Brave-Browser'), path.join(local, 'BraveSoftware', 'Brave-Browser', 'User Data'), path.join(home, '.config', 'BraveSoftware', 'Brave-Browser')],
    Edge: [mac('Microsoft Edge'), path.join(local, 'Microsoft', 'Edge', 'User Data'), path.join(home, '.config', 'microsoft-edge')],
    Arc: [mac('Arc', 'User Data')],
    Vivaldi: [mac('Vivaldi'), path.join(local, 'Vivaldi', 'User Data'), path.join(home, '.config', 'vivaldi')],
    Opera: [mac('com.operasoftware.Opera'), path.join(home, '.config', 'opera')],
    Chromium: [mac('Chromium'), path.join(home, '.config', 'chromium')]
  }
}

const dirsIn = (p) => { try { return fs.readdirSync(p, { withFileTypes: true }).filter(d => d.isDirectory()).map(d => d.name) } catch { return [] } }

// A manifest may declare its name as a placeholder resolved from the locale
// files shipped beside it. Left unresolved it reads as __MSG_extName__ on screen,
// which tells a reader nothing.
function resolveName (versionDir, name, manifest) {
  const m = /^__MSG_(.+)__$/.exec(String(name || ''))
  if (!m) return String(name || '')
  const locales = [manifest.default_locale, 'en_US', 'en'].filter(Boolean)
  for (const loc of locales) {
    try {
      const msgs = JSON.parse(fs.readFileSync(path.join(versionDir, '_locales', loc, 'messages.json'), 'utf8'))
      const hit = msgs[m[1]] || msgs[Object.keys(msgs).find(k => k.toLowerCase() === m[1].toLowerCase())]
      if (hit && hit.message) return String(hit.message)
    } catch { /* try the next locale */ }
  }
  return String(name || '')
}

// What the manifest asks to reach. A fact, taken from the declaration itself.
function reachOf (manifest) {
  const hosts = [
    ...(Array.isArray(manifest.host_permissions) ? manifest.host_permissions : []),
    ...(Array.isArray(manifest.permissions) ? manifest.permissions.filter(x => typeof x === 'string' && (x === '<all_urls>' || x.includes('://'))) : [])
  ]
  const every = hosts.some(h => h === '<all_urls>' || /^(\*|https?):\/\/\*\/\*$/.test(h) || h === '*://*/*')
  if (every) return { scope: 'every site', hosts }
  if (hosts.length) return { scope: `${hosts.length} site pattern${hosts.length === 1 ? '' : 's'}`, hosts }
  return { scope: 'no site access', hosts }
}

// Chromium keeps the enabled state apart from the manifest, in the profile's
// preference file: an extension with a non-empty disable reason list is off.
function chromiumStates (profileDir) {
  const state = new Map()
  for (const f of ['Secure Preferences', 'Preferences']) {
    try {
      const d = JSON.parse(fs.readFileSync(path.join(profileDir, f), 'utf8'))
      const settings = d?.extensions?.settings
      if (!settings || typeof settings !== 'object') continue
      for (const [id, v] of Object.entries(settings)) {
        const off = Array.isArray(v?.disable_reasons) && v.disable_reasons.length > 0
        if (!state.has(id)) state.set(id, off ? 'disabled' : 'enabled')
      }
    } catch { /* a profile that will not parse simply answers nothing */ }
  }
  return state
}

// Firefox keeps every add-on in one record per profile, with the enabled state
// and, on recent versions, the origins the user granted. Written to the format
// Mozilla documents; NOT verified against a live profile, because none exists on
// the machine this was built on. It can therefore only add a find, never remove
// one, and an absent field degrades to "not declared" rather than to a claim.
function firefoxRoots (home, appData) {
  return [
    path.join(home, 'Library', 'Application Support', 'Firefox', 'Profiles'),
    path.join(appData, 'Mozilla', 'Firefox', 'Profiles'),
    path.join(home, '.mozilla', 'firefox')
  ]
}

function firefoxExtensions (home, appData) {
  const out = []
  for (const root of firefoxRoots(home, appData)) {
    if (!fs.existsSync(root)) continue
    for (const profile of dirsIn(root)) {
      let doc
      try { doc = JSON.parse(fs.readFileSync(path.join(root, profile, 'extensions.json'), 'utf8')) } catch { continue }
      for (const a of (Array.isArray(doc?.addons) ? doc.addons : [])) {
        if (a?.type !== 'extension') continue
        // Firefox ships its own add-ons in the same file and listing them would
        // bury what a person actually installed. Only the locations that clearly
        // mean "shipped with the browser" are dropped: `app-profile` is the user's
        // own profile, so a prefix rule on `app-` would remove precisely what we
        // came for. Anything unrecognised is kept, since listing one extra beats
        // hiding a real one.
        const loc = typeof a.location === 'string' ? a.location : ''
        if (loc === 'app-builtin' || loc === 'app-global' || loc.startsWith('app-system')) continue
        const name = a?.defaultLocale?.name || a?.id || '(unnamed)'
        const description = a?.defaultLocale?.description || ''
        const origins = Array.isArray(a?.userPermissions?.origins) ? a.userPermissions.origins : null
        let reach = 'not declared in this profile'
        if (origins) {
          const every = origins.some(h => h === '<all_urls>' || /^(\*|https?):\/\/\*\/\*$/.test(h) || h === '*://*/*')
          reach = every ? 'every site' : origins.length ? `${origins.length} site pattern${origins.length === 1 ? '' : 's'}` : 'no site access'
        }
        out.push({
          browser: 'Firefox', profile, id: String(a.id || ''), name: String(name), version: a.version || null,
          reach, hosts: (origins || []).slice(0, 8),
          state: (a.active === true && !a.userDisabled && !a.appDisabled) ? 'enabled' : 'disabled',
          ai: AI_EXTENSION_NAME.test(String(name)) || AI_EXTENSION_NAME.test(String(description))
        })
      }
    }
  }
  return out
}

// Safari extensions are app extensions registered with the OS, listed by a tool
// Apple ships. That gives the name and the application carrying it, which is the
// fact worth reporting. Their permissions live inside the bundle and only a
// converted web extension exposes a manifest, so reach is often unknown. Whether
// Safari has the extension switched ON lives in a container the OS protects, so
// this says INSTALLED and never claims otherwise.
function safariExtensions () {
  if (process.platform !== 'darwin') return []
  let raw
  try { raw = execFileSync('pluginkit', ['-mAvvv', '-p', 'com.apple.Safari.extension'], { encoding: 'utf8', maxBuffer: 4 << 20, timeout: 5000 }) } catch { return [] }
  const out = []
  let cur = null
  for (const line of raw.split('\n')) {
    const header = /^\s{4,}(\S+)\((.+)\)\s*$/.exec(line)
    if (header) {
      if (cur) out.push(cur)
      cur = { id: header[1], version: header[2], name: '', path: '', parent: '' }
      continue
    }
    if (!cur) continue
    const kv = /^\s+(Path|Display Name|Parent Bundle)\s*=\s*(.+?)\s*$/.exec(line)
    if (kv) cur[{ Path: 'path', 'Display Name': 'name', 'Parent Bundle': 'parent' }[kv[1]]] = kv[2]
  }
  if (cur) out.push(cur)

  return out.filter(e => e.id).map(e => {
    let reach = 'not declared in a readable manifest'
    let hosts = []
    try {
      const m = JSON.parse(fs.readFileSync(path.join(e.path, 'Contents', 'Resources', 'manifest.json'), 'utf8'))
      const r = reachOf(m)
      reach = r.scope
      hosts = r.hosts.slice(0, 8)
    } catch { /* a native app extension has no manifest to read */ }
    return {
      browser: 'Safari', profile: '', id: e.id, name: e.name || e.id, version: e.version || null,
      reach, hosts, state: 'installed, state not readable',
      ai: AI_EXTENSION_NAME.test(e.name) || AI_EXTENSION_NAME.test(e.parent) || AI_EXTENSION_NAME.test(e.id)
    }
  })
}

function browserExtensions (home, appData) {
  const out = []
  for (const [browser, roots] of Object.entries(chromiumRoots(home, appData))) {
    for (const root of roots) {
      if (!fs.existsSync(root)) continue
      for (const profile of dirsIn(root)) {
        const extRoot = path.join(root, profile, 'Extensions')
        if (!fs.existsSync(extRoot)) continue
        const states = chromiumStates(path.join(root, profile))
        for (const id of dirsIn(extRoot)) {
          // Several versions can sit side by side; the last one is what loads.
          const versions = dirsIn(path.join(extRoot, id)).sort()
          const versionDir = versions.length ? path.join(extRoot, id, versions[versions.length - 1]) : null
          if (!versionDir) continue
          let manifest
          try { manifest = JSON.parse(fs.readFileSync(path.join(versionDir, 'manifest.json'), 'utf8')) } catch { continue }
          const name = resolveName(versionDir, manifest.name, manifest)
          const reach = reachOf(manifest)
          const description = resolveName(versionDir, manifest.description, manifest)
          const looksAI = AI_EXTENSION_NAME.test(name) || AI_EXTENSION_NAME.test(description)
          out.push({ browser, profile, id, name, version: manifest.version || null, reach: reach.scope, hosts: reach.hosts.slice(0, 8), state: states.get(id) || 'enabled', ai: looksAI })
        }
      }
      break // one layout per browser is enough; the rest are other platforms
    }
  }
  return [...out, ...firefoxExtensions(home, appData), ...safariExtensions()]
}

// ── Remediation: point a shadow client at Clevr ─────────────────────────────
// Listing shadow AI only produces a list. What makes an agent on the machine
// worth installing is that it can CLOSE what it found: write a Clevr MCP server
// entry into the client's own configuration, so that client's tool calls start
// going through the Clevr MCP server. Discovery, then remediation, in one gesture.
//
// Limits, stated here and printed in the output rather than hidden:
//  - userland. It edits configuration files the signed-in user already owns.
//    No kernel, no MDM, no privilege escalation.
//  - it never removes or rewrites another MCP server, and refuses to touch a
//    file it cannot parse.
//  - a client with no user-editable MCP configuration cannot be remediated from
//    here. Those are listed with the reason instead of being quietly skipped.
//  - the client must be restarted before the new entry takes effect.
// A hook is the deepest control on a machine, and where one exists it is what
// --govern should put in place rather than the MCP pointer. The pointer governs
// `tools/call` on one server and nothing else, no shell command, no file edit,
// no prompt and no answer; the hook sees every tool before it runs AND carries
// the conversation to the engine.
//
// The agent does NOT reimplement the installers. It carries no hook scripts, and
// five harness hook formats copied into a second place is how this component
// produced most of its defects. It delegates to the CLI, which owns them, and
// reports honestly when the CLI is not on the machine.
// A harness with no hook and no Clevr MCP server still has controls; saying only "no MCP
// configuration" hides them behind a shrug.
const NO_HOOK_REASON = {}

// Clients the CLI can put the MCP GUARD in front of. The guard wraps the servers
// this client already has, so a blocked call never reaches the tool. Adding the
// Clevr MCP server instead only lets the client ask, a different thing, and it is
// labelled as one below.
const GUARD_TARGETS = {
  'claude-desktop': 'claude-desktop'
}

const HOOK_TARGETS = {
  'claude-code': 'claude-code',
  cursor: 'cursor',
  'copilot-cli': 'copilot-cli',
  augment: 'augment',
  'gemini-cli': 'gemini-cli',
  codex: 'codex',
  // The ChatGPT desktop app runs Codex locally and reads the same hooks file.
  chatgpt: 'codex'
}

function findClevrCli (home) {
  const candidates = [
    process.env.CLEVR_CLI,
    ...(process.env.PATH || '').split(path.delimiter).filter(Boolean).map(d => path.join(d, 'clevr')),
    path.join(home, '.clevr', 'bin', 'clevr'),
    path.join(home, '.local', 'bin', 'clevr')
  ].filter(Boolean)
  for (const c of candidates) {
    try { if (fs.statSync(c).isFile()) return c } catch { /* next */ }
  }
  return null
}

const MCP_URL = process.env.CLEVR_MCP_URL || (GATEWAY_URL ? GATEWAY_URL.replace(/\/+$/, '') + '/mcp' : '')
const MCP_ENTRY_NAME = process.env.CLEVR_MCP_NAME || 'clevr'

function readConfig (file) {
  if (!fs.existsSync(file)) return { doc: {}, existed: false }
  const raw = fs.readFileSync(file, 'utf8')
  if (!raw.trim()) return { doc: {}, existed: true }
  const doc = JSON.parse(raw)
  if (!doc || typeof doc !== 'object' || Array.isArray(doc)) throw new Error('top level is not a JSON object')
  return { doc, existed: true }
}

// Decide what would change, without changing anything. --govern prints this.
function planRemediation (report) {
  const home = os.homedir()
  const cfg = configPaths(home, process.env.APPDATA || path.join(home, 'AppData', 'Roaming'))
  const plan = []
  const running = new Map(report.clients.map(c => [c.id, c]))

  // Remediation covers what is INSTALLED, not only what is running, and those are
  // two different questions. The scan answers "what is running ungoverned", which
  // is the shadow-AI question. Remediation answers "what can I point at Clevr",
  // and a client that has to be closed before it can be configured is, by
  // definition, not running at the moment it can be fixed. Keying this off the
  // scan made the one client that needs closing impossible to reach at all:
  // refused while open, invisible once shut.
  const ids = new Set(running.keys())
  for (const [id, t] of Object.entries(cfg)) {
    if (t.detect.some(f => fs.existsSync(f))) ids.add(id)
  }

  // Every client, not only the shadow ones. A client routed through the LLM
  // gateway is governed on the model hop and ungoverned on the tool hop, and that
  // gap is worth closing; a client already pointing at the Clevr MCP server should say so on
  // screen rather than vanish from the list.
  for (const id of ids) {
    const known = CATALOG.find(e => e.id === id)
    const c = running.get(id) || { id, label: known?.label || id, kind: known?.kind || 'unknown' }

    // The hook is decided BEFORE the MCP table is consulted, for two reasons.
    // Where a harness has a hook it is the answer, and falling through would put
    // the weaker control on a client that can carry the stronger one. And
    // several of these harnesses have no MCP configuration at all, so consulting
    // that table first rejected them as unreachable when a hook was available.
    const cliTarget = HOOK_TARGETS[id]
    if (cliTarget) {
      if (report.machine?.hook?.[id]?.governed) {
        plan.push({ id, label: c.label, action: 'already', running: running.has(id), via: 'the Clevr hook is installed here, the deepest control available: every tool call is checked before it runs' })
        continue
      }
      const cli = findClevrCli(home)
      plan.push(cli
        ? { id, label: c.label, action: 'hook', target: cliTarget, cli, running: running.has(id), command: `${cli} setup ${cliTarget}` }
        : { id, label: c.label, action: 'cannot', running: running.has(id),
            reason: `a hook is the right control for this harness, and the clevr CLI that installs it is not on this machine. Install the CLI, then run: clevr setup ${cliTarget}` })
      continue
    }

    const target = cfg[c.id]
    if (!target) {
      plan.push({
        id: c.id,
        label: c.label,
        action: 'cannot',
        reason: NO_HOOK_REASON[c.id] || (c.kind === 'local-model'
          ? 'local model runner: it has no MCP client to point at Clevr. Govern its tool use where the tools are.'
          : 'no user-editable MCP configuration is documented for this client')
      })
      continue
    }
    // Only while it is actually running: a client that rewrites its own file can
    // be configured safely the moment it is closed, and that is the whole point of
    // asking for it to be closed. --force writes anyway.
    if (target.quitFirst && running.has(id) && !args.has('--force')) {
      plan.push({
        id: c.id,
        label: c.label,
        file: target.write,
        action: 'cannot',
        // An explicit field, so the fleet view buckets this on a contract rather
        // than by matching the sentence below. Closed by shutting the app, which
        // is not the same as a client that cannot be reached at all.
        blocked: 'client_running',
        reason: `${target.quitFirst} rewrites this file while running and drops the entry, so close it and run this again.`
      })
      continue
    }
    const step = { id: c.id, label: c.label, file: target.write, running: running.has(id) }
    let doc
    try { doc = readConfig(target.write).doc } catch (e) {
      plan.push({ ...step, action: 'cannot', reason: `its configuration file is not valid JSON (${e.message}). Left untouched.` })
      continue
    }
    const servers = doc.mcpServers && typeof doc.mcpServers === 'object' ? doc.mcpServers : {}
    const existing = servers[MCP_ENTRY_NAME]
    step.keeps = Object.keys(servers).filter(k => k !== MCP_ENTRY_NAME)
    // An entry with no url but a command naming Clevr is the local guard wrapper.
    // It is a deliberate, working configuration in another style, so it is left
    // alone rather than replaced by the HTTP server entry.
    const guardWrapper = existing && !existing.url &&
      [existing.command, ...(Array.isArray(existing.args) ? existing.args : [])].join(' ').toLowerCase().includes(MCP_MARKER)
    const guardTarget = GUARD_TARGETS[id]
    const cliForGuard = guardTarget ? findClevrCli(home) : null
    step.guard = guardTarget ? `${cliForGuard || 'clevr'} setup ${guardTarget}` : null
    if (existing && guardWrapper) plan.push({ ...step, action: 'already', via: 'the guard wraps a server here, so a blocked call never reaches the tool' })
    else if (existing && existing.url === MCP_URL) plan.push({ ...step, action: 'already', via: `the Clevr MCP server is configured (${MCP_URL}), which lets this client ask but does not gate it` })
    else if (existing) plan.push({ ...step, action: 'update', from: existing.url || '(no url)' })
    else plan.push({ ...step, action: 'add' })
  }
  return plan
}

function applyRemediation (plan) {
  const stamp = new Date().toISOString().replace(/[:.]/g, '-')
  for (const step of plan) {
    if (step.action === 'hook') {
      // Running the installer the CLI owns. Its output is reported as it came,
      // and a failure is a failure: no guessing that it half worked.
      try {
        const out = execFileSync(step.cli, ['setup', step.target], { encoding: 'utf8', timeout: 120000, stdio: ['ignore', 'pipe', 'pipe'] })
        step.result = 'written'
        step.output = String(out).trim().split('\n').slice(-3).join(' · ').slice(0, 300)
      } catch (e) {
        step.result = 'failed'
        step.error = String(e.stderr || e.stdout || e.message).trim().split('\n').slice(-2).join(' · ').slice(0, 300)
      }
      continue
    }
    if (step.action !== 'add' && step.action !== 'update') continue
    try {
      const { doc, existed } = readConfig(step.file)
      if (existed) {
        step.backup = `${step.file}.clevr-backup-${stamp}`
        fs.copyFileSync(step.file, step.backup)
      } else {
        fs.mkdirSync(path.dirname(step.file), { recursive: true })
      }
      if (!doc.mcpServers || typeof doc.mcpServers !== 'object' || Array.isArray(doc.mcpServers)) doc.mcpServers = {}
      doc.mcpServers[MCP_ENTRY_NAME] = { type: 'http', url: MCP_URL }
      // Write then rename: an interrupted run must never leave a client with a
      // truncated configuration file it can no longer start from.
      const tmp = `${step.file}.clevr-tmp-${process.pid}`
      fs.writeFileSync(tmp, JSON.stringify(doc, null, 2) + '\n')
      fs.renameSync(tmp, step.file)
      step.result = 'written'
      rememberApplied(step)
    } catch (e) {
      step.result = 'failed'
      step.error = e.message
    }
  }
  return plan
}

function printPlan (plan, applied) {
  console.log(applied ? 'Remediation applied' : 'Remediation plan. Nothing is written without --apply.')
  console.log(`Clevr MCP server: ${MCP_URL}\n${'-'.repeat(70)}`)
  if (!plan.length) { console.log('No AI client detected on this machine.\n'); return }
  let restart = false
  for (const step of plan) {
    if (step.action === 'cannot') { console.log(`[SKIP    ] ${step.label}\n           - ${step.reason}`); continue }
    // The whole sentence lives in `via`. A fixed prefix like "already routed
    // through Clevr" contradicted the very case it introduced, where the Clevr MCP server is
    // configured and gates nothing.
    if (step.action === 'already') { console.log(`[OK      ] ${step.label}\n           - ${step.via}`); continue }
    if (step.result === 'failed') { console.log(`[FAILED  ] ${step.label}\n           - ${step.error}\n           - ${step.file}`); continue }
    if (step.action === 'hook') {
      console.log(`[${step.result === 'written' ? 'GOVERNED' : 'PLANNED '}] ${step.label}${step.running === false ? ' (not running)' : ''}`)
      console.log(`           - ${step.result === 'written' ? 'installed the Clevr hook' : 'would install the Clevr hook'}, the deepest control here: every tool call before it runs, plus the conversation`)
      console.log(`           - ${step.command}`)
      if (step.output) console.log(`           - ${step.output}`)
      if (step.result === 'written') restart = true
      continue
    }
    const verb = step.action === 'update' ? `repoint "${MCP_ENTRY_NAME}" from ${step.from}` : `add "${MCP_ENTRY_NAME}"`
    console.log(`[${step.result === 'written' ? 'ADDED   ' : 'PLANNED '}] ${step.label}${step.running === false ? ' (not running)' : ''}`)
    console.log(`           - ${step.result === 'written' ? 'wrote' : 'would'} ${verb} in ${step.file}`)
    // That server is not a gate, and the line has to say so or the plan reads as
    // remediation when it is an offer of advice.
    console.log('           - this lets the client ASK Clevr for a verdict. It does not gate what the client does.')
    if (step.guard) console.log(`           - to gate this client's own tools, wrap its servers with the guard: ${step.guard}`)
    if (step.keeps.length) console.log(`           - leaves ${step.keeps.length} other MCP server(s) untouched: ${step.keeps.join(', ')}`)
    if (step.backup) console.log(`           - backup: ${step.backup}`)
    if (step.result === 'written') restart = true
  }
  console.log('-'.repeat(70))
  if (restart) console.log('Restart each client above for the new configuration to take effect.')
  if (!applied && plan.some(s => s.action === 'add' || s.action === 'update' || s.action === 'hook')) console.log('Re-run with --govern --apply to write these changes.')
  if (plan.some(s => s.blocked === 'client_running')) console.log('One client needs to be closed first, for the reason on its line.')
  console.log()
}

function govern (report) {
  if (!MCP_URL) {
    console.error('--govern needs a Clevr MCP URL: set CLEVR_MCP_URL, or CLEVR_GATEWAY_URL / CLEVR_URL to derive it.')
    return null
  }
  const plan = args.has('--apply') ? applyRemediation(planRemediation(report)) : planRemediation(report)
  // Attached to the posted report. Two limits, both true today:
  // POST /v1/endpoints persists `clients` and `summary` only, so this block
  // reaches the server and is dropped; surfacing it in the fleet view needs a
  // column first. And it is NOT covered by the device signature, which stays
  // fixed so the Node agent, the Go agent and the brain verifier keep building
  // identical bytes. Context, not attested fact.
  report.remediation = { url: MCP_URL, applied: args.has('--apply'), signed: false, steps: plan }
  return plan
}


// ── Drift: did our change survive? ──────────────────────────────────────────
// Writing a configuration is not the same as it holding. Measured 2026-09-17:
// Claude Desktop took an entry back seven minutes after it was written, with no
// user involved. A console reading "pointed at Clevr" for a machine that is
// ungoverned again is worse than one that never claimed it, so the agent keeps
// a note of what it wrote and checks, on every run, whether it is still there.
//
// What this can and cannot say, and the difference matters in front of a
// customer: it knows Clevr WAS configured here and is not now. It does not know
// who undid it. The client rewriting its own file, someone editing it by hand
// and an administrator changing the target all look the same on disk. So the
// finding is stated as the fact, and the known behaviour of a client that
// rewrites its own configuration is offered as context, not as a verdict.
const STATE_PATH = path.join(os.homedir(), '.clevr', 'endpoint-state.json')

function readState () {
  let j
  try { j = JSON.parse(fs.readFileSync(STATE_PATH, 'utf8')) } catch { return { seen: {} } }
  if (!j || typeof j !== 'object') return { seen: {} }
  const state = { seen: (j.seen && typeof j.seen === 'object') ? j.seen : {} }
  // An older file kept only what the agent had written, keyed by client id.
  // Carried across so a machine does not forget its history on upgrade.
  if (j.applied && typeof j.applied === 'object') {
    for (const [id, rec] of Object.entries(j.applied)) {
      const key = id + '#mcp'
      if (!state.seen[key]) state.seen[key] = { ...rec, id, kind: 'mcp', by: 'agent', detail: rec.url || null }
    }
  }
  return state
}
function writeState (state) {
  try {
    fs.mkdirSync(path.dirname(STATE_PATH), { recursive: true })
    fs.writeFileSync(STATE_PATH, JSON.stringify(state, null, 2), { mode: 0o600 })
  } catch { /* userland: a machine that cannot keep state simply makes no claim */ }
}

// Every Clevr configuration this scan can see, whoever put it there. Keyed by
// client and kind, because one client can carry two at once and losing either
// one is its own event.
//
// Recording what is OBSERVED rather than only what this agent wrote is the whole
// point: a setting installed by the CLI, by an administrator or by hand is
// exactly as worth watching, and before this the agent went quiet about all of
// them. A reversal then read as plain shadow, with nothing to say it had ever
// been configured.
function observedGovernance (sig) {
  const out = {}
  const add = (id, kind, f) => {
    if (!f || !f.governed || !f.file) return
    out[id + '#' + kind] = { id, kind, file: f.file, detail: f.via || null }
  }
  for (const [id, f] of Object.entries(sig.hook || {})) add(id, 'hook', f)
  for (const [id, f] of Object.entries(sig.mcp || {})) add(id, f.enforcing ? 'guard' : 'mcp', f)
  for (const [id, f] of Object.entries(sig.harnessGateway || {})) add(id, 'gateway', f)
  return out
}

// Our entry is still in the file but no longer aimed at us. Only meaningful for
// the MCP kinds, where a named entry carries a URL.
function entryNowAt (rec) {
  if (rec.kind !== 'mcp' && rec.kind !== 'guard') return null
  try {
    const doc = JSON.parse(fs.readFileSync(rec.file, 'utf8'))
    const e = doc?.mcpServers?.[MCP_ENTRY_NAME]
    if (!e || typeof e !== 'object') return null
    return e.url || '(no url)'
  } catch { return null }
}

const KIND_LABEL = {
  hook: 'the Clevr hook',
  guard: 'the Clevr MCP guard',
  mcp: 'the Clevr MCP entry',
  gateway: 'the Clevr model provider block'
}

// Record a successful write by this agent. It is the same record as an observed
// one, marked so the report can say we put it there.
function rememberApplied (step) {
  const state = readState()
  const key = step.id + '#mcp'
  const prev = state.seen[key] || {}
  state.seen[key] = {
    id: step.id,
    label: step.label,
    kind: 'mcp',
    by: 'agent',
    file: step.file,
    detail: MCP_URL,
    at: new Date().toISOString(),
    state: 'holding',
    reverts: prev.reverts || 0,
    last_reverted_at: prev.last_reverted_at || null
  }
  writeState(state)
}

// Compare what is configured now against what was configured before, and report
// what disappeared. The comparison re-runs the detectors rather than re-parsing
// a file by hand: whatever found a setting is what decides it is still there.
function checkDrift (sig, labelOf) {
  const state = readState()
  const now = observedGovernance(sig)
  const found = []
  let changed = false

  // Still there, or newly there. Either way it is the current truth.
  for (const [key, obs] of Object.entries(now)) {
    const prev = state.seen[key] || {}
    const label = labelOf(obs.id) || prev.label || obs.id
    if (prev.state !== 'holding' || prev.detail !== obs.detail || prev.file !== obs.file) changed = true
    state.seen[key] = {
      ...prev,
      id: obs.id,
      label,
      kind: obs.kind,
      by: prev.by || 'observed',
      file: obs.file,
      detail: obs.detail,
      at: prev.at || new Date().toISOString(),
      state: 'holding',
      reverts: prev.reverts || 0,
      last_reverted_at: prev.last_reverted_at || null
    }
    found.push({ id: obs.id, label, kind: obs.kind, state: 'holding', file: obs.file, applied_at: state.seen[key].at, reverts: state.seen[key].reverts })
  }

  // Configured before, not configured now.
  for (const [key, rec] of Object.entries(state.seen)) {
    if (now[key]) continue
    // The count moves only when this crosses from holding to gone. Counting it
    // on every scan would turn one reversal into three hundred a day and make
    // the number useless for telling an accident from a habit.
    const firstSighting = rec.state === 'holding' || rec.state === undefined
    const label = labelOf(rec.id) || rec.label || rec.id
    // Gone, or still present under our name but aimed somewhere else. The second
    // is not the same story as the first and the line says where it points now.
    const now2 = entryNowAt(rec)
    const drifted = {
      id: rec.id,
      label,
      kind: rec.kind || 'mcp',
      by: rec.by || 'observed',
      state: now2 ? 'repointed' : 'removed',
      now: now2,
      file: rec.file || null,
      applied_at: rec.at || null,
      expected: rec.detail || null,
      reverts: (rec.reverts || 0) + (firstSighting ? 1 : 0),
      since: firstSighting ? new Date().toISOString() : (rec.last_reverted_at || null)
    }
    // Context, flagged as context: this client is known to rewrite its own file.
    const home = os.homedir()
    const target = configPaths(home, process.env.APPDATA || path.join(home, 'AppData', 'Roaming'))[rec.id]
    if (target?.quitFirst) drifted.likely = `${target.quitFirst} rewrites this file while running and drops entries added underneath it`
    found.push(drifted)
    if (firstSighting) {
      state.seen[key] = { ...rec, label, state: drifted.state, reverts: drifted.reverts, last_reverted_at: drifted.since }
      changed = true
    }
  }

  if (changed) writeState(state)
  return found
}

function printDrift (drift) {
  const gone = drift.filter(d => d.state === 'removed' || d.state === 'repointed')
  if (!gone.length) return
  console.log('Clevr settings that were configured here and are gone')
  console.log('-'.repeat(70))
  for (const d of gone) {
    console.log(`[UNDONE  ] ${d.label}`)
    const what = KIND_LABEL[d.kind] || 'the Clevr entry'
    console.log(`           - ${d.state === 'removed' ? what + ' is gone from' : 'now points at ' + d.now + ' in'} ${d.file}`)
    if (d.by === 'observed') console.log('           - it was not written by this agent, only seen configured here before')
    console.log(`           - ${d.by === 'agent' ? 'applied' : 'first seen'} ${d.applied_at}${d.since ? `, undone ${d.since}` : ''}${d.reverts > 1 ? ` (${d.reverts} times in all)` : ''}`)
    if (d.likely) console.log(`           - likely cause: ${d.likely}`)
  }
  console.log('-'.repeat(70))
  console.log('Re-run with --govern --apply to put it back.\n')
}

// ── Device identity: a per-machine Ed25519 keypair, persisted userland, used to
// SIGN each report so the control plane knows it came from this machine — and can
// flag a report whose signing key silently changed (a spoof / re-imaged host).
// Built-in crypto, zero deps. The private key never leaves the machine (0600).
const KEY_PATH = path.join(os.homedir(), '.clevr', 'endpoint-key.json')
// RFC 8410 PKCS8 prefix for a raw 32-byte Ed25519 seed. We persist the SEED (not
// PKCS8) so the Node and Go agents derive the SAME key from the SAME file.
const PKCS8_ED25519_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex')
function deviceKeypair () {
  try {
    const j = JSON.parse(fs.readFileSync(KEY_PATH, 'utf8'))
    const seed = j.seed ? Buffer.from(j.seed, 'base64') : null
    if (seed && seed.length === 32) {
      const priv = crypto.createPrivateKey({ key: Buffer.concat([PKCS8_ED25519_PREFIX, seed]), format: 'der', type: 'pkcs8' })
      return { priv, pub: j.pub }
    }
  } catch {}
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519')
  const der = privateKey.export({ format: 'der', type: 'pkcs8' })   // 48B = 16-byte prefix + 32-byte seed
  const seed = der.subarray(der.length - 32).toString('base64')
  const spki = publicKey.export({ format: 'der', type: 'spki' })
  const pub = spki.subarray(spki.length - 32).toString('base64')    // raw 32-byte public key
  try { fs.mkdirSync(path.dirname(KEY_PATH), { recursive: true }); fs.writeFileSync(KEY_PATH, JSON.stringify({ seed, pub }), { mode: 0o600 }) } catch {}
  return { priv: privateKey, pub }
}
// Deterministic, language-neutral signing string (scalars only — no JSON — so the
// JS agent, the Go agent, and the brain verifier all build the identical bytes).
function signingString (r) {
  const s = r.summary || {}
  const sigs = (r.clients || []).map(c => `${c.id}:${c.monitored ? '1' : '0'}:${c.via || ''}`).sort()
  return [r.host, r.ts, r.version, String(s.running || 0), String(s.monitored || 0), String(s.shadow || 0), sigs.join(',')].join('\n')
}

async function postReport (report) {
  if (!CLEVR_URL || !CLEVR_KEY) { console.error('--report needs CLEVR_URL and CLEVR_API_KEY.'); return false }
  let body = report
  try {
    const kp = deviceKeypair()
    const sig = 'ed25519:' + crypto.sign(null, Buffer.from(signingString(report), 'utf8'), kp.priv).toString('base64')
    body = { ...report, device_key: kp.pub, sig }
  } catch (e) { /* signing is best-effort — an unsigned report is still accepted, just marked unsigned */ }
  try {
    const res = await fetch(`${CLEVR_URL}/v1/endpoints`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${CLEVR_KEY}`, 'Content-Type': 'application/json' },
      body: JSON.stringify(body)
    })
    console.log(res.ok ? `Reported to Clevr (${res.status}).` : `Report failed: HTTP ${res.status} ${await res.text()}`)
    return res.ok
  } catch (e) { console.error('Report failed:', e.message); return false }
}

async function runOnce () {
  const report = buildReport()
  const plan = args.has('--govern') ? govern(report) : null
  // Runs on every invocation, not only under --govern: a machine that merely
  // reports must still say that what it was configured with has been taken back.
  const labelOf = (id) => (report.clients.find(c => c.id === id) || CATALOG.find(e => e.id === id) || {}).label
  // After a write, the signals taken at the top of this run are stale: they were
  // read before --apply touched anything, so the setting just installed would be
  // reported undone in the same breath. Re-read them, and only then.
  report.drift = checkDrift(args.has('--apply') ? machineSignals() : report.machine, labelOf)
  printReport(report)
  if (plan && !args.has('--json')) printPlan(plan, args.has('--apply'))
  if (!args.has('--json')) printDrift(report.drift)
  if (args.has('--report')) await postReport(report)
}

// --identify <path>: how this agent recognises one executable or application,
// and nothing else. For support ("why is this not listed?") and for the tests,
// which cannot start a renamed client on every machine they run on.
if (args.has('--identify')) {
  const target = process.argv[process.argv.indexOf('--identify') + 1] || ''
  const file = target.endsWith('.app') ? path.join(target, 'Contents', 'MacOS', plistKey(target, 'CFBundleExecutable') || '') : target
  const byName = CATALOG.find(e => !e.inArgs && e.re && e.re.test(file))
  const ident = identityOfFile(file)
  const hit = byName ? { entry: byName, by: 'its name' } : entryOfIdentity(ident)
  console.log(JSON.stringify({ path: file, identity: ident, client: hit ? { id: hit.entry.id, label: hit.entry.label, by: hit.by } : null }, null, 2))
  process.exit(0)
}

await runOnce()

// --watch: keep scanning so the fleet view stays live (a laptop that stops
// reporting goes stale server-side). Bounded to >= 30s to stay light.
if (args.has('--watch')) {
  const interval = Math.max(30, Number(process.env.CLEVR_INTERVAL) || 300) * 1000
  console.log(`Watching. Re-scanning every ${interval / 1000}s. Ctrl-C to stop.`)
  setInterval(runOnce, interval)
}
