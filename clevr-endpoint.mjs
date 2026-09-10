// Clevr endpoint agent — userland, cross-platform (macOS / Windows / Linux).
// Requires Node 18+ (built-in fetch). Zero dependencies.
//
//   node clevr-endpoint.mjs            # print a posture report for this machine
//   node clevr-endpoint.mjs --report   # also POST it to Clevr (needs CLEVR_URL + CLEVR_API_KEY)
//   node clevr-endpoint.mjs --json     # machine-readable output
//   node clevr-endpoint.mjs --watch    # re-run every CLEVR_INTERVAL seconds (default 300)
//
// What it does: it lists the AI clients / agents running on this machine and, for
// each, whether there is evidence it routes through Clevr (an LLM gateway base URL,
// or a Clevr-fronted MCP server in the client's config). Anything running with no
// such evidence is flagged as SHADOW AI.
//
// What it is NOT: it is userland and DETECTION-ONLY. It sees processes and config,
// not kernel syscalls, and it does not block. Enforcement is the job of the
// MDM-pushed gateway/MCP config it checks for. This closes the visibility gap
// ("is there an ungoverned agent on this laptop?") without becoming an EDR.

import { execFileSync } from 'node:child_process'
import crypto from 'node:crypto'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'

const VERSION = '0.1.0'
const args = new Set(process.argv.slice(2))
const CLEVR_URL = process.env.CLEVR_URL || ''
const CLEVR_KEY = process.env.CLEVR_API_KEY || ''
const GATEWAY_URL = process.env.CLEVR_GATEWAY_URL || CLEVR_URL
const MCP_MARKER = (process.env.CLEVR_MCP_MARKER || 'clevr').toLowerCase()

const hostOf = (u) => { try { return new URL(u).host } catch { return '' } }
const CLEVR_HOST = hostOf(GATEWAY_URL)

// ── AI-client catalog. Ordered specific → generic; each process is assigned to
// the first entry it matches. `re` is tested against the full command (unix) or
// the executable name (Windows).
const CATALOG = [
  { id: 'claude-code', label: 'Claude Code (CLI)', kind: 'cli-agent', re: /claude[-_ ]?code|@anthropic-ai[\/\\]claude-code/i },
  { id: 'cursor', label: 'Cursor', kind: 'ide-agent', re: /(?:^|[\/\\ ])cursor(?:\.exe| helper|$|[\/\\ ])/i },
  { id: 'windsurf', label: 'Windsurf', kind: 'ide-agent', re: /windsurf/i },
  { id: 'chatgpt', label: 'ChatGPT desktop', kind: 'desktop-assistant', re: /chatgpt/i },
  { id: 'claude-desktop', label: 'Claude Desktop', kind: 'desktop-assistant', re: /(?:^|[\/\\ ])claude(?:\.exe| helper|$|[\/\\ ])/i },
  { id: 'ollama', label: 'Ollama (local model)', kind: 'local-model', re: /ollama/i },
  { id: 'lmstudio', label: 'LM Studio (local model)', kind: 'local-model', re: /lm[-_ ]?studio/i },
  // Heuristic homegrown agents: match on specific agent FRAMEWORKS only (not the
  // bare words "agent"/"mcp", which catch unrelated tooling and cause false positives).
  { id: 'py-agent', label: 'Python agent', kind: 'custom-agent', re: /python[0-9.]*\b.*(langchain|langgraph|crewai|autogen|llama[_-]?index|pydantic_ai|smolagents|@?modelcontextprotocol[\/\\]server)/i },
  { id: 'node-agent', label: 'Node agent', kind: 'custom-agent', re: /\bnode\b.*(langchain|@langchain|crewai|@modelcontextprotocol[\/\\]server|ai-sdk|@openai[\/\\]agents)/i }
]

function listProcesses () {
  try {
    if (process.platform === 'win32') {
      const out = execFileSync('tasklist', ['/fo', 'csv', '/nh'], { encoding: 'utf8', maxBuffer: 8 << 20 })
      return out.split(/\r?\n/).filter(Boolean).map(line => {
        const f = line.match(/"([^"]*)"/g)?.map(s => s.slice(1, -1)) || []
        return { pid: f[1] || '?', cmd: f[0] || '' } // Windows: exe name only
      })
    }
    const out = execFileSync('ps', ['-axww', '-o', 'pid=,command='], { encoding: 'utf8', maxBuffer: 16 << 20 })
    return out.split('\n').filter(Boolean).map(line => {
      const t = line.trim(); const sp = t.indexOf(' ')
      return { pid: sp < 0 ? t : t.slice(0, sp), cmd: sp < 0 ? '' : t.slice(sp + 1) }
    })
  } catch { return [] }
}

// ── Machine-level signals: is an LLM gateway configured, and does any known
// desktop client route its MCP through Clevr?
function readJson (p) { try { return JSON.parse(fs.readFileSync(p, 'utf8')) } catch { return null } }
function fileMentionsClevr (p) { try { return fs.readFileSync(p, 'utf8').toLowerCase().includes(MCP_MARKER) } catch { return false } }

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
  // Candidate MCP config locations per client/OS.
  const claudeCfg = [
    path.join(home, 'Library', 'Application Support', 'Claude', 'claude_desktop_config.json'),
    path.join(appData, 'Claude', 'claude_desktop_config.json'),
    path.join(home, '.config', 'Claude', 'claude_desktop_config.json')
  ]
  const cursorCfg = [
    path.join(home, '.cursor', 'mcp.json'),
    path.join(home, 'Library', 'Application Support', 'Cursor', 'User', 'mcp.json'),
    path.join(appData, 'Cursor', 'User', 'mcp.json')
  ]
  const claudeCodeCfg = [path.join(home, '.claude', 'settings.json'), path.join(home, '.claude.json')]
  const anyMentionsClevr = (paths) => paths.some(p => fs.existsSync(p) && fileMentionsClevr(p))
  return {
    llmGateway,
    mcp: {
      claudeDesktop: anyMentionsClevr(claudeCfg),
      cursor: anyMentionsClevr(cursorCfg),
      claudeCode: anyMentionsClevr(claudeCodeCfg)
    }
  }
}

function assess (entry, sig) {
  const ev = []; let via = 'none'
  const llm = sig.llmGateway.routesClevr
  if (llm) ev.push(`LLM traffic routed through Clevr gateway (${sig.llmGateway.url})`)
  else if (sig.llmGateway.configured) ev.push(`LLM base URL set but points elsewhere (${sig.llmGateway.url})`)

  let mcp = false
  if (entry.id === 'claude-desktop' && sig.mcp.claudeDesktop) { mcp = true }
  if (entry.id === 'cursor' && sig.mcp.cursor) { mcp = true }
  if (entry.id === 'claude-code' && sig.mcp.claudeCode) { mcp = true }
  if (mcp) ev.push('Clevr-fronted MCP server found in this client\'s config')

  if (entry.kind === 'local-model') {
    ev.push('Local model runner: no cloud gateway to route through; govern its tool use via a local MCP proxy')
    return { monitored: false, via: 'local', evidence: ev }
  }
  const monitored = !!(llm || mcp)
  if (monitored) via = mcp ? 'mcp' : 'llm-gateway'
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
  for (const p of procs) {
    for (const entry of CATALOG) {
      if (entry.re.test(p.cmd)) {
        let c = byId.get(entry.id)
        if (!c) {
          c = { id: entry.id, label: entry.label, kind: entry.kind, pid: p.pid, procs: 0, ...assess(entry, sig) }
          byId.set(entry.id, c)
        }
        c.procs += 1
        break
      }
    }
  }
  const clients = [...byId.values()]
  const summary = {
    running: clients.length,
    monitored: clients.filter(c => c.monitored).length,
    shadow: clients.filter(c => !c.monitored).length
  }
  return {
    host: os.hostname(), os: `${process.platform} ${os.release()}`, user: os.userInfo().username,
    version: VERSION, ts: new Date().toISOString(), machine: sig, clients, summary
  }
}

function printReport (report) {
  const { clients, summary } = report
  if (args.has('--json')) { console.log(JSON.stringify(report, null, 2)); return }
  console.log(`\nClevr endpoint agent  ${VERSION}   ${report.host}  (${report.os})  user ${report.user}`)
  console.log(`Clevr gateway: ${CLEVR_HOST || '(not configured)'}\n${'-'.repeat(70)}`)
  if (!clients.length) console.log('No known AI clients detected running.')
  for (const c of clients) {
    const tag = c.monitored ? 'GOVERNED' : (c.kind === 'local-model' ? 'LOCAL   ' : 'SHADOW  ')
    console.log(`[${tag}] ${c.label}  (pid ${c.pid}, ${c.kind})`)
    for (const e of c.evidence) console.log(`           - ${e}`)
  }
  console.log(`${'-'.repeat(70)}`)
  console.log(`Running: ${summary.running}   Governed: ${summary.monitored}   Shadow: ${summary.shadow}`)
  if (summary.shadow) console.log('Shadow AI present: an AI client is running with no evidence it is governed by Clevr.')
  console.log()
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
  printReport(report)
  if (args.has('--report')) await postReport(report)
}

await runOnce()

// --watch: keep scanning so the fleet view stays live (a laptop that stops
// reporting goes stale server-side). Bounded to >= 30s to stay light.
if (args.has('--watch')) {
  const interval = Math.max(30, Number(process.env.CLEVR_INTERVAL) || 300) * 1000
  console.log(`Watching — re-scanning every ${interval / 1000}s. Ctrl-C to stop.`)
  setInterval(runOnce, interval)
}
