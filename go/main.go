// Clevr endpoint agent — Go port of clevr-endpoint.mjs. Userland, cross-platform
// (macOS / Windows / Linux), zero external deps (stdlib only) -> a ~10 MB static
// binary, no runtime to install. Same behaviour and same wire contract as the .mjs:
//   clevr-endpoint            print a posture report for this machine
//   clevr-endpoint --report   also POST it to Clevr (needs CLEVR_URL + CLEVR_API_KEY)
//   clevr-endpoint --json     machine-readable output
//   clevr-endpoint --watch    re-run every CLEVR_INTERVAL seconds (default 300)
//
// It lists the AI clients running on this machine and, for each, whether there is
// evidence it routes through Clevr (an LLM gateway base URL, or a Clevr-fronted MCP
// server in the client's config). Anything with no such evidence is SHADOW AI.
// Userland, detection-only: it sees processes and config, not kernel syscalls, and
// it does not block. Each report is signed with a per-machine Ed25519 device key.
package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
)

const version = "0.1.0"

var (
	clevrURL   = os.Getenv("CLEVR_URL")
	clevrKey   = os.Getenv("CLEVR_API_KEY")
	gatewayURL = firstNonEmpty(os.Getenv("CLEVR_GATEWAY_URL"), os.Getenv("CLEVR_URL"))
	mcpMarker  = strings.ToLower(firstNonEmpty(os.Getenv("CLEVR_MCP_MARKER"), "clevr"))
	clevrHost  = hostOf(gatewayURL)
)

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
func hostOf(u string) string {
	if u == "" {
		return ""
	}
	p, err := url.Parse(u)
	if err != nil {
		return ""
	}
	return p.Host
}

type catEntry struct {
	id, label, kind string
	re              *regexp.Regexp
}

// AI-client catalog. Ordered specific -> generic; each process is assigned to the
// first entry it matches. Mirrors the .mjs CATALOG exactly.
var catalog = []catEntry{
	{"claude-code", "Claude Code (CLI)", "cli-agent", regexp.MustCompile(`(?i)claude[-_ ]?code|@anthropic-ai[/\\]claude-code`)},
	{"cursor", "Cursor", "ide-agent", regexp.MustCompile(`(?i)(?:^|[/\\ ])cursor(?:\.exe| helper|$|[/\\ ])`)},
	{"windsurf", "Windsurf", "ide-agent", regexp.MustCompile(`(?i)windsurf`)},
	{"chatgpt", "ChatGPT desktop", "desktop-assistant", regexp.MustCompile(`(?i)chatgpt`)},
	{"claude-desktop", "Claude Desktop", "desktop-assistant", regexp.MustCompile(`(?i)(?:^|[/\\ ])claude(?:\.exe| helper|$|[/\\ ])`)},
	{"ollama", "Ollama (local model)", "local-model", regexp.MustCompile(`(?i)ollama`)},
	{"lmstudio", "LM Studio (local model)", "local-model", regexp.MustCompile(`(?i)lm[-_ ]?studio`)},
	{"py-agent", "Python agent", "custom-agent", regexp.MustCompile(`(?i)python[0-9.]*\b.*(langchain|langgraph|crewai|autogen|llama[_-]?index|pydantic_ai|smolagents|@?modelcontextprotocol[/\\]server)`)},
	{"node-agent", "Node agent", "custom-agent", regexp.MustCompile(`(?i)\bnode\b.*(langchain|@langchain|crewai|@modelcontextprotocol[/\\]server|ai-sdk|@openai[/\\]agents)`)},
}

type proc struct{ pid, cmd string }

func listProcesses() []proc {
	if runtime.GOOS == "windows" {
		out, err := exec.Command("tasklist", "/fo", "csv", "/nh").Output()
		if err != nil {
			return nil
		}
		var ps []proc
		for _, line := range strings.Split(string(out), "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			fields := csvFields(line)
			name, pid := "", "?"
			if len(fields) > 0 {
				name = fields[0]
			}
			if len(fields) > 1 {
				pid = fields[1]
			}
			ps = append(ps, proc{pid: pid, cmd: name}) // Windows: exe name only
		}
		return ps
	}
	out, err := exec.Command("ps", "-axww", "-o", "pid=,command=").Output()
	if err != nil {
		return nil
	}
	var ps []proc
	for _, line := range strings.Split(string(out), "\n") {
		t := strings.TrimSpace(line)
		if t == "" {
			continue
		}
		sp := strings.IndexByte(t, ' ')
		if sp < 0 {
			ps = append(ps, proc{pid: t})
		} else {
			ps = append(ps, proc{pid: t[:sp], cmd: strings.TrimSpace(t[sp+1:])})
		}
	}
	return ps
}

// Minimal CSV field extractor for tasklist's quoted output ("a","b",...).
func csvFields(line string) []string {
	var out []string
	inQ := false
	var b strings.Builder
	for _, r := range line {
		switch {
		case r == '"':
			inQ = !inQ
		case r == ',' && !inQ:
			out = append(out, b.String())
			b.Reset()
		default:
			b.WriteRune(r)
		}
	}
	out = append(out, b.String())
	return out
}

type llmGateway struct {
	Configured  bool   `json:"configured"`
	URL         string `json:"url"`
	RoutesClevr bool   `json:"routesClevr"`
}
type mcpSignals struct {
	ClaudeDesktop bool `json:"claudeDesktop"`
	Cursor        bool `json:"cursor"`
	ClaudeCode    bool `json:"claudeCode"`
}
type machine struct {
	LLMGateway llmGateway `json:"llmGateway"`
	MCP        mcpSignals `json:"mcp"`
}

func fileMentionsClevr(p string) bool {
	b, err := os.ReadFile(p)
	if err != nil {
		return false
	}
	return strings.Contains(strings.ToLower(string(b)), mcpMarker)
}
func anyMentionsClevr(paths []string) bool {
	for _, p := range paths {
		if fileMentionsClevr(p) {
			return true
		}
	}
	return false
}

func machineSignals() machine {
	home, _ := os.UserHomeDir()
	appData := firstNonEmpty(os.Getenv("APPDATA"), filepath.Join(home, "AppData", "Roaming"))
	llmBase := firstNonEmpty(firstNonEmpty(os.Getenv("ANTHROPIC_BASE_URL"), os.Getenv("OPENAI_BASE_URL")), os.Getenv("CLEVR_LLM_BASE_URL"))
	llmHost := hostOf(llmBase)
	gw := llmGateway{
		Configured:  llmBase != "",
		URL:         llmBase,
		RoutesClevr: llmBase != "" && clevrHost != "" && llmHost == clevrHost,
	}
	claudeCfg := []string{
		filepath.Join(home, "Library", "Application Support", "Claude", "claude_desktop_config.json"),
		filepath.Join(appData, "Claude", "claude_desktop_config.json"),
		filepath.Join(home, ".config", "Claude", "claude_desktop_config.json"),
	}
	cursorCfg := []string{
		filepath.Join(home, ".cursor", "mcp.json"),
		filepath.Join(home, "Library", "Application Support", "Cursor", "User", "mcp.json"),
		filepath.Join(appData, "Cursor", "User", "mcp.json"),
	}
	claudeCodeCfg := []string{filepath.Join(home, ".claude", "settings.json"), filepath.Join(home, ".claude.json")}
	return machine{
		LLMGateway: gw,
		MCP: mcpSignals{
			ClaudeDesktop: anyMentionsClevr(claudeCfg),
			Cursor:        anyMentionsClevr(cursorCfg),
			ClaudeCode:    anyMentionsClevr(claudeCodeCfg),
		},
	}
}

type client struct {
	ID        string   `json:"id"`
	Label     string   `json:"label"`
	Kind      string   `json:"kind"`
	PID       string   `json:"pid"`
	Procs     int      `json:"procs"`
	Monitored bool     `json:"monitored"`
	Via       string   `json:"via"`
	Evidence  []string `json:"evidence"`
}

func assess(e catEntry, sig machine) (monitored bool, via string, evidence []string) {
	via = "none"
	ev := []string{}
	llm := sig.LLMGateway.RoutesClevr
	if llm {
		ev = append(ev, "LLM traffic routed through Clevr gateway ("+sig.LLMGateway.URL+")")
	} else if sig.LLMGateway.Configured {
		ev = append(ev, "LLM base URL set but points elsewhere ("+sig.LLMGateway.URL+")")
	}
	mcp := false
	if e.id == "claude-desktop" && sig.MCP.ClaudeDesktop {
		mcp = true
	}
	if e.id == "cursor" && sig.MCP.Cursor {
		mcp = true
	}
	if e.id == "claude-code" && sig.MCP.ClaudeCode {
		mcp = true
	}
	if mcp {
		ev = append(ev, "Clevr-fronted MCP server found in this client's config")
	}
	if e.kind == "local-model" {
		ev = append(ev, "Local model runner: no cloud gateway to route through; govern its tool use via a local MCP proxy")
		return false, "local", ev
	}
	monitored = llm || mcp
	if monitored {
		if mcp {
			via = "mcp"
		} else {
			via = "llm-gateway"
		}
	} else {
		ev = append(ev, "No evidence this client routes through Clevr")
	}
	return monitored, via, ev
}

type summary struct {
	Running   int `json:"running"`
	Monitored int `json:"monitored"`
	Shadow    int `json:"shadow"`
}
type report struct {
	Host    string   `json:"host"`
	OS      string   `json:"os"`
	User    string   `json:"user"`
	Version string   `json:"version"`
	TS      string   `json:"ts"`
	Machine machine  `json:"machine"`
	Clients []client `json:"clients"`
	Summary summary  `json:"summary"`
}

func buildReport() report {
	sig := machineSignals()
	procs := listProcesses()
	// One entry per detected client (a desktop app spawns many helpers — count
	// them, don't list the app ten times). First match is the representative.
	order := []string{}
	byID := map[string]*client{}
	for _, p := range procs {
		for _, e := range catalog {
			if e.re.MatchString(p.cmd) {
				c, ok := byID[e.id]
				if !ok {
					mon, via, ev := assess(e, sig)
					c = &client{ID: e.id, Label: e.label, Kind: e.kind, PID: p.pid, Monitored: mon, Via: via, Evidence: ev}
					byID[e.id] = c
					order = append(order, e.id)
				}
				c.Procs++
				break
			}
		}
	}
	clients := make([]client, 0, len(order))
	mon, shadow := 0, 0
	for _, id := range order {
		c := byID[id]
		clients = append(clients, *c)
		if c.Monitored {
			mon++
		} else if c.Via != "local" {
			shadow++
		}
	}
	host, _ := os.Hostname()
	uname := "?"
	if u, err := user.Current(); err == nil {
		uname = u.Username
	}
	return report{
		Host: host, OS: runtime.GOOS, User: uname, Version: version,
		TS: time.Now().UTC().Format("2006-01-02T15:04:05.000Z"), Machine: sig,
		Clients: clients, Summary: summary{Running: len(clients), Monitored: mon, Shadow: shadow},
	}
}

func printReport(r report) {
	if hasArg("--json") {
		b, _ := json.MarshalIndent(r, "", "  ")
		fmt.Println(string(b))
		return
	}
	fmt.Printf("\nClevr endpoint agent  %s   %s  (%s)  user %s\n", version, r.Host, r.OS, r.User)
	gw := clevrHost
	if gw == "" {
		gw = "(not configured)"
	}
	fmt.Printf("Clevr gateway: %s\n%s\n", gw, strings.Repeat("-", 70))
	if len(r.Clients) == 0 {
		fmt.Println("No known AI clients detected running.")
	}
	for _, c := range r.Clients {
		tag := "SHADOW  "
		if c.Monitored {
			tag = "GOVERNED"
		} else if c.Kind == "local-model" {
			tag = "LOCAL   "
		}
		fmt.Printf("[%s] %s  (pid %s, %s)\n", tag, c.Label, c.PID, c.Kind)
		for _, e := range c.Evidence {
			fmt.Printf("           - %s\n", e)
		}
	}
	fmt.Println(strings.Repeat("-", 70))
	fmt.Printf("Running: %d   Governed: %d   Shadow: %d\n", r.Summary.Running, r.Summary.Monitored, r.Summary.Shadow)
	if r.Summary.Shadow > 0 {
		fmt.Println("Shadow AI present: an AI client is running with no evidence it is governed by Clevr.")
	}
	fmt.Println()
}

// ── Device identity: a per-machine Ed25519 keypair, persisted userland (0600),
// used to sign each report. Same wire contract as the .mjs + the brain verifier:
// raw 32-byte public key (base64) + "ed25519:"+base64(sig) over signingString.
func keyPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".clevr", "endpoint-key.json")
}

// Stored as the raw 32-byte seed (not the 64-byte key or PKCS8), so the Go and the
// Node agents produce the SAME key from the SAME file — a machine can switch between
// them with no spurious key_changed.
type keyFile struct {
	Seed string `json:"seed"` // base64 of the raw 32-byte ed25519 seed
	Pub  string `json:"pub"`  // base64 of the raw 32-byte public key
}

func deviceKeypair() (ed25519.PrivateKey, string) {
	if b, err := os.ReadFile(keyPath()); err == nil {
		var kf keyFile
		if json.Unmarshal(b, &kf) == nil {
			if seed, e := base64.StdEncoding.DecodeString(kf.Seed); e == nil && len(seed) == ed25519.SeedSize {
				return ed25519.NewKeyFromSeed(seed), kf.Pub
			}
		}
	}
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	kf := keyFile{Seed: base64.StdEncoding.EncodeToString(priv.Seed()), Pub: base64.StdEncoding.EncodeToString(pub)}
	if b, err := json.Marshal(kf); err == nil {
		_ = os.MkdirAll(filepath.Dir(keyPath()), 0o700)
		_ = os.WriteFile(keyPath(), b, 0o600)
	}
	return priv, kf.Pub
}

// Deterministic, language-neutral signing string (scalars only — no JSON — so the
// JS agent, this Go agent, and the brain all build the identical bytes).
func signingString(r report) string {
	sigs := make([]string, 0, len(r.Clients))
	for _, c := range r.Clients {
		m := "0"
		if c.Monitored {
			m = "1"
		}
		sigs = append(sigs, c.ID+":"+m+":"+c.Via)
	}
	sort.Strings(sigs)
	return strings.Join([]string{
		r.Host, r.TS, r.Version,
		strconv.Itoa(r.Summary.Running), strconv.Itoa(r.Summary.Monitored), strconv.Itoa(r.Summary.Shadow),
		strings.Join(sigs, ","),
	}, "\n")
}

func postReport(r report) bool {
	if clevrURL == "" || clevrKey == "" {
		fmt.Fprintln(os.Stderr, "--report needs CLEVR_URL and CLEVR_API_KEY.")
		return false
	}
	// Sign (best-effort — an unsigned report is still accepted, just marked unsigned).
	body := map[string]any{}
	rb, _ := json.Marshal(r)
	_ = json.Unmarshal(rb, &body)
	if priv, pub := deviceKeypair(); priv != nil {
		sig := ed25519.Sign(priv, []byte(signingString(r)))
		body["device_key"] = pub
		body["sig"] = "ed25519:" + base64.StdEncoding.EncodeToString(sig)
	}
	payload, _ := json.Marshal(body)
	req, err := http.NewRequest("POST", strings.TrimRight(clevrURL, "/")+"/v1/endpoints", bytes.NewReader(payload))
	if err != nil {
		fmt.Fprintln(os.Stderr, "Report failed:", err)
		return false
	}
	req.Header.Set("Authorization", "Bearer "+clevrKey)
	req.Header.Set("Content-Type", "application/json")
	res, err := (&http.Client{Timeout: 15 * time.Second}).Do(req)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Report failed:", err)
		return false
	}
	defer res.Body.Close()
	if res.StatusCode >= 200 && res.StatusCode < 300 {
		fmt.Printf("Reported to Clevr (%d).\n", res.StatusCode)
		return true
	}
	b, _ := io.ReadAll(res.Body)
	fmt.Printf("Report failed: HTTP %d %s\n", res.StatusCode, string(b))
	return false
}

func hasArg(a string) bool {
	for _, x := range os.Args[1:] {
		if x == a {
			return true
		}
	}
	return false
}

func runOnce() {
	r := buildReport()
	printReport(r)
	if hasArg("--report") {
		postReport(r)
	}
}

func main() {
	runOnce()
	if hasArg("--watch") {
		secs := 300
		if v, err := strconv.Atoi(os.Getenv("CLEVR_INTERVAL")); err == nil && v >= 30 {
			secs = v
		}
		fmt.Printf("Watching — re-scanning every %ds. Ctrl-C to stop.\n", secs)
		for range time.Tick(time.Duration(secs) * time.Second) {
			runOnce()
		}
	}
}
