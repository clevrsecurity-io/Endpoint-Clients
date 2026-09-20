// clevr-scan — a one-shot, read-only inventory of the AI assistants installed on a
// machine and of what they are wired to.
//
// This is NOT the fleet agent (../go). It is the artifact you hand to someone who
// does not know you yet, so three properties are non-negotiable:
//
//  1. It opens no network connection, ever. There is no URL, no key, no telemetry.
//  2. It reads, never writes, except the one report file it is asked to produce.
//  3. It never prints a secret. MCP server configs carry API keys in their env
//     blocks; only server NAMES are read out.
//
// It also judges governance vendor-neutrally: a gate belonging to someone else is
// reported as a gate. A scan that calls every competitor's install "ungoverned" is
// an advert, and the reader can tell.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"time"
)

const version = "1.0.0"

// ── i18n ─────────────────────────────────────────────────────────────────────
// French by default: every current recipient is French. Flip defaultLang to "en"
// if that stops being true.
const defaultLang = "fr"

var lang = defaultLang

func t(fr, en string) string {
	if lang == "en" {
		return en
	}
	return fr
}

// ── what we look for ─────────────────────────────────────────────────────────

type tool struct {
	id    string
	label string
	kind  string // "coding" | "desktop" | "ide" | "local-model" | "cli"
	// Any of these existing means the tool is installed. Paths are expanded
	// against the home directory and the platform's app/data directories.
	paths []string
	// A binary on PATH is also proof of an install.
	bins []string
	// A VS Code extension id prefix (the folder is "<id>-<version>").
	vscodeExt string
	// Matches a running process command line.
	proc *regexp.Regexp
}

var tools = []tool{
	{
		id: "claude-code", label: "Claude Code", kind: "coding",
		paths: []string{"~/.claude", "~/.claude.json"},
		bins:  []string{"claude"},
		proc:  regexp.MustCompile(`(?i)claude[-_ ]?code|@anthropic-ai[/\\]claude-code`),
	},
	{
		id: "cursor", label: "Cursor", kind: "coding",
		paths: []string{"~/.cursor", "/Applications/Cursor.app", "@LOCALAPPDATA@/Programs/cursor", "@LOCALAPPDATA@/Programs/Cursor"},
		proc:  regexp.MustCompile(`(?i)cursor\.app|cursor\.exe|cursor helper`),
	},
	{
		id: "codex", label: "Codex CLI", kind: "coding",
		paths: []string{"~/.codex"},
		bins:  []string{"codex"},
		proc:  regexp.MustCompile(`(?i)(?:^|[/\\ ])codex(?:\.exe|$|[/\\ ])`),
	},
	{
		id: "copilot", label: "GitHub Copilot", kind: "coding",
		vscodeExt: "github.copilot",
	},
	{
		id: "cline", label: "Cline", kind: "coding",
		vscodeExt: "saoudrizwan.claude-dev",
	},
	{
		id: "roo", label: "Roo Code", kind: "coding",
		vscodeExt: "rooveterinaryinc.roo-cline",
	},
	{
		id: "continue", label: "Continue", kind: "coding",
		vscodeExt: "continue.continue",
		paths:     []string{"~/.continue"},
	},
	{
		id: "gemini-cli", label: "Gemini CLI", kind: "coding",
		paths: []string{"~/.gemini"},
		bins:  []string{"gemini"},
	},
	{
		id: "windsurf", label: "Windsurf", kind: "coding",
		paths: []string{"~/.windsurf", "/Applications/Windsurf.app", "@LOCALAPPDATA@/Programs/Windsurf"},
		proc:  regexp.MustCompile(`(?i)windsurf`),
	},
	{
		id: "claude-desktop", label: "Claude Desktop", kind: "desktop",
		paths: []string{"/Applications/Claude.app", "@APPDATA@/Claude", "~/.config/Claude"},
		proc:  regexp.MustCompile(`(?i)claude\.app|claude\.exe|claude helper`),
	},
	{
		id: "chatgpt", label: "ChatGPT (application)", kind: "desktop",
		paths: []string{"/Applications/ChatGPT.app", "@LOCALAPPDATA@/Programs/ChatGPT"},
		proc:  regexp.MustCompile(`(?i)chatgpt`),
	},
	{
		id: "vscode", label: "VS Code", kind: "ide",
		paths: []string{"/Applications/Visual Studio Code.app", "@LOCALAPPDATA@/Programs/Microsoft VS Code", "~/.vscode"},
		bins:  []string{"code"},
	},
	{
		id: "ollama", label: "Ollama", kind: "local-model",
		paths: []string{"~/.ollama", "/Applications/Ollama.app"},
		bins:  []string{"ollama"},
		proc:  regexp.MustCompile(`(?i)ollama`),
	},
	{
		id: "lmstudio", label: "LM Studio", kind: "local-model",
		paths: []string{"~/.lmstudio", "/Applications/LM Studio.app", "@LOCALAPPDATA@/Programs/lm-studio"},
		proc:  regexp.MustCompile(`(?i)lm[-_ ]?studio`),
	},
}

// Process lines are assigned to the FIRST tool that matches, in this order. A
// host application claims its own bundled frameworks before a CLI of the same
// name can: ChatGPT ships a "Codex Framework" that is not the Codex CLI.
var procOrder = []string{"claude-code", "chatgpt", "claude-desktop", "cursor", "windsurf", "codex", "ollama", "lmstudio"}

func runningIDs(procs []string) map[string]bool {
	byID := map[string]tool{}
	for _, tl := range tools {
		byID[tl.id] = tl
	}
	out := map[string]bool{}
	for _, line := range procs {
		for _, id := range procOrder {
			tl, ok := byID[id]
			if !ok || tl.proc == nil || !tl.proc.MatchString(line) {
				continue
			}
			out[id] = true
			break
		}
	}
	return out
}

// ── paths ────────────────────────────────────────────────────────────────────

var home, _ = os.UserHomeDir()

func appData() string {
	if v := os.Getenv("APPDATA"); v != "" {
		return v
	}
	return filepath.Join(home, "AppData", "Roaming")
}

func localAppData() string {
	if v := os.Getenv("LOCALAPPDATA"); v != "" {
		return v
	}
	return filepath.Join(home, "AppData", "Local")
}

func expand(p string) string {
	p = strings.ReplaceAll(p, "@APPDATA@", appData())
	p = strings.ReplaceAll(p, "@LOCALAPPDATA@", localAppData())
	if strings.HasPrefix(p, "~/") {
		p = filepath.Join(home, p[2:])
	}
	return filepath.FromSlash(p)
}

func exists(p string) bool {
	_, err := os.Stat(expand(p))
	return err == nil
}

func onPath(bin string) bool {
	_, err := exec.LookPath(bin)
	return err == nil
}

func vscodeExtDirs() []string {
	var out []string
	for _, root := range []string{filepath.Join(home, ".vscode", "extensions"), filepath.Join(home, ".vscode-insiders", "extensions"), filepath.Join(home, ".cursor", "extensions")} {
		entries, err := os.ReadDir(root)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() {
				out = append(out, strings.ToLower(e.Name()))
			}
		}
	}
	return out
}

// ── running processes ────────────────────────────────────────────────────────

func processes() []string {
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("tasklist", "/fo", "csv", "/nh")
	} else {
		cmd = exec.Command("ps", "-axo", "command=")
	}
	out, err := cmd.Output()
	if err != nil {
		return nil
	}
	var lines []string
	for _, l := range strings.Split(string(out), "\n") {
		if l = strings.TrimSpace(l); l != "" {
			lines = append(lines, l)
		}
	}
	return lines
}

// ── what each assistant is wired to ──────────────────────────────────────────

// mcpConfig is every place a host lists its MCP servers. The value shape differs
// per host, so only the keys (server names) are read. Their env blocks hold API
// keys and are never touched.
var mcpConfigs = map[string][]string{
	"claude-desktop": {
		"~/Library/Application Support/Claude/claude_desktop_config.json",
		"@APPDATA@/Claude/claude_desktop_config.json",
		"~/.config/Claude/claude_desktop_config.json",
	},
	"cursor":      {"~/.cursor/mcp.json"},
	"claude-code": {"~/.claude.json", "~/.claude/settings.json"},
	"copilot": {
		"~/Library/Application Support/Code/User/mcp.json",
		"@APPDATA@/Code/User/mcp.json",
		"~/.config/Code/User/mcp.json",
	},
	"windsurf":   {"~/.codeium/windsurf/mcp_config.json", "~/.windsurf/mcp.json"},
	"gemini-cli": {"~/.gemini/settings.json"},
}

func mcpServers(id string) []string {
	seen := map[string]bool{}
	var names []string
	for _, p := range mcpConfigs[id] {
		b, err := os.ReadFile(expand(p))
		if err != nil {
			continue
		}
		var doc map[string]json.RawMessage
		if json.Unmarshal(b, &doc) != nil {
			continue
		}
		collect := func(raw json.RawMessage) {
			var m map[string]json.RawMessage
			if json.Unmarshal(raw, &m) != nil {
				return
			}
			for name := range m {
				if !seen[name] {
					seen[name] = true
					names = append(names, name)
				}
			}
		}
		for _, key := range []string{"mcpServers", "servers"} {
			if raw, ok := doc[key]; ok {
				collect(raw)
			}
		}
		// Claude Code also stores servers per project, under projects.<path>.mcpServers.
		if raw, ok := doc["projects"]; ok {
			var projects map[string]map[string]json.RawMessage
			if json.Unmarshal(raw, &projects) == nil {
				for _, proj := range projects {
					if inner, ok := proj["mcpServers"]; ok {
						collect(inner)
					}
				}
			}
		}
	}
	sort.Strings(names)
	return names
}

// A gate is anything that inspects a tool call before it runs. Reported by the
// name of whatever is configured, not by vendor.
type gate struct {
	kind   string // "hook" | "gateway"
	detail string
}

var hookFiles = map[string][]string{
	"claude-code": {"~/.claude/settings.json"},
	"cursor":      {"~/.cursor/hooks.json"},
}

var hookKey = regexp.MustCompile(`(?i)"(pre_?tool_?use|preToolUse|PreToolUse)"`)
var commandVal = regexp.MustCompile(`(?i)"command"\s*:\s*"([^"]{0,200})"`)

func gatesFor(id string) []gate {
	var gs []gate
	for _, p := range hookFiles[id] {
		b, err := os.ReadFile(expand(p))
		if err != nil {
			continue
		}
		if !hookKey.Match(b) {
			continue
		}
		detail := t("un contrôle est branché avant chaque appel d'outil", "a check runs before every tool call")
		if m := commandVal.FindSubmatch(b); m != nil {
			detail = filepath.Base(strings.Trim(string(m[1]), `" `))
		}
		gs = append(gs, gate{"hook", detail})
	}
	// A model endpoint pointed somewhere other than the provider means the
	// conversation goes through an intermediary, whoever it belongs to.
	for _, env := range []string{"ANTHROPIC_BASE_URL", "OPENAI_BASE_URL", "OPENAI_API_BASE"} {
		if v := os.Getenv(env); v != "" && !strings.Contains(v, "api.anthropic.com") && !strings.Contains(v, "api.openai.com") {
			gs = append(gs, gate{"gateway", v})
			break
		}
	}
	return gs
}

// ── the scan ─────────────────────────────────────────────────────────────────

type finding struct {
	ID         string   `json:"id"`
	Label      string   `json:"label"`
	Kind       string   `json:"kind"`
	Installed  bool     `json:"installed"`
	Running    bool     `json:"running"`
	MCPServers []string `json:"mcp_servers"`
	Gates      []string `json:"gates"`
	Evidence   string   `json:"evidence"`
}

type result struct {
	Tool       string    `json:"tool"`
	Version    string    `json:"version"`
	Host       string    `json:"host"`
	OS         string    `json:"os"`
	User       string    `json:"user"`
	Scanned    time.Time `json:"scanned_at"`
	Findings   []finding `json:"findings"`
	Installed  int       `json:"installed"`
	Ungoverned int       `json:"ungoverned"`
}

func scan() result {
	running := runningIDs(processes())
	exts := vscodeExtDirs()
	hostname, _ := os.Hostname()
	user := os.Getenv("USER")
	if user == "" {
		user = os.Getenv("USERNAME")
	}

	r := result{Tool: "clevr-scan", Version: version, Host: hostname, OS: runtime.GOOS, User: user, Scanned: time.Now()}

	for _, tl := range tools {
		f := finding{ID: tl.id, Label: tl.label, Kind: tl.kind}

		for _, p := range tl.paths {
			if exists(p) {
				f.Installed, f.Evidence = true, expand(p)
				break
			}
		}
		if !f.Installed {
			for _, b := range tl.bins {
				if onPath(b) {
					f.Installed, f.Evidence = true, b+t(" présent dans le PATH", " on PATH")
					break
				}
			}
		}
		if !f.Installed && tl.vscodeExt != "" {
			for _, e := range exts {
				if strings.HasPrefix(e, tl.vscodeExt) {
					f.Installed, f.Evidence = true, t("extension ", "extension ")+e
					break
				}
			}
		}
		if running[tl.id] {
			f.Running = true
			f.Installed = true
			if f.Evidence == "" {
				f.Evidence = t("processus en cours d'exécution", "process running")
			}
		}
		if !f.Installed {
			continue
		}

		f.MCPServers = mcpServers(tl.id)
		for _, g := range gatesFor(tl.id) {
			f.Gates = append(f.Gates, g.kind+": "+g.detail)
		}
		r.Findings = append(r.Findings, f)
	}

	for _, f := range r.Findings {
		r.Installed++
		// A local model runner has no tool calls of its own to gate; it is
		// reported, not counted as ungoverned.
		if len(f.Gates) == 0 && f.Kind != "local-model" && f.Kind != "ide" {
			r.Ungoverned++
		}
	}
	return r
}

// ── output ───────────────────────────────────────────────────────────────────

func render(r result) string {
	var b strings.Builder
	w := func(f string, a ...any) { fmt.Fprintf(&b, f+"\n", a...) }

	w("")
	w(t("Inventaire des assistants IA de ce poste", "AI assistant inventory for this machine"))
	w(strings.Repeat("=", 62))
	w("")
	w("%-12s %s", t("Poste", "Host"), r.Host)
	w("%-12s %s", t("Système", "System"), r.OS)
	w("%-12s %s", t("Session", "Session"), r.User)
	w("%-12s %s", t("Date", "Date"), r.Scanned.Format("2006-01-02 15:04"))
	w("")
	w(t("Lecture seule. Aucune connexion réseau n'est ouverte, rien n'est envoyé,",
		"Read only. No network connection is opened, nothing is sent,"))
	w(t("et aucune clé ni aucun secret n'est lu ni affiché.",
		"and no key or secret is read or printed."))
	w("")

	if len(r.Findings) == 0 {
		w(t("Aucun assistant IA détecté sur ce poste.", "No AI assistant found on this machine."))
		w("")
		return b.String()
	}

	for _, f := range r.Findings {
		state := t("installé", "installed")
		if f.Running {
			state = t("en cours d'exécution", "running")
		}
		w("%s  (%s)", f.Label, state)
		if f.Evidence != "" {
			w("    %-14s %s", t("trouvé ici", "found at"), f.Evidence)
		}
		if len(f.MCPServers) > 0 {
			w("    %-14s %d  %s", t("connecteurs", "connectors"), len(f.MCPServers), strings.Join(f.MCPServers, ", "))
		}
		if len(f.Gates) > 0 {
			for _, g := range f.Gates {
				w("    %-14s %s", t("contrôle", "gate"), g)
			}
		} else if f.Kind == "local-model" {
			w("    %-14s %s", t("contrôle", "gate"), t("modèle local, pas d'appel sortant à contrôler ici", "local model, no outbound call to gate here"))
		} else if f.Kind == "ide" {
			w("    %-14s %s", t("contrôle", "gate"), t("éditeur, voir les assistants qu'il héberge", "editor, see the assistants it hosts"))
		} else {
			w("    %-14s %s", t("contrôle", "gate"), t("AUCUN", "NONE"))
		}
		w("")
	}

	w(strings.Repeat("-", 62))
	w(t("%d assistant(s) présent(s) sur ce poste, %d sans aucun contrôle.",
		"%d assistant(s) present on this machine, %d with no gate at all."), r.Installed, r.Ungoverned)
	w("")
	if r.Ungoverned > 0 {
		w(t("Un assistant sans contrôle exécute des commandes et lit des fichiers",
			"An assistant with no gate runs commands and reads files"))
		w(t("avec les droits de la session ouverte. Rien ne relit ce qu'il fait.",
			"with the rights of the open session. Nothing reviews what it does."))
		w("")
	}
	return b.String()
}

func main() {
	args := map[string]bool{}
	for _, a := range os.Args[1:] {
		args[strings.ToLower(a)] = true
	}
	if args["--en"] {
		lang = "en"
	}
	if args["--fr"] {
		lang = "fr"
	}
	if args["--help"] || args["-h"] {
		fmt.Println("clevr-scan " + version + "\n" +
			t("  Inventorie les assistants IA de ce poste. Lecture seule, aucun envoi.\n",
				"  Inventories the AI assistants on this machine. Read only, sends nothing.\n") +
			"  --json    " + t("sortie machine", "machine-readable output") + "\n" +
			"  --quiet   " + t("n'écrit pas le fichier de rapport", "do not write the report file") + "\n" +
			"  --en/--fr " + t("langue", "language"))
		return
	}

	r := scan()

	if args["--json"] {
		out, _ := json.MarshalIndent(r, "", "  ")
		fmt.Println(string(out))
		return
	}

	text := render(r)
	fmt.Print(text)

	if !args["--quiet"] {
		name := fmt.Sprintf("clevr-scan-%s-%s.txt", safe(r.Host), r.Scanned.Format("2006-01-02"))
		if err := os.WriteFile(name, []byte(text), 0o644); err == nil {
			fmt.Println(t("Rapport écrit dans ", "Report written to ") + name)
			fmt.Println("")
		}
	}
}

var unsafeChars = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

func safe(s string) string {
	s = unsafeChars.ReplaceAllString(s, "-")
	if s == "" {
		return "poste"
	}
	return s
}
