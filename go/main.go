// Clevr endpoint agent — Go port of clevr-endpoint.mjs. Userland, cross-platform
// (macOS / Windows / Linux), zero external deps (stdlib only) -> a ~10 MB static
// binary, no runtime to install. Same behaviour and same wire contract as the .mjs:
//
//	clevr-endpoint            print a posture report for this machine
//	clevr-endpoint --report   also POST it to Clevr (needs CLEVR_URL + CLEVR_API_KEY)
//	clevr-endpoint --json     machine-readable output
//	clevr-endpoint --watch    re-run every CLEVR_INTERVAL seconds (default 300)
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
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
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
	"unicode/utf16"
)

const version = "0.2.0"

var (
	clevrURL   = os.Getenv("CLEVR_URL")
	clevrKey   = os.Getenv("CLEVR_API_KEY")
	gatewayURL = firstNonEmpty(os.Getenv("CLEVR_GATEWAY_URL"), os.Getenv("CLEVR_URL"))
	mcpMarker  = strings.ToLower(firstNonEmpty(os.Getenv("CLEVR_MCP_MARKER"), "clevr"))
	mcpEntry   = firstNonEmpty(os.Getenv("CLEVR_MCP_NAME"), "clevr")
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
	inArgs          bool
}

// AI-client catalog. Ordered specific -> generic; each process is assigned to the
// first entry it matches. Mirrors the .mjs CATALOG exactly.
// An installed application is identified by its EXECUTABLE, never by its
// arguments. Matching the whole command line turned any process that merely
// mentioned a client's name into that client, which is invented shadow AI on a
// security screen. inArgs is the deliberate exception, for entries whose identity
// genuinely lives in the arguments because the executable is just an interpreter.
var catalog = []catEntry{
	{"claude-code", "Claude Code (CLI)", "cli-agent", regexp.MustCompile(`(?i)claude[-_ ]?code|@anthropic-ai[/\\]claude-code`), true},
	{"cursor", "Cursor", "ide-agent", regexp.MustCompile(`(?i)(?:^|[/\\ ])cursor(?:\.exe| helper|$|[/\\ ])`), false},
	{"windsurf", "Windsurf", "ide-agent", regexp.MustCompile(`(?i)windsurf`), false},
	{"chatgpt", "ChatGPT desktop", "desktop-assistant", regexp.MustCompile(`(?i)chatgpt`), false},
	{"claude-desktop", "Claude Desktop", "desktop-assistant", regexp.MustCompile(`(?i)(?:^|[/\\ ])claude(?:\.exe| helper|$|[/\\ ])`), false},
	// The command-line harnesses come AFTER the desktop applications on purpose.
	// ChatGPT desktop ships a binary literally named `codex` inside its own
	// bundle, and a machine carrying one product must not be reported as two.
	// Anchored to the END of the executable path: a harness is a binary CALLED
	// codex, not any path containing the word.
	{"gemini-cli", "Gemini CLI", "cli-agent", regexp.MustCompile(`(?i)(?:^|[/\\])gemini(?:\.exe)?$`), false},
	{"copilot-cli", "GitHub Copilot CLI", "cli-agent", regexp.MustCompile(`(?i)(?:^|[/\\])copilot(?:\.exe)?$`), false},
	{"augment", "Augment", "cli-agent", regexp.MustCompile(`(?i)(?:^|[/\\])(?:auggie|augment)(?:\.exe)?$`), false},
	{"codex", "Codex (CLI)", "cli-agent", regexp.MustCompile(`(?i)(?:^|[/\\])codex(?:\.exe)?$`), false},
	{"ollama", "Ollama (local model)", "local-model", regexp.MustCompile(`(?i)ollama`), false},
	{"lmstudio", "LM Studio (local model)", "local-model", regexp.MustCompile(`(?i)lm[-_ ]?studio`), false},
	{"py-agent", "Python agent", "custom-agent", regexp.MustCompile(`(?i)python[0-9.]*\b.*(langchain|langgraph|crewai|autogen|llama[_-]?index|pydantic_ai|smolagents|@?modelcontextprotocol[/\\]server)`), true},
	{"node-agent", "Node agent", "custom-agent", regexp.MustCompile(`(?i)\bnode\b.*(langchain|@langchain|crewai|@modelcontextprotocol[/\\]server|ai-sdk|@openai[/\\]agents)`), true},
}

type proc struct{ pid, cmd, exe string }

// pid -> last field, for a ps format whose final column is rendered unbounded.
func psByPID(args ...string) map[string]string {
	out, err := exec.Command("ps", args...).Output()
	if err != nil {
		return nil
	}
	m := map[string]string{}
	for _, line := range strings.Split(string(out), "\n") {
		t := strings.TrimSpace(line)
		if t == "" {
			continue
		}
		if sp := strings.IndexByte(t, ' '); sp > 0 {
			m[t[:sp]] = strings.TrimSpace(t[sp+1:])
		}
	}
	return m
}

// Where a client leaves a trace when it is NOT running. A person can install an
// AI client and open it once a month; the machine still carries it, and an
// inventory that only lists what happens to be running misses it. Kept in step
// with the .mjs installPaths.

// ── Browser extensions ──────────────────────────────────────────────────────
// An AI assistant living in the browser is an agent on this machine too. Reach
// is a FACT read from the extension's own manifest; "looks like an AI assistant"
// is a name match, reported as the heuristic it is. Chromium-family layouts
// only; Safari and Firefox are not read and are not claimed to be empty. Kept in
// step with the .mjs.
var aiExtensionName = regexp.MustCompile(`(?i)\b(chatgpt|openai|claude|anthropic|copilot|gemini|perplexity|mistral|le ?chat|monica|sider|merlin|harpa|jasper|writesonic|poe)\b`)

type browserExt struct {
	Browser string   `json:"browser"`
	Profile string   `json:"profile"`
	ID      string   `json:"id"`
	Name    string   `json:"name"`
	Version string   `json:"version,omitempty"`
	Reach   string   `json:"reach"`
	Hosts   []string `json:"hosts,omitempty"`
	State   string   `json:"state"`
	AI      bool     `json:"ai"`
}

func chromiumRoots(home, appData string) map[string][]string {
	local := firstNonEmpty(os.Getenv("LOCALAPPDATA"), filepath.Join(home, "AppData", "Local"))
	mac := func(parts ...string) string {
		return filepath.Join(append([]string{home, "Library", "Application Support"}, parts...)...)
	}
	return map[string][]string{
		"Chrome":   {mac("Google", "Chrome"), filepath.Join(local, "Google", "Chrome", "User Data"), filepath.Join(home, ".config", "google-chrome")},
		"Brave":    {mac("BraveSoftware", "Brave-Browser"), filepath.Join(local, "BraveSoftware", "Brave-Browser", "User Data"), filepath.Join(home, ".config", "BraveSoftware", "Brave-Browser")},
		"Edge":     {mac("Microsoft Edge"), filepath.Join(local, "Microsoft", "Edge", "User Data"), filepath.Join(home, ".config", "microsoft-edge")},
		"Arc":      {mac("Arc", "User Data")},
		"Vivaldi":  {mac("Vivaldi"), filepath.Join(local, "Vivaldi", "User Data"), filepath.Join(home, ".config", "vivaldi")},
		"Opera":    {mac("com.operasoftware.Opera"), filepath.Join(home, ".config", "opera")},
		"Chromium": {mac("Chromium"), filepath.Join(home, ".config", "chromium")},
	}
}

func dirsIn(p string) []string {
	entries, err := os.ReadDir(p)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() {
			out = append(out, e.Name())
		}
	}
	sort.Strings(out)
	return out
}

// A manifest may declare its name as a placeholder resolved from the locale files
// shipped beside it. Left unresolved it reads as __MSG_extName__ on screen.
func resolveExtName(versionDir, name, defaultLocale string) string {
	if !strings.HasPrefix(name, "__MSG_") || !strings.HasSuffix(name, "__") {
		return name
	}
	key := strings.TrimSuffix(strings.TrimPrefix(name, "__MSG_"), "__")
	for _, loc := range []string{defaultLocale, "en_US", "en"} {
		if loc == "" {
			continue
		}
		b, err := os.ReadFile(filepath.Join(versionDir, "_locales", loc, "messages.json"))
		if err != nil {
			continue
		}
		var msgs map[string]struct {
			Message string `json:"message"`
		}
		if json.Unmarshal(b, &msgs) != nil {
			continue
		}
		if v, ok := msgs[key]; ok && v.Message != "" {
			return v.Message
		}
		for k, v := range msgs {
			if strings.EqualFold(k, key) && v.Message != "" {
				return v.Message
			}
		}
	}
	return name
}

// Chromium keeps the enabled state apart from the manifest, in the profile's
// preference file: an extension with a non-empty disable reason list is off.
func chromiumStates(profileDir string) map[string]string {
	state := map[string]string{}
	for _, f := range []string{"Secure Preferences", "Preferences"} {
		b, err := os.ReadFile(filepath.Join(profileDir, f))
		if err != nil {
			continue
		}
		var d struct {
			Extensions struct {
				Settings map[string]struct {
					DisableReasons []json.RawMessage `json:"disable_reasons"`
				} `json:"settings"`
			} `json:"extensions"`
		}
		if json.Unmarshal(b, &d) != nil {
			continue
		}
		for id, v := range d.Extensions.Settings {
			if _, seen := state[id]; seen {
				continue
			}
			if len(v.DisableReasons) > 0 {
				state[id] = "disabled"
			} else {
				state[id] = "enabled"
			}
		}
	}
	return state
}

func reachOfHosts(hosts []string, unknown string) string {
	if hosts == nil {
		return unknown
	}
	for _, h := range hosts {
		if h == "<all_urls>" || h == "*://*/*" || h == "https://*/*" || h == "http://*/*" {
			return "every site"
		}
	}
	switch len(hosts) {
	case 0:
		return "no site access"
	case 1:
		return "1 site pattern"
	default:
		return fmt.Sprintf("%d site patterns", len(hosts))
	}
}

// Firefox keeps every add-on in one record per profile, with the enabled state
// and, on recent versions, the origins the user granted. Written to the format
// Mozilla documents; NOT verified against a live profile, because none existed on
// the machine this was built on. It can therefore only add a find, never remove
// one, and an absent field degrades to "not declared" rather than to a claim.
func firefoxRoots(home, appData string) []string {
	return []string{
		filepath.Join(home, "Library", "Application Support", "Firefox", "Profiles"),
		filepath.Join(appData, "Mozilla", "Firefox", "Profiles"),
		filepath.Join(home, ".mozilla", "firefox"),
	}
}

func firefoxExtensions(home, appData string) []browserExt {
	out := []browserExt{}
	for _, root := range firefoxRoots(home, appData) {
		if _, err := os.Stat(root); err != nil {
			continue
		}
		for _, profile := range dirsIn(root) {
			b, err := os.ReadFile(filepath.Join(root, profile, "extensions.json"))
			if err != nil {
				continue
			}
			var doc struct {
				Addons []struct {
					ID            string `json:"id"`
					Type          string `json:"type"`
					Location      string `json:"location"`
					Version       string `json:"version"`
					Active        bool   `json:"active"`
					UserDisabled  bool   `json:"userDisabled"`
					AppDisabled   bool   `json:"appDisabled"`
					DefaultLocale struct {
						Name        string `json:"name"`
						Description string `json:"description"`
					} `json:"defaultLocale"`
					UserPermissions struct {
						Origins []string `json:"origins"`
					} `json:"userPermissions"`
				} `json:"addons"`
			}
			if json.Unmarshal(b, &doc) != nil {
				continue
			}
			for _, a := range doc.Addons {
				if a.Type != "extension" {
					continue
				}
				// `app-profile` is the user's own profile, so a prefix rule on
				// `app-` would drop precisely what we came for. Anything
				// unrecognised is kept: listing one extra beats hiding a real one.
				if a.Location == "app-builtin" || a.Location == "app-global" || strings.HasPrefix(a.Location, "app-system") {
					continue
				}
				name := a.DefaultLocale.Name
				if name == "" {
					name = a.ID
				}
				hosts := a.UserPermissions.Origins
				reach := reachOfHosts(hosts, "not declared in this profile")
				state := "disabled"
				if a.Active && !a.UserDisabled && !a.AppDisabled {
					state = "enabled"
				}
				if len(hosts) > 8 {
					hosts = hosts[:8]
				}
				out = append(out, browserExt{
					Browser: "Firefox", Profile: profile, ID: a.ID, Name: name, Version: a.Version,
					Reach: reach, Hosts: hosts, State: state,
					AI: aiExtensionName.MatchString(name) || aiExtensionName.MatchString(a.DefaultLocale.Description),
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
// Safari has one switched ON lives in a container the OS protects, so this says
// INSTALLED and never claims otherwise.
var safariHeaderRe = regexp.MustCompile(`^\s{4,}(\S+)\((.+)\)\s*$`)
var safariKVRe = regexp.MustCompile(`^\s+(Path|Display Name|Parent Bundle)\s*=\s*(.+?)\s*$`)

func safariExtensions() []browserExt {
	if runtime.GOOS != "darwin" {
		return nil
	}
	raw, err := exec.Command("pluginkit", "-mAvvv", "-p", "com.apple.Safari.extension").Output()
	if err != nil {
		return nil
	}
	type entry struct{ id, version, name, path, parent string }
	var found []entry
	var cur *entry
	for _, line := range strings.Split(string(raw), "\n") {
		if m := safariHeaderRe.FindStringSubmatch(line); m != nil {
			if cur != nil {
				found = append(found, *cur)
			}
			cur = &entry{id: m[1], version: m[2]}
			continue
		}
		if cur == nil {
			continue
		}
		if m := safariKVRe.FindStringSubmatch(line); m != nil {
			switch m[1] {
			case "Path":
				cur.path = m[2]
			case "Display Name":
				cur.name = m[2]
			case "Parent Bundle":
				cur.parent = m[2]
			}
		}
	}
	if cur != nil {
		found = append(found, *cur)
	}
	out := []browserExt{}
	for _, e := range found {
		if e.id == "" {
			continue
		}
		var hosts []string
		reach := "not declared in a readable manifest"
		if b, err := os.ReadFile(filepath.Join(e.path, "Contents", "Resources", "manifest.json")); err == nil {
			var m struct {
				HostPermissions []string `json:"host_permissions"`
				Permissions     []string `json:"permissions"`
			}
			if json.Unmarshal(b, &m) == nil {
				hosts = append(hosts, m.HostPermissions...)
				for _, p := range m.Permissions {
					if p == "<all_urls>" || strings.Contains(p, "://") {
						hosts = append(hosts, p)
					}
				}
				if hosts == nil {
					hosts = []string{}
				}
				reach = reachOfHosts(hosts, reach)
			}
		}
		name := e.name
		if name == "" {
			name = e.id
		}
		if len(hosts) > 8 {
			hosts = hosts[:8]
		}
		out = append(out, browserExt{
			Browser: "Safari", ID: e.id, Name: name, Version: e.version,
			Reach: reach, Hosts: hosts, State: "installed, state not readable",
			AI: aiExtensionName.MatchString(e.name) || aiExtensionName.MatchString(e.parent) || aiExtensionName.MatchString(e.id),
		})
	}
	return out
}

func browserExtensions(home, appData string) []browserExt {
	out := []browserExt{}
	browsers := chromiumRoots(home, appData)
	names := make([]string, 0, len(browsers))
	for b := range browsers {
		names = append(names, b)
	}
	sort.Strings(names)
	for _, browser := range names {
		for _, root := range browsers[browser] {
			if _, err := os.Stat(root); err != nil {
				continue
			}
			for _, profile := range dirsIn(root) {
				extRoot := filepath.Join(root, profile, "Extensions")
				if _, err := os.Stat(extRoot); err != nil {
					continue
				}
				states := chromiumStates(filepath.Join(root, profile))
				for _, id := range dirsIn(extRoot) {
					versions := dirsIn(filepath.Join(extRoot, id))
					if len(versions) == 0 {
						continue
					}
					versionDir := filepath.Join(extRoot, id, versions[len(versions)-1])
					b, err := os.ReadFile(filepath.Join(versionDir, "manifest.json"))
					if err != nil {
						continue
					}
					var m struct {
						Name            string   `json:"name"`
						Description     string   `json:"description"`
						Version         string   `json:"version"`
						DefaultLocale   string   `json:"default_locale"`
						HostPermissions []string `json:"host_permissions"`
						Permissions     []string `json:"permissions"`
					}
					if json.Unmarshal(b, &m) != nil {
						continue
					}
					name := resolveExtName(versionDir, m.Name, m.DefaultLocale)
					desc := resolveExtName(versionDir, m.Description, m.DefaultLocale)
					hosts := append([]string{}, m.HostPermissions...)
					for _, p := range m.Permissions {
						if p == "<all_urls>" || strings.Contains(p, "://") {
							hosts = append(hosts, p)
						}
					}
					reach := "no site access"
					every := false
					for _, h := range hosts {
						if h == "<all_urls>" || h == "*://*/*" || h == "https://*/*" || h == "http://*/*" {
							every = true
						}
					}
					switch {
					case every:
						reach = "every site"
					case len(hosts) == 1:
						reach = "1 site pattern"
					case len(hosts) > 1:
						reach = fmt.Sprintf("%d site patterns", len(hosts))
					}
					if len(hosts) > 8 {
						hosts = hosts[:8]
					}
					out = append(out, browserExt{
						Browser: browser, Profile: profile, ID: id, Name: name, Version: m.Version,
						Reach: reach, Hosts: hosts, State: firstNonEmpty(states[id], "enabled"),
						AI: aiExtensionName.MatchString(name) || aiExtensionName.MatchString(desc),
					})
				}
			}
			break
		}
	}
	out = append(out, firefoxExtensions(home, appData)...)
	out = append(out, safariExtensions()...)
	return out
}

// Same section, same words, same order as the .mjs agent: the parity cases
// compare the WHOLE report, and a section printed by one agent and not the other
// is exactly the divergence they exist to catch.
func printMcpJson(rows []mcpJsonEntry) {
	if len(rows) == 0 {
		return
	}
	fmt.Println(strings.Repeat("-", 70))
	fmt.Println("MCP servers declared in .mcp.json")
	for _, r := range rows {
		if r.Unparsed {
			continue
		}
		tag := "SHADOW  "
		switch {
		case r.Clevr:
			tag = "CLEVR   "
		case r.Approval == "disabled":
			tag = "OFF     "
		}
		where := "user"
		if r.Project != nil {
			where = *r.Project
		}
		fmt.Printf("[%s] %s  (%s, %s)  %s\n", tag, r.Name, r.Transport, r.Approval, where)
		if r.Target != "" {
			fmt.Printf("           - %s\n", r.Target)
		}
	}
	for _, r := range rows {
		if r.Unparsed {
			fmt.Printf("[UNREAD  ] %s could not be parsed, so what it declares is unknown\n", r.File)
		}
	}
	fmt.Println("These files are read, never written. A .mcp.json entry applies where that file applies,")
	fmt.Println("so it is reported here rather than counted as governance for the whole machine.")
}

func printExtensions(exts []browserExt) {
	var ai, broad []browserExt
	seen := map[string]bool{}
	for _, e := range exts {
		seen[e.Browser] = true
		if e.AI {
			ai = append(ai, e)
		} else if e.Reach == "every site" && e.State != "disabled" {
			broad = append(broad, e)
		}
	}
	if len(ai) == 0 && len(broad) == 0 {
		return
	}
	fmt.Println(strings.Repeat("-", 70))
	fmt.Println("Browser extensions")
	for _, e := range ai {
		tag := "AI      "
		if e.State == "disabled" {
			tag = "AI, OFF "
		}
		fmt.Printf("[%s] %s  (%s) can read %s\n", tag, e.Name, e.Browser, e.Reach)
		fmt.Println("           - name matches a known AI assistant, which is a heuristic, not a verdict")
		if e.State != "enabled" {
			fmt.Printf("           - %s\n", e.State)
		}
	}
	if n := len(broad); n > 0 {
		plural := "s"
		if n == 1 {
			plural = ""
		}
		var names []string
		for i, e := range broad {
			if i == 6 {
				break
			}
			names = append(names, e.Name)
		}
		fmt.Printf("%d other extension%s can read every site: %s\n", n, plural, strings.Join(names, ", "))
	}
	names := make([]string, 0, len(seen))
	for b := range seen {
		names = append(names, b)
	}
	sort.Strings(names)
	fmt.Printf("Read from: %s. Safari reports what is installed, not what Safari has switched on.\n", strings.Join(names, ", "))
}

func installPaths(home, appData string) map[string][]string {
	local := firstNonEmpty(os.Getenv("LOCALAPPDATA"), filepath.Join(home, "AppData", "Local"))
	apps := func(name string) []string {
		return []string{
			filepath.Join("/Applications", name+".app"),
			filepath.Join(home, "Applications", name+".app"),
			filepath.Join(local, "Programs", name),
			filepath.Join(home, ".local", "share", "applications", strings.ToLower(name)+".desktop"),
		}
	}
	sup := func(parts ...string) []string {
		return []string{
			filepath.Join(append([]string{home, "Library", "Application Support"}, parts...)...),
			filepath.Join(append([]string{appData}, parts...)...),
			filepath.Join(append([]string{home, ".config"}, parts...)...),
		}
	}
	join := func(lists ...[]string) []string {
		var out []string
		for _, l := range lists {
			out = append(out, l...)
		}
		return out
	}
	return map[string][]string{
		"claude-desktop": join(apps("Claude"), sup("Claude")),
		"chatgpt":        join(apps("ChatGPT"), sup("ChatGPT"), sup("com.openai.chat")),
		"cursor":         join(apps("Cursor"), sup("Cursor"), []string{filepath.Join(home, ".cursor")}),
		"windsurf":       join(apps("Windsurf"), sup("Windsurf"), []string{filepath.Join(home, ".codeium", "windsurf")}),
		"claude-code":    {filepath.Join(home, ".claude"), filepath.Join(home, ".claude.json")},
		"gemini-cli":     {filepath.Join(home, ".gemini")},
		"copilot-cli":    {firstNonEmpty(os.Getenv("COPILOT_HOME"), filepath.Join(home, ".copilot"))},
		"augment":        {filepath.Join(home, ".augment")},
		"codex":          {filepath.Join(home, ".codex")},
		"ollama":         join(apps("Ollama"), []string{filepath.Join(home, ".ollama")}),
		"lmstudio":       join(apps("LM Studio"), []string{filepath.Join(home, ".lmstudio")}, sup("LM Studio")),
	}
}

func installedClients(home, appData string) map[string]string {
	found := map[string]string{}
	for id, paths := range installPaths(home, appData) {
		for _, p := range paths {
			if _, err := os.Stat(p); err == nil {
				found[id] = p
				break
			}
		}
	}
	return found
}

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
			ps = append(ps, proc{pid: pid, cmd: name, exe: name}) // Windows: tasklist gives the exe name
		}
		return ps
	}
	// Two passes on purpose. command= is the full line, which the interpreter-style
	// catalog entries need. comm= is what ps itself considers the executable that
	// was run, and it stays correct where any parse of the command line fails: a
	// path with spaces, or a process with no flags to cut at.
	// command= is read as an ordered LIST, not a map: ps order is the report's
	// order, and a map would shuffle it on every run in Go.
	out, err := exec.Command("ps", "-axww", "-o", "pid=,command=").Output()
	if err != nil {
		return nil
	}
	exes := psByPID("-axww", "-o", "pid=,comm=")
	var ps []proc
	for _, line := range strings.Split(string(out), "\n") {
		t := strings.TrimSpace(line)
		if t == "" {
			continue
		}
		sp := strings.IndexByte(t, ' ')
		if sp < 0 {
			ps = append(ps, proc{pid: t})
			continue
		}
		pid, cmd := t[:sp], strings.TrimSpace(t[sp+1:])
		exe := exes[pid]
		if exe == "" {
			exe = cmd
		}
		ps = append(ps, proc{pid: pid, cmd: cmd, exe: exe})
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
type mcpFinding struct {
	Governed  bool   `json:"governed"`
	Via       string `json:"via,omitempty"`
	File      string `json:"file,omitempty"`
	Unparsed  bool   `json:"unparsed,omitempty"`
	Enforcing bool   `json:"enforcing,omitempty"`
	Names     bool   `json:"names,omitempty"`
	Untrusted bool   `json:"untrusted,omitempty"`
}
type mcpSignals map[string]mcpFinding
type machine struct {
	LLMGateway     llmGateway        `json:"llmGateway"`
	MCP            mcpSignals        `json:"mcp"`
	Hook           mcpSignals        `json:"hook"`
	HarnessGateway mcpSignals        `json:"harnessGateway"`
	WrapperGate    map[string]string `json:"wrapperGate"`
	McpJson        []mcpJsonEntry    `json:"mcpJson"`
	Extensions     []browserExt      `json:"extensions"`
	Skills         []skillOnMachine  `json:"skills"`
}

// A server declared in a .mcp.json. Surface, never a governance verdict: an
// entry applies where its file applies, so a Clevr guard in one project's file
// governs that project and not the machine.
// Project is a pointer and Clevr carries no omitempty so the two agents put the
// same bytes on the wire: the JS agent emits `"project": null` for the
// user-level file and `"clevr": false` for an entry that is not ours, and a
// field silently missing on one side is exactly the kind of drift the parity
// cases exist to catch.
type mcpJsonEntry struct {
	File      string  `json:"file"`
	Project   *string `json:"project"`
	Name      string  `json:"name,omitempty"`
	Transport string  `json:"transport,omitempty"`
	Target    string  `json:"target,omitempty"`
	Scope     string  `json:"scope,omitempty"`
	Approval  string  `json:"approval,omitempty"`
	Clevr     bool    `json:"clevr"`
	Unparsed  bool    `json:"unparsed,omitempty"`
}

// Does this config point the client at Clevr?
//
// NOT "does the word clevr appear somewhere in the file". That question returns
// true for a folder path, a plugin name or a stale entry aimed at a host that no
// longer exists, and answering GOVERNED on any of those is a false green on a
// machine with no governance at all. So the check reads the MCP server list and
// nothing else. A file that parses but declares no MCP server is a definite no,
// not an unknown. A file we cannot parse is an unknown, and unknown is not
// governed: otherwise a machine turns itself green by corrupting its own config.
// It is reported as shadow, with the reason on the line.
// Both addresses that mean "us". Kept identical to the Node agent, which is
// verified case by case: the two must never disagree on a verdict.
func clevrHosts() map[string]bool {
	out := map[string]bool{}
	for _, h := range []string{clevrHost, hostOf(mcpURL())} {
		if h != "" {
			out[h] = true
		}
	}
	return out
}
func mcpURL() string {
	if v := os.Getenv("CLEVR_MCP_URL"); v != "" {
		return v
	}
	if gatewayURL != "" {
		return strings.TrimRight(gatewayURL, "/") + "/mcp"
	}
	return ""
}

// Where a client keeps its HOOKS, which is a deeper control than an MCP server
// entry: a hook runs inside the harness before the tool call, in a separate
// process outside the model, so an injection cannot talk its way past it and the
// client rewriting its own configuration does not silently remove it. Kept in
// step with the .mjs hookPaths.
func hookPaths(home string) map[string][]string {
	copilotHome := firstNonEmpty(os.Getenv("COPILOT_HOME"), filepath.Join(home, ".copilot"))
	return map[string][]string{
		"claude-code": {filepath.Join(home, ".claude", "settings.json")},
		"cursor":      {filepath.Join(home, ".cursor", "hooks.json")},
		"copilot-cli": {filepath.Join(copilotHome, "hooks", "clevr.json")},
		"augment":     {filepath.Join(home, ".augment", "settings.json")},
		"gemini-cli":  {filepath.Join(home, ".gemini", "settings.json")},
		// Codex gained hooks in May 2026, and the ChatGPT desktop app runs the
		// same Codex from the same file. Kept in step with the .mjs hookPaths.
		"codex": {filepath.Join(home, ".codex", "hooks.json")},
		// The ChatGPT desktop app IS that Codex: same binary, same file.
		"chatgpt": {filepath.Join(home, ".codex", "hooks.json")},
	}
}

// A harness governed through the gateway rather than a hook. The Codex config is
// TOML, so there is no object to walk: the block we write is fenced by markers
// and only that fence counts.
// A gate script: a script Clevr installs for a harness with no hook, which
// governs only the commands a person wraps with it by hand. NOT governance of the
// machine, and the verdict does not move for it. Reported because a screen that
// says nothing right after a successful install reads as a failure.
func wrapperGatePaths(home string) map[string][]string {
	// Empty since Codex gained real hooks; kept in step with the .mjs table.
	_ = home
	return map[string][]string{}
}

func gatewayConfigPaths(home string) map[string][]string {
	return map[string][]string{
		"codex": {filepath.Join(home, ".codex", "config.toml")},
	}
}

func gatewayGoverns(p string) mcpFinding {
	b, err := os.ReadFile(p)
	if err != nil {
		return mcpFinding{}
	}
	raw := string(b)
	i := strings.Index(raw, "# --- clevr begin ---")
	if i < 0 || !strings.Contains(raw[i:], "# --- clevr end ---") {
		return mcpFinding{}
	}
	return mcpFinding{Governed: true, Via: "model provider block in " + filepath.Base(p)}
}

// Reads the hook and plugin declarations, nothing else.
// Codex runs a hook only after the person has trusted it once (the TUI asks at
// startup and records a hash per hook under [hooks.state."<file>:<event>:<entry>:
// <handler>"] in config.toml). Until then the hook is listed and skipped without
// a word, so a Clevr hook in the file is not governance until its slot has a
// trust record. The hash is Codex's own; presence is what can be read. Kept in
// step with codexHooksUntrusted in the .mjs agent.
var clevrKeyRe = regexp.MustCompile(`clevr_sk_[A-Za-z0-9_-]+`)
var codexCamel = regexp.MustCompile(`([a-z0-9])([A-Z])`)
var codexTrustedHash = regexp.MustCompile(`(?m)^\s*trusted_hash\s*=\s*"`)

func codexHooksUntrusted(home, hooksFile string) bool {
	b, err := os.ReadFile(hooksFile)
	if err != nil {
		return false
	}
	var doc struct {
		Hooks map[string][]struct {
			Hooks []struct {
				Command string `json:"command"`
			} `json:"hooks"`
		} `json:"hooks"`
	}
	if json.Unmarshal(b, &doc) != nil {
		return false
	}
	tomlBytes, _ := os.ReadFile(filepath.Join(home, ".codex", "config.toml"))
	toml := string(tomlBytes)
	ours, missing := 0, 0
	for event, entries := range doc.Hooks {
		for i, entry := range entries {
			for j, h := range entry.Hooks {
				if !strings.Contains(strings.ToLower(h.Command), mcpMarker) {
					continue
				}
				ours++
				key := fmt.Sprintf("[hooks.state.\"%s:%s:%d:%d\"]", hooksFile, strings.ToLower(codexCamel.ReplaceAllString(event, "${1}_${2}")), i, j)
				at := strings.Index(toml, key)
				if at < 0 {
					missing++
					continue
				}
				rest := toml[at+len(key):]
				if len(rest) > 200 {
					rest = rest[:200]
				}
				if !codexTrustedHash.MatchString(rest) {
					missing++
				}
			}
		}
	}
	return ours > 0 && missing > 0
}

func hookGoverns(p string) mcpFinding {
	b, err := os.ReadFile(p)
	if err != nil {
		return mcpFinding{}
	}
	var doc map[string]json.RawMessage
	if json.Unmarshal(b, &doc) != nil {
		return mcpFinding{}
	}
	if raw, ok := doc["enabledPlugins"]; ok {
		var plugins map[string]bool
		if json.Unmarshal(raw, &plugins) == nil {
			names := make([]string, 0, len(plugins))
			for name := range plugins {
				names = append(names, name)
			}
			sort.Strings(names)
			for _, name := range names {
				if plugins[name] && strings.Contains(strings.ToLower(name), mcpMarker) {
					return mcpFinding{Governed: true, Via: "plugin " + name}
				}
			}
		}
	}
	if raw, ok := doc["hooks"]; ok {
		var cmds []string
		collectCommands(raw, 0, false, &cmds)
		for _, c := range cmds {
			if strings.Contains(strings.ToLower(c), mcpMarker) {
				if len(c) > 80 {
					c = c[:80]
				}
				// A key someone inlined in the command must not travel to the fleet
				// view. Kept in step with the .mjs agent.
				return mcpFinding{Governed: true, Via: "hook " + clevrKeyRe.ReplaceAllString(c, "clevr_sk_…")}
			}
		}
	}
	return mcpFinding{}
}

// The key holding a hook's command differs per harness: `command` for most, and
// `bash` plus `powershell` for the Copilot CLI. A whitelist rather than every
// string in the subtree, because an entry also carries a working directory and a
// project path containing the marker would then read as an installed hook.
var commandKeys = map[string]bool{
	"command": true, "bash": true, "powershell": true, "sh": true,
	"cmd": true, "exec": true, "script": true, "args": true,
}

func collectCommands(raw json.RawMessage, depth int, underCommandKey bool, out *[]string) {
	if depth > 6 {
		return
	}
	var str string
	if json.Unmarshal(raw, &str) == nil {
		if underCommandKey {
			*out = append(*out, str)
		}
		return
	}
	var arr []json.RawMessage
	if json.Unmarshal(raw, &arr) == nil {
		for _, x := range arr {
			collectCommands(x, depth+1, underCommandKey, out)
		}
		return
	}
	var obj map[string]json.RawMessage
	if json.Unmarshal(raw, &obj) == nil {
		keys := make([]string, 0, len(obj))
		for k := range obj {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			collectCommands(obj[k], depth+1, commandKeys[k], out)
		}
	}
}

func configPointsAtClevr(p string) mcpFinding {
	b, err := os.ReadFile(p)
	if err != nil {
		return mcpFinding{}
	}
	var doc map[string]json.RawMessage
	if json.Unmarshal(b, &doc) != nil {
		return mcpFinding{Unparsed: true, Names: strings.Contains(strings.ToLower(string(b)), mcpMarker)}
	}
	raw, ok := doc["mcpServers"]
	if !ok {
		return mcpFinding{}
	}
	var servers map[string]struct {
		URL     string   `json:"url"`
		Command string   `json:"command"`
		Args    []string `json:"args"`
	}
	if json.Unmarshal(raw, &servers) != nil {
		return mcpFinding{}
	}
	// Two entries can both name Clevr and they are NOT the same control. The GUARD
	// wraps another server, so a blocked call never reaches the tool: enforcement.
	// The Clevr MCP SERVER exposes two tools, one to ask for a verdict and one to
	// for a verdict and one to look a resource up. A client that has it CAN ask,
	// nothing obliges it to. Advisory. The guard wins when both are present.
	var advisory *mcpFinding
	for _, e := range servers {
		if e.URL != "" {
			// The Clevr MCP server does not have to sit on the engine's host: CLEVR_MCP_URL
			// exists so it can be published separately.
			ours := clevrHosts()
			mine := false
			if len(ours) > 0 {
				mine = ours[hostOf(e.URL)]
			} else {
				mine = strings.Contains(strings.ToLower(e.URL), mcpMarker)
			}
			if mine && advisory == nil {
				advisory = &mcpFinding{Governed: true, Enforcing: false, Via: e.URL}
			}
			continue
		}
		cmd := strings.ToLower(e.Command + " " + strings.Join(e.Args, " "))
		if strings.Contains(cmd, mcpMarker) {
			return mcpFinding{Governed: true, Enforcing: true, Via: "local guard command"}
		}
	}
	if advisory != nil {
		return *advisory
	}
	return mcpFinding{}
}

func firstGoverned(paths []string) mcpFinding {
	note := mcpFinding{}
	for _, p := range paths {
		f := configPointsAtClevr(p)
		if f.Governed {
			f.File = p
			return f
		}
		// Not governed, but worth saying why: a config naming Clevr that we could
		// not read is a question mark, and a question mark belongs on the screen.
		if f.Unparsed && f.Names && !note.Unparsed {
			f.File = p
			note = f
		}
	}
	return note
}

// The .mcp.json files, which none of the client config paths name.
//
// Claude Code loads MCP servers from a .mcp.json as well as from ~/.claude.json,
// and the agent read only the latter. Measured on a real machine 2026-09-18:
// ~/.mcp.json had declared an HTTP MCP server since 11 July, the CLI listed it as
// a live server, and this agent reported the machine without it.
//
// The roots come from ~/.claude.json's own projects map, a bounded list the CLI
// already knows. This never walks the filesystem looking for them: a crawl is
// slow, needs reach this agent should not have, and would report a checked-out
// repo nobody has opened.
func mcpJsonServers(home string) []mcpJsonEntry {
	type serverEntry struct {
		URL     string   `json:"url"`
		Command string   `json:"command"`
		Args    []string `json:"args"`
	}
	type projectCfg struct {
		Enabled  []string `json:"enabledMcpjsonServers"`
		Disabled []string `json:"disabledMcpjsonServers"`
		// Local scope: what `claude mcp add` writes by default. Not a file of its
		// own, a branch of ~/.claude.json, and nothing read it before.
		Servers map[string]serverEntry `json:"mcpServers"`
	}
	var cfg struct {
		Projects map[string]projectCfg `json:"projects"`
	}
	if b, err := os.ReadFile(filepath.Join(home, ".claude.json")); err == nil {
		_ = json.Unmarshal(b, &cfg)
	}
	type source struct {
		file    string
		project *string
		scope   string
		servers map[string]serverEntry
	}
	roots := make([]string, 0, len(cfg.Projects))
	for root := range cfg.Projects {
		if root != "" {
			roots = append(roots, root)
		}
	}
	// Map order is random in Go and the JS agent walks its object in insertion
	// order; sorting makes the two reports comparable line for line.
	sort.Strings(roots)
	// The home directory is a project root like any other, and on the machine this
	// was measured on it is one. Emitting ~/.mcp.json as the user-level file AND
	// again as that root's shared file put one server on two rows carrying two
	// different approval states, and counted it twice in the fleet total. It is
	// emitted once, carrying the project entry when there is one, because that is
	// where the acceptance is recorded and so it is the only row that can say
	// whether the server actually loads.
	homeFile := filepath.Join(home, ".mcp.json")
	var homeProject *string
	for _, root := range roots {
		if root == home {
			r := root
			homeProject = &r
			break
		}
	}
	sources := []source{{homeFile, homeProject, "user", nil}}
	for _, root := range roots {
		r := root
		if shared := filepath.Join(root, ".mcp.json"); shared != homeFile {
			sources = append(sources, source{shared, &r, "shared", nil})
		}
		if srv := cfg.Projects[root].Servers; len(srv) > 0 {
			sources = append(sources, source{filepath.Join(home, ".claude.json"), &r, "local", srv})
		}
	}
	// A server is not live until the person accepts it, and pending is its own
	// state: accepting is one keystroke, so calling it inactive understates it and
	// calling it active claims something that has not happened.
	approval := func(project *string, name, scope string) string {
		// Local scope is what `claude mcp add` writes for the person who ran it.
		// There is no prompt to accept and no enabled/disabled list to consult, so
		// reporting it as pending would invent a question nobody was asked.
		if scope == "local" {
			return "enabled"
		}
		key := ""
		if project != nil {
			key = *project
		}
		p := cfg.Projects[key]
		for _, d := range p.Disabled {
			if d == name {
				return "disabled"
			}
		}
		for _, e := range p.Enabled {
			if e == name {
				return "enabled"
			}
		}
		return "pending"
	}
	out := []mcpJsonEntry{}
	for _, src := range sources {
		servers := src.servers
		if servers == nil {
			b, err := os.ReadFile(src.file)
			if err != nil {
				continue
			}
			var doc struct {
				McpServers map[string]serverEntry `json:"mcpServers"`
			}
			if json.Unmarshal(b, &doc) != nil {
				out = append(out, mcpJsonEntry{File: src.file, Project: src.project, Scope: src.scope, Unparsed: true})
				continue
			}
			servers = doc.McpServers
		}
		names := make([]string, 0, len(servers))
		for name := range servers {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			entry := servers[name]
			cmd := strings.TrimSpace(strings.Join(append([]string{entry.Command}, entry.Args...), " "))
			ours := clevrHosts()
			clevr := false
			transport := "unknown"
			target := ""
			switch {
			case entry.URL != "":
				transport, target = "http", entry.URL
				if len(ours) > 0 {
					clevr = ours[hostOf(entry.URL)]
				} else {
					clevr = strings.Contains(strings.ToLower(entry.URL), mcpMarker)
				}
			case cmd != "":
				transport, target = "stdio", cmd
				clevr = strings.Contains(strings.ToLower(cmd), mcpMarker)
			}
			if len(target) > 120 {
				target = target[:120]
			}
			out = append(out, mcpJsonEntry{
				File: src.file, Project: src.project, Name: name,
				Transport: transport, Target: target, Scope: src.scope,
				Approval: approval(src.project, name, src.scope), Clevr: clevr,
			})
		}
	}
	return out
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
	// Keyed by the same client ids as the catalog, so detection can never drift
	// apart from the catalog on a client name.
	hooks := mcpSignals{}
	for id, files := range hookPaths(home) {
		hooks[id] = mcpFinding{}
		for _, f := range files {
			if r := hookGoverns(f); r.Governed {
				r.File = f
				if (id == "codex" || id == "chatgpt") && codexHooksUntrusted(home, f) {
					r.Untrusted = true
				}
				hooks[id] = r
				break
			}
		}
	}
	gates := map[string]string{}
	for id, files := range wrapperGatePaths(home) {
		for _, f := range files {
			if _, err := os.Stat(f); err == nil {
				gates[id] = f
				break
			}
		}
	}
	harnessGw := mcpSignals{}
	for id, files := range gatewayConfigPaths(home) {
		harnessGw[id] = mcpFinding{}
		for _, f := range files {
			if r := gatewayGoverns(f); r.Governed {
				r.File = f
				harnessGw[id] = r
				break
			}
		}
	}
	return machine{
		LLMGateway:     gw,
		Hook:           hooks,
		HarnessGateway: harnessGw,
		WrapperGate:    gates,
		McpJson:        mcpJsonServers(home),
		Extensions:     browserExtensions(home, appData),
		Skills:         skillsOnMachine(home),
		MCP: mcpSignals{
			"claude-desktop": firstGoverned(claudeCfg),
			"cursor":         firstGoverned(cursorCfg),
			"claude-code":    firstGoverned(claudeCodeCfg),
		},
	}
}

type client struct {
	Running     bool     `json:"running"`
	Installed   bool     `json:"installed"`
	InstalledAt string   `json:"installedAt,omitempty"`
	ID          string   `json:"id"`
	Label       string   `json:"label"`
	Kind        string   `json:"kind"`
	PID         string   `json:"pid"`
	Procs       int      `json:"procs"`
	Monitored   bool     `json:"monitored"`
	Via         string   `json:"via"`
	Evidence    []string `json:"evidence"`
}

func assess(e catEntry, sig machine) (monitored bool, via string, evidence []string) {
	via = "none"
	ev := []string{}
	// A harness whose own configuration points its model traffic at Clevr. It
	// covers the conversation, not the local command, and the line says so.
	harnessGw := sig.HarnessGateway[e.id].Governed
	if harnessGw {
		ev = append(ev, "This harness's model traffic points at Clevr ("+sig.HarnessGateway[e.id].Via+"). It covers the conversation, not the local command.")
	}
	llm := sig.LLMGateway.RoutesClevr || harnessGw
	if sig.LLMGateway.RoutesClevr {
		ev = append(ev, "LLM traffic routed through Clevr gateway ("+sig.LLMGateway.URL+")")
	} else if sig.LLMGateway.Configured {
		ev = append(ev, "LLM base URL set but points elsewhere ("+sig.LLMGateway.URL+")")
	}
	// Deepest control first: a hook sees every tool call before it runs, an MCP
	// entry sees only what crosses that server, a gateway base URL sees the model
	// hop and not the tool hop.
	hookSig := sig.Hook[e.id]
	hooked := hookSig.Governed && !hookSig.Untrusted
	if hooked {
		ev = append(ev, fmt.Sprintf("Clevr hook installed in this harness: every tool call is checked before it runs (%s)", hookSig.Via))
	} else if hookSig.Governed && hookSig.Untrusted {
		// Installed is not trusted. Codex skips a hook nobody has reviewed and
		// says nothing, so the line says it, and the verdict does not move.
		ev = append(ev, fmt.Sprintf("Clevr hook installed in this harness but not yet trusted by Codex, which skips an untrusted hook without saying so: nothing is checked until someone runs codex once and answers \"Trust all and continue\" (%s)", hookSig.File))
	}
	// Claude Desktop is two things: the Chat tab (MCP connectors, no hook) and
	// Cowork sessions, which run the Claude Code plugin hooks. Kept in step with
	// the .mjs assess.
	if e.id == "claude-desktop" && sig.Hook["claude-code"].Governed {
		ev = append(ev, "Cowork sessions in this app run the Claude Code plugin hooks; the Chat tab reaches its connectors over MCP, governed only where the guard wraps them or the gateway fronts them")
	}
	found := sig.MCP[e.id]
	mcp := found.Governed
	if mcp && found.Enforcing {
		ev = append(ev, fmt.Sprintf("Clevr MCP guard wraps a server in this client's config: a blocked call never reaches the tool (%s)", found.Via))
	} else if mcp {
		ev = append(ev, fmt.Sprintf("The Clevr MCP server is configured in this client (%s). It lets the client ASK for a verdict; it does not gate what the client does.", found.Via))
	} else if found.Unparsed {
		ev = append(ev, fmt.Sprintf("Config names Clevr but could not be read, so governance is unconfirmed (%s)", found.File))
	}

	// A Clevr entry in a .mcp.json or in a project's local scope is real, and it is
	// real WHERE THAT FILE APPLIES. It does not make the client governed on this
	// machine, because the acceptance is recorded per project: the same entry is
	// live in one directory and pending in the next. So it is said on the line
	// rather than counted in the verdict, which is the difference between a machine
	// that looks green and a machine someone can reason about.
	if e.id == "claude-code" {
		where := []string{}
		for _, m := range sig.McpJson {
			if !m.Clevr || m.Unparsed || m.Approval == "disabled" {
				continue
			}
			if m.Project != nil {
				where = append(where, *m.Project)
			} else {
				where = append(where, "the user-level file")
			}
		}
		if n := len(where); n > 0 {
			plural := "ies"
			if n == 1 {
				plural = "y"
			}
			shown, tail := where, ""
			if n > 3 {
				shown, tail = where[:3], ", …"
			}
			ev = append(ev, fmt.Sprintf("Clevr is configured in %d .mcp.json entr%s (%s%s). That governs those projects, not this machine, because acceptance is recorded per project.",
				n, plural, strings.Join(shown, ", "), tail))
		}
	}

	if e.kind == "local-model" {
		ev = append(ev, "Local model runner: no cloud gateway to route through; govern its tool use via a local MCP proxy")
		return false, "local", ev
	}
	// Stated after the verdict lines and never counted into them: a gate nobody
	// calls governs nothing.
	if g, ok := sig.WrapperGate[e.id]; ok {
		ev = append(ev, "A Clevr gate script is installed at "+g+", but nothing invokes it: it governs only the commands you wrap with it by hand.")
	}

	// Advisory is not governance: a client that can ask, with nothing obliging it
	// to and nothing stopping it when it does not, is listed as shadow with the
	// server named on its line.
	enforcingMcp := mcp && found.Enforcing
	monitored = hooked || llm || enforcingMcp
	if monitored {
		switch {
		case hooked:
			via = "hook"
		case enforcingMcp:
			via = "mcp"
		default:
			via = "llm-gateway"
		}
	} else {
		ev = append(ev, "No evidence this client routes through Clevr")
	}
	return monitored, via, ev
}

// ── Drift: did the setting hold? ────────────────────────────────────────────
// This binary discovers and reports, it does not remediate. But it is the one
// pushed to a fleet by MDM, so it is usually the thing running when a setting
// gets taken back. It reads the note the Node agent left and applies the same
// rules, so a fleet on the binary reports drift exactly as a laptop on Node.
//
// The state file is a shared contract between the two agents. Its fields must
// change in both at once, or a round trip here silently drops what the other
// wrote.
var rewritesOwnConfig = map[string]string{
	"claude-desktop": "Claude Desktop",
}

// One record per Clevr setting seen on this machine, keyed by client and kind,
// because a client can carry two at once and losing either is its own event.
// `by` says whether this agent wrote it or merely saw it configured: recording
// what is OBSERVED is the point, since a setting installed by the CLI, by an
// administrator or by hand is exactly as worth watching.
type seenRec struct {
	ID             string `json:"id"`
	Label          string `json:"label"`
	Kind           string `json:"kind"`
	By             string `json:"by"`
	File           string `json:"file"`
	Detail         string `json:"detail"`
	At             string `json:"at"`
	State          string `json:"state"`
	Reverts        int    `json:"reverts"`
	LastRevertedAt string `json:"last_reverted_at"`
}

type endpointState struct {
	Seen map[string]seenRec `json:"seen"`
	// An older file kept only what the agent had written, keyed by client id.
	Applied map[string]seenRec `json:"applied,omitempty"`
}

type driftItem struct {
	ID        string `json:"id"`
	Label     string `json:"label"`
	Kind      string `json:"kind"`
	By        string `json:"by,omitempty"`
	State     string `json:"state"`
	File      string `json:"file"`
	AppliedAt string `json:"applied_at"`
	Since     string `json:"since,omitempty"`
	Now       string `json:"now,omitempty"`
	Expected  string `json:"expected,omitempty"`
	Likely    string `json:"likely,omitempty"`
	Reverts   int    `json:"reverts"`
}

var kindLabel = map[string]string{
	"hook":    "the Clevr hook",
	"guard":   "the Clevr MCP guard",
	"mcp":     "the Clevr MCP entry",
	"gateway": "the Clevr model provider block",
}

func statePath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".clevr", "endpoint-state.json")
}

func readState() endpointState {
	st := endpointState{Seen: map[string]seenRec{}}
	b, err := os.ReadFile(statePath())
	if err != nil {
		return st
	}
	var raw endpointState
	if json.Unmarshal(b, &raw) != nil {
		return st
	}
	if raw.Seen != nil {
		st.Seen = raw.Seen
	}
	for id, rec := range raw.Applied {
		key := id + "#mcp"
		if _, ok := st.Seen[key]; !ok {
			rec.ID = id
			rec.Kind = "mcp"
			rec.By = "agent"
			st.Seen[key] = rec
		}
	}
	return st
}

func writeState(st endpointState) {
	st.Applied = nil
	if b, err := json.MarshalIndent(st, "", "  "); err == nil {
		_ = os.MkdirAll(filepath.Dir(statePath()), 0o755)
		_ = os.WriteFile(statePath(), b, 0o600)
	}
}

// Every Clevr configuration this scan can see, whoever put it there.
func observedGovernance(sig machine) map[string]seenRec {
	out := map[string]seenRec{}
	add := func(id, kind string, f mcpFinding) {
		if !f.Governed || f.File == "" {
			return
		}
		out[id+"#"+kind] = seenRec{ID: id, Kind: kind, File: f.File, Detail: f.Via}
	}
	for id, f := range sig.Hook {
		add(id, "hook", f)
	}
	for id, f := range sig.MCP {
		kind := "mcp"
		if f.Enforcing {
			kind = "guard"
		}
		add(id, kind, f)
	}
	for id, f := range sig.HarnessGateway {
		add(id, "gateway", f)
	}
	return out
}

// Our entry is still in the file but no longer aimed at us.
func entryNowAt(rec seenRec) string {
	if rec.Kind != "mcp" && rec.Kind != "guard" {
		return ""
	}
	b, err := os.ReadFile(rec.File)
	if err != nil {
		return ""
	}
	var doc struct {
		MCPServers map[string]struct {
			URL string `json:"url"`
		} `json:"mcpServers"`
	}
	if json.Unmarshal(b, &doc) != nil {
		return ""
	}
	e, ok := doc.MCPServers[mcpEntry]
	if !ok {
		return ""
	}
	if e.URL == "" {
		return "(no url)"
	}
	return e.URL
}

func checkDrift(sig machine, labelOf func(string) string) []driftItem {
	st := readState()
	now := observedGovernance(sig)
	out := []driftItem{}
	changed := false

	keys := make([]string, 0, len(now))
	for k := range now {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, key := range keys {
		obs := now[key]
		prev := st.Seen[key]
		label := labelOf(obs.ID)
		if label == "" {
			label = prev.Label
		}
		if label == "" {
			label = obs.ID
		}
		if prev.State != "holding" || prev.Detail != obs.Detail || prev.File != obs.File {
			changed = true
		}
		at := prev.At
		if at == "" {
			at = time.Now().UTC().Format(time.RFC3339)
		}
		by := prev.By
		if by == "" {
			by = "observed"
		}
		st.Seen[key] = seenRec{ID: obs.ID, Label: label, Kind: obs.Kind, By: by, File: obs.File,
			Detail: obs.Detail, At: at, State: "holding", Reverts: prev.Reverts, LastRevertedAt: prev.LastRevertedAt}
		out = append(out, driftItem{ID: obs.ID, Label: label, Kind: obs.Kind, State: "holding",
			File: obs.File, AppliedAt: at, Reverts: prev.Reverts})
	}

	goneKeys := make([]string, 0, len(st.Seen))
	for k := range st.Seen {
		if _, ok := now[k]; !ok {
			goneKeys = append(goneKeys, k)
		}
	}
	sort.Strings(goneKeys)
	for _, key := range goneKeys {
		rec := st.Seen[key]
		// The count moves only when this crosses from holding to gone. Counting it
		// on every scan would turn one reversal into hundreds a day.
		first := rec.State == "holding" || rec.State == ""
		label := labelOf(rec.ID)
		if label == "" {
			label = rec.Label
		}
		if label == "" {
			label = rec.ID
		}
		kind := rec.Kind
		if kind == "" {
			kind = "mcp"
		}
		by := rec.By
		if by == "" {
			by = "observed"
		}
		d := driftItem{ID: rec.ID, Label: label, Kind: kind, By: by, State: "removed", File: rec.File,
			AppliedAt: rec.At, Expected: rec.Detail, Reverts: rec.Reverts}
		if n := entryNowAt(rec); n != "" {
			d.State = "repointed"
			d.Now = n
		}
		if first {
			d.Reverts++
			d.Since = time.Now().UTC().Format(time.RFC3339)
		} else {
			d.Since = rec.LastRevertedAt
		}
		if name, ok := rewritesOwnConfig[rec.ID]; ok {
			d.Likely = name + " rewrites this file while running and drops entries added underneath it"
		}
		out = append(out, d)
		if first {
			rec.Label = label
			rec.State = d.State
			rec.Reverts = d.Reverts
			rec.LastRevertedAt = d.Since
			st.Seen[key] = rec
			changed = true
		}
	}

	if changed {
		writeState(st)
	}
	return out
}

func printDrift(drift []driftItem) {
	gone := []driftItem{}
	for _, d := range drift {
		if d.State == "removed" || d.State == "repointed" {
			gone = append(gone, d)
		}
	}
	if len(gone) == 0 {
		return
	}
	fmt.Println("Clevr settings that were configured here and are gone")
	fmt.Println(strings.Repeat("-", 70))
	for _, d := range gone {
		fmt.Printf("[UNDONE  ] %s\n", d.Label)
		what := kindLabel[d.Kind]
		if what == "" {
			what = "the Clevr entry"
		}
		if d.State == "removed" {
			fmt.Printf("           - %s is gone from %s\n", what, d.File)
		} else {
			fmt.Printf("           - now points at %s in %s\n", d.Now, d.File)
		}
		if d.By == "observed" {
			fmt.Println("           - it was not written by this agent, only seen configured here before")
		}
		seenVerb := "first seen"
		if d.By == "agent" {
			seenVerb = "applied"
		}
		line := fmt.Sprintf("           - %s %s", seenVerb, d.AppliedAt)
		if d.Since != "" {
			line += fmt.Sprintf(", undone %s", d.Since)
		}
		if d.Reverts > 1 {
			line += fmt.Sprintf(" (%d times in all)", d.Reverts)
		}
		fmt.Println(line)
		if d.Likely != "" {
			fmt.Printf("           - likely cause: %s\n", d.Likely)
		}
	}
	fmt.Println(strings.Repeat("-", 70))
	fmt.Println("Re-run with --govern --apply to put it back.")
	fmt.Println()
}

type summary struct {
	Running   int `json:"running"`
	Present   int `json:"present"`
	Monitored int `json:"monitored"`
	// Kept to its original meaning, running and ungoverned, so the number does not
	// silently change under anyone reading it.
	Shadow          int `json:"shadow"`
	ShadowInstalled int `json:"shadow_installed"`
	// Counted apart because it is the strongest thing this machine can say.
	Hooked int `json:"hooked"`
}
type report struct {
	Host    string      `json:"host"`
	OS      string      `json:"os"`
	User    string      `json:"user"`
	Version string      `json:"version"`
	TS      string      `json:"ts"`
	Machine machine     `json:"machine"`
	Clients []client    `json:"clients"`
	Summary summary     `json:"summary"`
	Drift   []driftItem `json:"drift"`
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
			target := p.cmd
			if !e.inArgs {
				target = p.exe
			}
			if e.re.MatchString(target) {
				c, ok := byID[e.id]
				if !ok {
					mon, via, ev := assess(e, sig)
					c = &client{ID: e.id, Label: e.label, Kind: e.kind, PID: p.pid, Monitored: mon, Via: via, Evidence: ev, Running: true}
					byID[e.id] = c
					order = append(order, e.id)
				}
				c.Procs++
				break
			}
		}
	}

	// A client that is installed but closed still belongs in the inventory. Added
	// after the running ones so the list keeps ps order at the top.
	home2, _ := os.UserHomeDir()
	appData2 := firstNonEmpty(os.Getenv("APPDATA"), filepath.Join(home2, "AppData", "Roaming"))
	installed := installedClients(home2, appData2)
	instIDs := make([]string, 0, len(installed))
	for id := range installed {
		instIDs = append(instIDs, id)
	}
	sort.Strings(instIDs)
	for _, id := range instIDs {
		if c, ok := byID[id]; ok {
			c.Installed = true
			c.InstalledAt = installed[id]
			continue
		}
		for _, e := range catalog {
			if e.id != id {
				continue
			}
			mon, via, ev := assess(e, sig)
			byID[id] = &client{ID: e.id, Label: e.label, Kind: e.kind, PID: "", Procs: 0,
				Monitored: mon, Via: via, Evidence: ev, Running: false, Installed: true, InstalledAt: installed[id]}
			order = append(order, id)
			break
		}
	}
	clients := make([]client, 0, len(order))
	mon, shadow, hooked, running, shadowInstalled := 0, 0, 0, 0, 0
	for _, id := range order {
		c := byID[id]
		clients = append(clients, *c)
		if c.Monitored {
			mon++
			if c.Via == "hook" {
				hooked++
			}
		} else if c.Via != "local" {
			if c.Running {
				shadow++
			} else {
				shadowInstalled++
			}
		}
		if c.Running {
			running++
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
		Clients: clients, Summary: summary{Running: running, Present: len(clients), Monitored: mon, Shadow: shadow, ShadowInstalled: shadowInstalled, Hooked: hooked},
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
		depth := ""
		if c.Monitored {
			switch c.Via {
			case "hook":
				depth = " via hook"
			case "mcp":
				depth = " via MCP"
			case "llm-gateway":
				depth = " via gateway"
			}
		}
		where := "installed, not running"
		if c.Running {
			where = "pid " + c.PID
		}
		fmt.Printf("[%s] %s  (%s, %s)%s\n", tag, c.Label, where, c.Kind, depth)
		if !c.Running && c.InstalledAt != "" {
			fmt.Printf("           - found at %s\n", c.InstalledAt)
		}
		for _, e := range c.Evidence {
			fmt.Printf("           - %s\n", e)
		}
	}
	fmt.Println(strings.Repeat("-", 70))
	byHook := ""
	if r.Summary.Hooked > 0 {
		byHook = fmt.Sprintf(" (%d by hook)", r.Summary.Hooked)
	}
	fmt.Printf("Running: %d   Governed: %d%s   Shadow: %d\n", r.Summary.Running, r.Summary.Monitored, byHook, r.Summary.Shadow)
	if r.Summary.Shadow > 0 {
		fmt.Println("Shadow AI present: an AI client is running with no evidence it is governed by Clevr.")
	}
	printExtensionsAfter := r.Machine.Extensions
	if n := r.Summary.ShadowInstalled; n > 0 {
		plural := "s"
		if n == 1 {
			plural = ""
		}
		fmt.Printf("Plus %d AI client%s installed on this machine, not running now, with no evidence of governance.\n", n, plural)
	}
	shadowJson := 0
	for _, m := range r.Machine.McpJson {
		if !m.Unparsed && !m.Clevr && m.Approval != "disabled" {
			shadowJson++
		}
	}
	if shadowJson > 0 {
		plural := "s"
		if shadowJson == 1 {
			plural = ""
		}
		fmt.Printf("Plus %d MCP server%s declared in a .mcp.json with no evidence of governance.\n", shadowJson, plural)
	}
	printMcpJson(r.Machine.McpJson)
	printExtensions(printExtensionsAfter)
	printSkills(r.Machine.Skills)
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
	// On every run, not only when asked to remediate: a machine that merely
	// reports must still say that what it was given has been taken back.
	labelOf := func(id string) string {
		for _, c := range r.Clients {
			if c.ID == id {
				return c.Label
			}
		}
		for _, e := range catalog {
			if e.id == id {
				return e.label
			}
		}
		return ""
	}
	r.Drift = checkDrift(r.Machine, labelOf)
	printReport(r)
	if !hasArg("--json") {
		printDrift(r.Drift)
	}
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

// ── Skills on this machine ───────────────────────────────────────────────────
// The same reading as the Node agent's skillsOnMachine, byte for byte: the
// folders each tool documents, never a crawl, and each skill with the version
// of its files as the plugins compute it (sha256 over "path\0sha256\n" of every
// file, in byte order). Read, never written.

type skillOnMachine struct {
	Name        string   `json:"name"`
	Scope       string   `json:"scope"`
	Tools       []string `json:"tools"`
	Project     *string  `json:"project"`
	Path        string   `json:"path"`
	Fingerprint *string  `json:"fingerprint"`
	Files       int      `json:"files"`
	Partial     bool     `json:"partial"`
	Description *string  `json:"description"`
	Clevr       bool     `json:"clevr"`
}

type skillRoot struct {
	dir     string
	scope   string
	tools   []string
	plugin  string
	project string
}

var skillSkip = map[string]bool{".git": true, "node_modules": true, ".DS_Store": true, ".clevr-skill.json": true}

const skillMaxFiles = 200
const skillMaxBytes = 5 * 1024 * 1024
const skillsMax = 300

// Folders inside dir, not hidden, not links, in byte order.
func skillSubdirs(dir string) []string {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range ents {
		if e.IsDir() && !strings.HasPrefix(e.Name(), ".") {
			out = append(out, e.Name())
		}
	}
	sort.Strings(out)
	return out
}

func skillRootsOnMachine(home string) []skillRoot {
	roots := []skillRoot{
		{dir: filepath.Join(home, ".claude", "skills"), scope: "personal", tools: []string{"Claude Code", "Cursor"}},
		{dir: filepath.Join(home, ".agents", "skills"), scope: "personal", tools: []string{"Codex", "Cursor", "Copilot", "Gemini CLI"}},
		{dir: filepath.Join(home, ".codex", "skills"), scope: "personal", tools: []string{"Codex", "Cursor"}},
		{dir: filepath.Join(home, ".codex", "skills", ".system"), scope: "built-in", tools: []string{"Codex"}},
		{dir: filepath.Join(home, ".cursor", "skills"), scope: "personal", tools: []string{"Cursor"}},
		{dir: filepath.Join(home, ".gemini", "skills"), scope: "personal", tools: []string{"Gemini CLI"}},
		{dir: filepath.Join(home, ".copilot", "skills"), scope: "personal", tools: []string{"Copilot"}},
	}
	switch runtime.GOOS {
	case "darwin":
		roots = append(roots, skillRoot{dir: "/Library/Application Support/ClaudeCode/.claude/skills", scope: "administrator", tools: []string{"Claude Code"}})
	case "windows":
		roots = append(roots, skillRoot{dir: `C:\Program Files\ClaudeCode\.claude\skills`, scope: "administrator", tools: []string{"Claude Code"}})
	default:
		roots = append(roots, skillRoot{dir: "/etc/claude-code/.claude/skills", scope: "administrator", tools: []string{"Claude Code"}})
	}
	if runtime.GOOS != "windows" {
		roots = append(roots, skillRoot{dir: "/etc/codex/skills", scope: "administrator", tools: []string{"Codex"}})
	}
	// Plugins: Claude Code's registry, the newest copy of each plugin in Codex's
	// cache, Gemini CLI's extensions.
	var reg struct {
		Plugins map[string]json.RawMessage `json:"plugins"`
	}
	if b, err := os.ReadFile(filepath.Join(home, ".claude", "plugins", "installed_plugins.json")); err == nil {
		_ = json.Unmarshal(b, &reg)
	}
	keys := make([]string, 0, len(reg.Plugins))
	for k := range reg.Plugins {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	type installEntry struct {
		InstallPath string `json:"installPath"`
	}
	for _, k := range keys {
		var list []installEntry
		if err := json.Unmarshal(reg.Plugins[k], &list); err != nil {
			var one installEntry
			if json.Unmarshal(reg.Plugins[k], &one) == nil {
				list = []installEntry{one}
			}
		}
		for _, e := range list {
			if e.InstallPath != "" {
				roots = append(roots, skillRoot{dir: filepath.Join(e.InstallPath, "skills"), scope: "plugin", tools: []string{"Claude Code"}, plugin: strings.SplitN(k, "@", 2)[0]})
			}
		}
	}
	codexCache := filepath.Join(home, ".codex", "plugins", "cache")
	for _, market := range skillSubdirs(codexCache) {
		for _, plugin := range skillSubdirs(filepath.Join(codexCache, market)) {
			versions := skillSubdirs(filepath.Join(codexCache, market, plugin))
			if len(versions) > 0 {
				roots = append(roots, skillRoot{dir: filepath.Join(codexCache, market, plugin, versions[len(versions)-1], "skills"), scope: "plugin", tools: []string{"Codex"}, plugin: plugin})
			}
		}
	}
	gemExt := filepath.Join(home, ".gemini", "extensions")
	for _, ext := range skillSubdirs(gemExt) {
		roots = append(roots, skillRoot{dir: filepath.Join(gemExt, ext, "skills"), scope: "plugin", tools: []string{"Gemini CLI"}, plugin: ext})
	}
	// The projects Claude Code knows, bounded.
	var cj struct {
		Projects map[string]json.RawMessage `json:"projects"`
	}
	if b, err := os.ReadFile(filepath.Join(home, ".claude.json")); err == nil {
		_ = json.Unmarshal(b, &cj)
	}
	projects := make([]string, 0, len(cj.Projects))
	for p := range cj.Projects {
		if p != "" {
			projects = append(projects, p)
		}
	}
	sort.Strings(projects)
	if len(projects) > 100 {
		projects = projects[:100]
	}
	subs := []struct {
		sub   string
		tools []string
	}{
		{filepath.Join(".claude", "skills"), []string{"Claude Code", "Cursor", "Copilot"}},
		{filepath.Join(".agents", "skills"), []string{"Codex", "Cursor", "Copilot", "Gemini CLI"}},
		{filepath.Join(".cursor", "skills"), []string{"Cursor"}},
		{filepath.Join(".github", "skills"), []string{"Copilot"}},
		{filepath.Join(".gemini", "skills"), []string{"Gemini CLI"}},
	}
	for _, root := range projects {
		for _, sb := range subs {
			dir := filepath.Join(root, sb.sub)
			dup := false
			for _, r := range roots {
				if r.dir == dir {
					dup = true
					break
				}
			}
			if !dup {
				roots = append(roots, skillRoot{dir: dir, scope: "project", tools: sb.tools, project: root})
			}
		}
	}
	return roots
}

// The first n UTF-16 code units of s, as JavaScript's slice counts them.
func jsSlice(s string, n int) string {
	u := utf16.Encode([]rune(s))
	if len(u) <= n {
		return s
	}
	return string(utf16.Decode(u[:n]))
}

func skillDescription(text string) *string {
	lines := strings.Split(jsSlice(text, 64*1024), "\n")
	for i := range lines {
		lines[i] = strings.TrimSuffix(lines[i], "\r")
	}
	if len(lines) == 0 || lines[0] != "---" {
		return nil
	}
	for i := 1; i < len(lines) && lines[i] != "---"; i++ {
		if !strings.HasPrefix(lines[i], "description:") {
			continue
		}
		v := strings.TrimSpace(strings.TrimPrefix(lines[i], "description:"))
		if strings.HasPrefix(v, "\"") || strings.HasPrefix(v, "'") {
			v = v[1:]
		}
		if strings.HasSuffix(v, "\"") || strings.HasSuffix(v, "'") {
			v = v[:len(v)-1]
		}
		if v == "" {
			return nil
		}
		v = jsSlice(v, 300)
		return &v
	}
	return nil
}

type skillFile struct{ path, sha string }

func skillVersionOf(dir string) (fp *string, files int, partial bool, desc *string) {
	var list []skillFile
	bytesSeen := 0
	var walk func(d string) error
	walk = func(d string) error {
		ents, err := os.ReadDir(d)
		if err != nil {
			return err
		}
		for _, e := range ents {
			if skillSkip[e.Name()] {
				continue
			}
			abs := filepath.Join(d, e.Name())
			st, err := os.Lstat(abs)
			if err != nil {
				return err
			}
			if st.Mode()&os.ModeSymlink != 0 {
				continue
			}
			if st.IsDir() {
				if err := walk(abs); err != nil {
					return err
				}
				continue
			}
			if !st.Mode().IsRegular() {
				continue
			}
			if len(list) >= skillMaxFiles {
				partial = true
				continue
			}
			b, err := os.ReadFile(abs)
			if err != nil {
				return err
			}
			if bytesSeen+len(b) > skillMaxBytes {
				partial = true
				continue
			}
			bytesSeen += len(b)
			rel, _ := filepath.Rel(dir, abs)
			sum := sha256.Sum256(b)
			list = append(list, skillFile{filepath.ToSlash(rel), hex.EncodeToString(sum[:])})
		}
		return nil
	}
	if err := walk(dir); err != nil {
		return nil, len(list), true, nil
	}
	main, err := os.ReadFile(filepath.Join(dir, "SKILL.md"))
	if err != nil {
		return nil, len(list), true, nil
	}
	desc = skillDescription(string(main))
	sort.Slice(list, func(i, j int) bool { return list[i].path < list[j].path })
	var sb strings.Builder
	for _, f := range list {
		sb.WriteString(f.path + "\x00" + f.sha + "\n")
	}
	sum := sha256.Sum256([]byte(sb.String()))
	h := hex.EncodeToString(sum[:])
	return &h, len(list), partial, desc
}

func skillsOnMachine(home string) []skillOnMachine {
	out := []skillOnMachine{}
	seen := map[string]bool{}
	for _, r := range skillRootsOnMachine(home) {
		for _, n := range skillSubdirs(r.dir) {
			dir := filepath.Join(r.dir, n)
			if seen[dir] {
				continue
			}
			st, err := os.Lstat(dir)
			if err != nil || st.Mode()&os.ModeSymlink != 0 {
				continue
			}
			if _, err := os.Stat(filepath.Join(dir, "SKILL.md")); err != nil {
				continue
			}
			seen[dir] = true
			name := n
			if r.plugin != "" {
				name = r.plugin + ":" + n
			}
			var project *string
			if r.project != "" {
				p := r.project
				project = &p
			}
			fp, files, partial, desc := skillVersionOf(dir)
			_, clevrErr := os.Stat(filepath.Join(dir, ".clevr-skill.json"))
			out = append(out, skillOnMachine{Name: name, Scope: r.scope, Tools: r.tools, Project: project, Path: dir, Fingerprint: fp, Files: files, Partial: partial, Description: desc, Clevr: clevrErr == nil})
			if len(out) >= skillsMax {
				return out
			}
		}
	}
	return out
}

func printSkills(skills []skillOnMachine) {
	if len(skills) == 0 {
		return
	}
	fmt.Println(strings.Repeat("-", 70))
	fmt.Println("Skills on this machine")
	for i, sk := range skills {
		if i == 40 {
			break
		}
		where := sk.Scope
		if sk.Scope == "project" && sk.Project != nil {
			where = "project " + *sk.Project
		}
		tag := "SKILL   "
		if sk.Clevr {
			tag = "CLEVR   "
		}
		ver := "unreadable"
		if sk.Fingerprint != nil {
			ver = (*sk.Fingerprint)[:12]
		}
		fmt.Printf("[%s] %s  (%s; %s)  %s\n", tag, sk.Name, where, strings.Join(sk.Tools, ", "), ver)
	}
	if len(skills) > 40 {
		fmt.Printf("and %d more\n", len(skills)-40)
	}
	fmt.Println("Read, never written. Each skill is listed with the version of its files; whether that")
	fmt.Println("version is approved, and which agents may load it, is answered in Clevr.")
}
