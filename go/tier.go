package main

// Which endpoint tier is in force on this machine, read from the managed
// settings file Claude Code really reads, and where the hooks take their key
// from. The same reading as the Node agent's tierInForce and hooksKey.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
)

type tierReport struct {
	Name             string          `json:"name"`
	ManagedSettings  *string         `json:"managed_settings"`
	HooksLocked      bool            `json:"hooks_locked"`
	Sandbox          *bool           `json:"sandbox,omitempty"`
	NetworkAllowlist *bool           `json:"network_allowlist,omitempty"`
	BypassDisabled   *bool           `json:"bypass_disabled,omitempty"`
	DeniedReads      *int            `json:"denied_reads,omitempty"`
	Failsafe         *string         `json:"failsafe"`
	Key              string          `json:"key"`
	Harnesses        map[string]bool `json:"harnesses"`
	PolicyHelper     bool            `json:"policy_helper,omitempty"`
	FromConsole      bool            `json:"from_console,omitempty"`
	Finding          string          `json:"finding,omitempty"`
	Note             string          `json:"note,omitempty"`
}

const legacyWinPolicy = `C:\ProgramData\ClaudeCode\managed-settings.json`

func machineFilePath() string {
	if runtime.GOOS == "windows" {
		return `C:\Program Files\Clevr\agent.env`
	}
	return "/etc/clevr/agent.env"
}

var machineLine = regexp.MustCompile(`^\s*(?:export\s+)?(CLEVR_[A-Z_]+)\s*=\s*(.*?)\s*$`)

// The engine and key deploy/mdm put in a file only an administrator can change;
// nil when the machine has none.
func readMachineFile() map[string]string {
	raw, err := os.ReadFile(machineFilePath())
	if err != nil {
		return nil
	}
	vars := map[string]string{}
	for _, line := range strings.Split(strings.ReplaceAll(string(raw), "\r\n", "\n"), "\n") {
		m := machineLine.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		v := m[2]
		if len(v) >= 2 && (v[0] == '"' || v[0] == '\'') && v[len(v)-1] == v[0] {
			v = v[1 : len(v)-1]
		}
		vars[m[1]] = v
	}
	return vars
}

var machineVars = readMachineFile()

func machineVar(name string) string {
	if machineVars == nil {
		return ""
	}
	return machineVars[name]
}

func hooksKey() string {
	if machineVars != nil {
		if machineVars["CLEVR_API_KEY"] != "" {
			return "machine"
		}
		return "missing"
	}
	home, _ := os.UserHomeDir()
	var c struct {
		Key string `json:"key"`
	}
	if raw, err := os.ReadFile(filepath.Join(home, ".clevr", "config.json")); err == nil && json.Unmarshal(raw, &c) == nil && c.Key != "" {
		return "person"
	}
	return "none"
}

func managedSettingsPaths() []string {
	switch runtime.GOOS {
	case "darwin":
		return []string{"/Library/Application Support/ClaudeCode/managed-settings.json"}
	case "windows":
		return []string{`C:\Program Files\ClaudeCode\managed-settings.json`}
	default:
		return []string{"/etc/claude-code/managed-settings.json"}
	}
}

// Which harnesses an administrator's policy points at Clevr (deploy/mdm).
func harnessPolicies(claudeCode string) map[string]bool {
	cursor, codex := "/etc/cursor/hooks.json", "/etc/codex/requirements.toml"
	switch runtime.GOOS {
	case "darwin":
		cursor = "/Library/Application Support/Cursor/hooks.json"
	case "windows":
		cursor, codex = `C:\ProgramData\Cursor\hooks.json`, `C:\ProgramData\OpenAI\Codex\requirements.toml`
	}
	namesClevr := func(p string) bool {
		if p == "" {
			return false
		}
		raw, err := os.ReadFile(p)
		return err == nil && strings.Contains(strings.ToLower(string(raw)), "clevr")
	}
	return map[string]bool{"claude_code": namesClevr(claudeCode), "cursor": namesClevr(cursor), "codex": namesClevr(codex)}
}

func exists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

func tierInForce() *tierReport {
	found := ""
	for _, p := range managedSettingsPaths() {
		if exists(p) {
			found = p
			break
		}
	}
	misplaced := runtime.GOOS == "windows" && exists(legacyWinPolicy)
	key := hooksKey()
	harnesses := harnessPolicies(found)
	if found == "" {
		t := &tierReport{Name: "none", Key: key, Harnesses: harnesses,
			Note: "No managed policy on this machine. Anything the agent is told not to do, it is told by a file its user can edit."}
		if misplaced {
			t.Finding = "A managed-settings.json exists at the legacy ProgramData path, which Claude Code does not read. It is not in force."
		}
		return t
	}
	var m struct {
		AllowManagedHooksOnly           bool `json:"allowManagedHooksOnly"`
		AllowManagedPermissionRulesOnly bool `json:"allowManagedPermissionRulesOnly"`
		Sandbox                         struct {
			Enabled bool `json:"enabled"`
			Network struct {
				StrictAllowlist bool `json:"strictAllowlist"`
			} `json:"network"`
		} `json:"sandbox"`
		Permissions struct {
			DisableBypassPermissionsMode any      `json:"disableBypassPermissionsMode"`
			Deny                         []string `json:"deny"`
		} `json:"permissions"`
		Env map[string]string `json:"env"`
	}
	raw, err := os.ReadFile(found)
	// A profile that names Clevr's policy helper is applied as the helper
	// builds it: read the tier from what Claude Code receives.
	helper, fromConsole := false, false
	var whole map[string]any
	if err == nil && json.Unmarshal(raw, &whole) == nil {
		if _, ok := whole["policyHelper"]; ok {
			helper = true
			var eff map[string]any
			eff, fromConsole = effectiveSettings(whole)
			if b, e := json.Marshal(eff); e == nil {
				raw = b
			}
		}
	}
	if err != nil || json.Unmarshal(raw, &m) != nil {
		return &tierReport{Name: "unreadable", ManagedSettings: strp(found), Key: key, Harnesses: harnesses,
			Note: "The managed settings file exists but is not valid JSON. Claude Code refuses to start on this, so the machine is not governed and not working."}
	}
	name := "custom"
	switch {
	case m.Sandbox.Network.StrictAllowlist && m.AllowManagedPermissionRulesOnly:
		name = "strict"
	case m.Sandbox.Enabled:
		name = "baseline"
	case m.AllowManagedHooksOnly:
		name = "observe"
	}
	sandbox, network := m.Sandbox.Enabled, m.Sandbox.Network.StrictAllowlist
	bypass := m.Permissions.DisableBypassPermissionsMode == "disable" || m.Permissions.DisableBypassPermissionsMode == true
	denied := len(m.Permissions.Deny)
	t := &tierReport{Name: name, ManagedSettings: strp(found), HooksLocked: m.AllowManagedHooksOnly,
		Sandbox: &sandbox, NetworkAllowlist: &network, BypassDisabled: &bypass, DeniedReads: &denied, Key: key, Harnesses: harnesses,
		PolicyHelper: helper, FromConsole: fromConsole}
	if f := m.Env["CLEVR_FAILSAFE"]; f != "" {
		t.Failsafe = &f
	}
	if misplaced {
		t.Finding = "A second managed-settings.json sits at the legacy ProgramData path and is NOT read. Remove it so nobody reads it as policy."
	}
	return t
}
