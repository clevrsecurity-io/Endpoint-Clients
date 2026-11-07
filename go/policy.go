package main

// The policy helper Claude Code runs at each start and every five minutes
// (managed settings policyHelper, deploy/mdm). Installed as clevr-policy, it
// asks Clevr for this machine's tier and prints the profile's managed settings
// with the tier's own settings replaced by Clevr's. When Clevr does not answer,
// or the console does not drive the machines, it prints {} and the profile
// applies as it is: the floor the MDM installed, never less.

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	neturl "net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// The settings a tier owns (brain/src/lib/agents/endpoint_tiers.js compile).
// Everything else in the profile stays: the hooks, the engine's address, the
// model route.
var tierOwned = map[string]bool{"permissions": true, "sandbox": true, "allowManagedPermissionRulesOnly": true, "allowManagedMcpServersOnly": true}

func policyMode() bool {
	base := strings.TrimSuffix(strings.ToLower(filepath.Base(os.Args[0])), ".exe")
	return base == "clevr-policy" || hasArg("--policy")
}

type policyAnswer struct {
	Tier     *string        `json:"tier"`
	Source   string         `json:"source"`
	Until    *string        `json:"until"`
	Settings map[string]any `json:"settings"`
}

func readManagedSettings() map[string]any {
	for _, p := range managedSettingsPaths() {
		raw, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		var m map[string]any
		if json.Unmarshal(raw, &m) == nil {
			return m
		}
	}
	return nil
}

// Only the machine file's proxy and CA file are used (CLEVR_PROXY,
// CLEVR_CA_FILE, the names every Clevr client on the machine reads:
// docs/integrate/network.mdx): the person's proxy variables could otherwise
// send the question nowhere and leave the machine on its floor. A proxy
// written without a scheme is http://; the CA file is added to the system's
// roots, never put in their place.
func policyTransport(proxy, caFile string) *http.Transport {
	tr := &http.Transport{Proxy: nil}
	if proxy != "" {
		if !strings.Contains(proxy, "://") {
			proxy = "http://" + proxy
		}
		if u, err := neturl.Parse(proxy); err == nil {
			tr.Proxy = http.ProxyURL(u)
		}
	}
	if caFile != "" {
		if pem, err := os.ReadFile(caFile); err == nil {
			pool, err := x509.SystemCertPool()
			if err != nil || pool == nil {
				pool = x509.NewCertPool()
			}
			if pool.AppendCertsFromPEM(pem) {
				tr.TLSClientConfig = &tls.Config{RootCAs: pool}
			}
		}
	}
	return tr
}

// The tier, asked with a machine token when the machine file names this
// machine's id and its custody answers (machinetoken.go), else with the key.
// Within six seconds in all: Claude Code gives the helper eight.
func fetchPolicy(base, key, machineID, host, proxy, caFile string) (*policyAnswer, error) {
	if base == "" {
		return nil, errors.New("no engine in the machine file")
	}
	client := &http.Client{Timeout: 5 * time.Second, Transport: policyTransport(proxy, caFile)}
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	bearer, err := engineBearer(ctx, client, base, key, machineID, systemCustodySocketPath(), os.Stderr)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, "GET", strings.TrimRight(base, "/")+"/v1/endpoints/policy?host="+neturl.QueryEscape(host), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return nil, fmt.Errorf("HTTP %d", res.StatusCode)
	}
	var a policyAnswer
	if err := json.NewDecoder(res.Body).Decode(&a); err != nil {
		return nil, err
	}
	return &a, nil
}

func hostOfURL(u string) string {
	p, err := neturl.Parse(u)
	if err != nil {
		return ""
	}
	return p.Hostname()
}

// The profile's settings with the tier's own replaced by Clevr's. A strict
// network allowlist still reaches the engine and the gateway.
func mergePolicy(profile, tier map[string]any, engineURL string) map[string]any {
	out := map[string]any{}
	for k, v := range profile {
		if k != "policyHelper" && !tierOwned[k] {
			out[k] = v
		}
	}
	env := map[string]any{}
	if e, ok := profile["env"].(map[string]any); ok {
		for k, v := range e {
			if k != "CLEVR_MODE" && k != "CLEVR_FAILSAFE" {
				env[k] = v
			}
		}
	}
	for k, v := range tier {
		if k == "env" {
			if e, ok := v.(map[string]any); ok {
				for ek, ev := range e {
					env[ek] = ev
				}
			}
			continue
		}
		out[k] = v
	}
	out["env"] = env
	if sb, ok := out["sandbox"].(map[string]any); ok {
		if nw, ok := sb["network"].(map[string]any); ok {
			domains, _ := nw["allowedDomains"].([]any)
			have := map[string]bool{}
			for _, d := range domains {
				if s, ok := d.(string); ok {
					have[s] = true
				}
			}
			gateway, _ := env["ANTHROPIC_BASE_URL"].(string)
			for _, u := range []string{engineURL, gateway} {
				if h := hostOfURL(u); h != "" && !have[h] {
					domains = append(domains, h)
					have[h] = true
				}
			}
			nw["allowedDomains"] = domains
		}
	}
	return out
}

// What Claude Code applies on this machine when the profile names a helper:
// the profile merged with the tier Clevr gives, or the profile alone.
func effectiveSettings(profile map[string]any) (map[string]any, bool) {
	host, _ := os.Hostname()
	base := machineVar("CLEVR_URL")
	a, err := fetchPolicy(base, machineVar("CLEVR_API_KEY"), machineIDFor(base), host, machineVar("CLEVR_PROXY"), machineVar("CLEVR_CA_FILE"))
	if err != nil || a.Tier == nil || a.Settings == nil {
		return profile, false
	}
	return mergePolicy(profile, a.Settings, machineVar("CLEVR_URL")), true
}

func runPolicy() {
	emit := func(v any) {
		b, _ := json.Marshal(v)
		os.Stdout.Write(b)
		os.Exit(0)
	}
	profile := readManagedSettings()
	if profile == nil {
		fmt.Fprintln(os.Stderr, "clevr-policy: no managed settings file to build on; the profile applies")
		emit(map[string]any{})
	}
	merged, fromClevr := effectiveSettings(profile)
	if !fromClevr {
		fmt.Fprintln(os.Stderr, "clevr-policy: no tier from Clevr; the profile applies")
		emit(map[string]any{})
	}
	emit(map[string]any{"managedSettings": merged})
}
