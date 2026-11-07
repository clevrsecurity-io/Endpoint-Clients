// Enrolment of this machine (docs-internal/SPEC-MACHINE-KEY-2026-11-06.md).
//
//	CLEVR_URL=... CLEVR_ENROLL_TOKEN=... clevr-endpoint --enroll
//
// Run as root (SYSTEM on Windows) by deploy/mdm, once the system custody runs. The custody signs the
// enrolment with the machine key; the engine pins its public half and, once the
// machine is approved, answers with a Clevr key bound to it, written to the
// machine file. A workspace that requires the machine answers no key: the
// machine file then holds CLEVR_URL and CLEVR_MACHINE_ID only, and the
// machine's clients present machine tokens (machinetoken.go). The token is
// read from the environment only and is never printed nor written.
//
// Exit: 0 enrolled, 3 waiting for an administrator's approval, 1 or 2 refused.
package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	neturl "net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const enrollPending = 3

// The machine file, or where a test puts it.
func agentEnvPath() string {
	if p := os.Getenv("CLEVR_AGENT_ENV"); p != "" {
		return p
	}
	return machineFilePath()
}

func runEnroll() int { return enroll(os.Stdout, os.Stderr) }

func enroll(stdout, stderr io.Writer) int {
	base, token := os.Getenv("CLEVR_URL"), os.Getenv("CLEVR_ENROLL_TOKEN")
	// Whatever is printed, the token is not.
	say := func(format string, a ...any) {
		msg := fmt.Sprintf(format, a...)
		if token != "" {
			msg = strings.ReplaceAll(msg, token, "[enrolment token]")
		}
		fmt.Fprintln(stderr, msg)
	}
	if base == "" || token == "" {
		say("--enroll needs CLEVR_URL and CLEVR_ENROLL_TOKEN in its environment.")
		return 2
	}
	if err := engineURLOK(base); err != nil {
		say("CLEVR_URL: %v", err)
		return 2
	}
	host := os.Getenv("CLEVR_ENROLL_HOST")
	if host == "" {
		host, _ = os.Hostname()
	}
	sock := systemCustodySocketPath()
	if sock == "" {
		say("Enrolment needs the system custody, on macOS, Linux and Windows only.")
		return 1
	}
	hello, err := askSystemCustody(sock, map[string]any{"op": "hello"})
	if err != nil || hello["machine"] != true {
		say("No system custody answers on %s: deploy/mdm starts clevr-endpoint --custody --system before it enrols the machine.", sock)
		return 1
	}
	client := enrollClient()
	endpoint := strings.TrimRight(base, "/")

	var ch struct {
		Challenge string `json:"challenge"`
	}
	if err := postEngine(context.Background(), client, endpoint+"/v1/machines/enroll/challenge", map[string]any{"token": token}, &ch); err != nil {
		say("Enrolment refused: %v", err)
		return 1
	}
	if ch.Challenge == "" {
		say("Enrolment refused: the engine gave no challenge.")
		return 1
	}
	signed, err := askSystemCustody(sock, map[string]any{"op": "machine_sign", "purpose": "enroll", "challenge": ch.Challenge, "host": host})
	if err != nil {
		say("The system custody did not sign the enrolment: %v", err)
		return 1
	}
	if e, _ := signed["error"].(string); e != "" {
		say("The system custody refused to sign the enrolment: %s", e)
		return 1
	}
	var got struct {
		MachineID string `json:"machine_id"`
		Status    string `json:"status"`
		APIKey    string `json:"api_key"`
	}
	body := map[string]any{"token": token, "public_key": signed["public_key"], "alg": signed["alg"], "custody": signed["custody"], "host": host, "challenge": ch.Challenge, "sig": signed["sig"]}
	if err := postEngine(context.Background(), client, endpoint+"/v1/machines/enroll", body, &got); err != nil {
		say("Enrolment refused: %v", err)
		return 1
	}
	switch got.Status {
	case "approved":
		if got.MachineID == "" {
			say("The engine approved the machine but gave no id for it.")
			return 1
		}
		path := agentEnvPath()
		if err := writeAgentEnv(path, base, got.APIKey, got.MachineID); err != nil {
			say("The machine is enrolled (%s) but its file could not be written to %s: %v", got.MachineID, path, err)
			return 1
		}
		if got.APIKey == "" {
			// The workspace requires the machine: no secret on disk, every
			// client asks the custody for a machine token.
			fmt.Fprintf(stdout, "This machine is enrolled (%s). It holds no Clevr key: its clients ask its custody for a machine token. Its id is in %s.\n", got.MachineID, path)
			return 0
		}
		fmt.Fprintf(stdout, "This machine is enrolled (%s). Its own Clevr key is in %s.\n", got.MachineID, path)
		return 0
	case "pending":
		fmt.Fprintf(stdout, "This machine is enrolled (%s) and waits for an administrator to approve it in the console, under Machines. Run the installer again once it is approved.\n", got.MachineID)
		return enrollPending
	}
	say("Enrolment refused: the engine answered status %q.", got.Status)
	return 1
}

// The token travels to an engine on https, or on http to this machine only.
func engineURLOK(base string) error {
	u, err := neturl.Parse(base)
	if err != nil || u.Host == "" {
		return errors.New("not a URL")
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		h := u.Hostname()
		if h == "localhost" || net.ParseIP(h).IsLoopback() {
			return nil
		}
		return errors.New("the enrolment token is sent over https only (http is for this machine's own address)")
	}
	return fmt.Errorf("scheme %q is not http or https", u.Scheme)
}

// The machine file's proxy and CA file, or the environment's (the installer's):
// CLEVR_PROXY, else HTTPS_PROXY and the others; CLEVR_CA_FILE beside the
// system's roots (policy.go policyTransport).
func enrollClient() *http.Client {
	proxy := firstNonEmpty(os.Getenv("CLEVR_PROXY"), machineVar("CLEVR_PROXY"))
	tr := policyTransport(proxy, firstNonEmpty(os.Getenv("CLEVR_CA_FILE"), machineVar("CLEVR_CA_FILE")))
	if proxy == "" {
		tr.Proxy = http.ProxyFromEnvironment
	}
	return &http.Client{Timeout: 15 * time.Second, Transport: tr}
}

// One POST to the engine; its error is the engine's message.
func postEngine(ctx context.Context, client *http.Client, url string, body any, out any) error {
	payload, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(res.Body, 64<<10))
	if res.StatusCode < 200 || res.StatusCode > 299 {
		var e struct {
			Error   string `json:"error"`
			Message string `json:"message"`
		}
		_ = json.Unmarshal(raw, &e)
		if msg := firstNonEmpty(e.Message, e.Error); msg != "" {
			return fmt.Errorf("%s (HTTP %d)", msg, res.StatusCode)
		}
		return fmt.Errorf("HTTP %d", res.StatusCode)
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return errors.New("the engine's answer is unreadable")
	}
	return nil
}

// One line to the system custody, one line back.
func askSystemCustody(path string, req map[string]any) (map[string]any, error) {
	conn, err := dialSystemCustody(path)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	line, _ := json.Marshal(req)
	if _, err := conn.Write(append(line, '\n')); err != nil {
		return nil, err
	}
	answer, err := bufio.NewReaderSize(conn, 16<<10).ReadBytes('\n')
	if err != nil && len(answer) == 0 {
		return nil, err
	}
	var out map[string]any
	if json.Unmarshal(answer, &out) != nil {
		return nil, errors.New("the custody's answer is unreadable")
	}
	return out, nil
}

var enrolledVars = map[string]bool{"CLEVR_URL": true, "CLEVR_API_KEY": true, "CLEVR_MACHINE_ID": true}

// The machine file with this machine's engine, key and id, every other line it
// had kept, written whole then renamed over the old one, readable by every
// account (the hooks run as the person) and changed by root only. With no key
// (a workspace that requires the machine), no CLEVR_API_KEY line at all, the
// fleet key's included.
func writeAgentEnv(path, url, key, machineID string) error {
	for _, v := range []string{url, machineID} {
		if v == "" {
			return errors.New("a value for the machine file is empty")
		}
	}
	for _, v := range []string{url, key, machineID} {
		if strings.ContainsAny(v, "\r\n\x00") {
			return errors.New("a value for the machine file spans lines")
		}
	}
	var b strings.Builder
	fmt.Fprintf(&b, "CLEVR_URL=%s\n", url)
	if key != "" {
		fmt.Fprintf(&b, "CLEVR_API_KEY=%s\n", key)
	}
	fmt.Fprintf(&b, "CLEVR_MACHINE_ID=%s\n", machineID)
	raw, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	for _, line := range strings.Split(strings.ReplaceAll(string(raw), "\r\n", "\n"), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		if m := machineLine.FindStringSubmatch(line); m != nil && enrolledVars[m[1]] {
			continue
		}
		b.WriteString(line + "\n")
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".agent.env.")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.WriteString(b.String()); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o644); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
