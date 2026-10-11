// Session key custody (docs-internal/SPEC-SESSION-IDENTITY-2026-10-10.md, phase 4).
//
//	clevr-endpoint --custody            hold session keys for the hooks on this machine
//	clevr-endpoint --custody --install  also write a login item that starts it
//
// A harness hook used to keep its session key in a 0600 file under the user's
// account (integrations/claude-code/hooks/clevr-common.mjs), where a model
// running shell commands as that user could read it and take it off the
// machine. Here the key is made and kept in this process's memory and never
// written anywhere. A hook asks for it over a socket only the user can open:
//
//	{"op":"open","session_id":S,"agent":A,"runtime":R}  -> {"public_key":...}
//	{"op":"sign","session_id":S,"agent":A,"digest":D,"ts":T,"nonce":N} -> {"sig":"ed25519:..."}
//
// A key signs only the session signing string (lib/session_identity.js) of the
// session it was made for, and only for a process that descends from the
// harness process that opened it: the harness is read from the kernel's
// process table at "open" (the asking hook's first ancestor that is not a
// shell), and every "sign" must come from below that same process, same pid
// and same start time. A command the model runs is below its own harness too,
// so it can have its own session's calls signed, which it could already do
// through the hook; it cannot carry the key away, and it cannot sign for a
// session another harness opened.
//
// Not covered, said plainly: a process of the same user that can read this
// one's memory (root, a debugger the user allowed, Linux with ptrace_scope 0),
// and Windows, which has no peer process on a local socket in Go's standard
// library: --custody refuses to start there.
package main

import (
	"bufio"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const custodyIdle = 24 * time.Hour

type procInfo struct {
	pid, ppid   int
	start, name string
}

type custodyKey struct {
	priv     ed25519.PrivateKey
	pub      string
	agent    string
	harness  procInfo
	lastUsed time.Time
}

type custodyReq struct {
	Op        string `json:"op"`
	SessionID string `json:"session_id"`
	Agent     string `json:"agent"`
	Runtime   string `json:"runtime"`
	Digest    string `json:"digest"`
	TS        int64  `json:"ts"`
	Nonce     string `json:"nonce"`
}

type custody struct {
	mu   sync.Mutex
	keys map[string]*custodyKey
	// The process table, and the asking process's pid: the platform's, or a
	// test's.
	table func() (map[int]procInfo, error)
	now   func() time.Time
}

func newCustody() *custody {
	return &custody{keys: map[string]*custodyKey{}, table: processTable, now: time.Now}
}

var shells = map[string]bool{"sh": true, "bash": true, "zsh": true, "dash": true, "fish": true, "ksh": true, "tcsh": true, "csh": true, "pwsh": true, "powershell": true, "cmd.exe": true}

func baseName(p string) string {
	n := filepath.Base(strings.TrimSpace(p))
	return strings.TrimPrefix(n, "-") // a login shell reads "-zsh"
}

// The harness a hook runs under: its first ancestor that is not a shell. The
// hook itself (an interpreter running the hook's script) is skipped.
func harnessOf(peer int, tab map[int]procInfo) (procInfo, bool) {
	p, ok := tab[peer]
	if !ok {
		return procInfo{}, false
	}
	cur, ok := tab[p.ppid]
	for i := 0; ok && i < 16 && cur.pid > 1; i++ {
		if !shells[baseName(cur.name)] {
			return cur, true
		}
		cur, ok = tab[cur.ppid]
	}
	return procInfo{}, false
}

// Whether a process descends from h, the same process (pid and start time).
func descendsFrom(peer int, h procInfo, tab map[int]procInfo) bool {
	cur, ok := tab[peer]
	for i := 0; ok && i < 64 && cur.pid > 1; i++ {
		if cur.pid == h.pid {
			return cur.start == h.start
		}
		cur, ok = tab[cur.ppid]
	}
	return false
}

// What the session key signs: byte for byte the brain's sessionSigningString.
func sessionSigningString(sid, agent, digest string, ts int64, nonce string) string {
	return strings.Join([]string{"clevr-session-v1", sid, agent, digest, fmt.Sprint(ts), nonce}, "\n")
}

func (c *custody) handle(req custodyReq, peer int) (map[string]any, error) {
	if req.Op == "hello" {
		return map[string]any{"ok": true, "version": version, "custody": "memory"}, nil
	}
	if req.SessionID == "" || len(req.SessionID) > 200 || req.Agent == "" || len(req.Agent) > 200 {
		return nil, errors.New("session_id and agent are required")
	}
	tab, err := c.table()
	if err != nil {
		return nil, errors.New("the process table could not be read")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	k := c.keys[req.SessionID]
	switch req.Op {
	case "open":
		h, ok := harnessOf(peer, tab)
		if !ok {
			return nil, errors.New("no harness process above the caller")
		}
		if k != nil {
			if k.harness.pid != h.pid || k.harness.start != h.start || k.agent != req.Agent {
				return nil, errors.New("this session is held for another harness")
			}
			k.lastUsed = c.now()
			return map[string]any{"public_key": k.pub, "harness": h.name, "reused": true}, nil
		}
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, errors.New("no key could be made")
		}
		k = &custodyKey{priv: priv, pub: base64.StdEncoding.EncodeToString(pub), agent: req.Agent, harness: h, lastUsed: c.now()}
		c.keys[req.SessionID] = k
		fmt.Fprintf(os.Stderr, "custody: session opened for %s under %s (pid %d)\n", req.Agent, baseName(h.name), h.pid)
		return map[string]any{"public_key": k.pub, "harness": h.name}, nil
	case "sign":
		if k == nil {
			return nil, errors.New("no key is held for this session")
		}
		if k.agent != req.Agent {
			return nil, errors.New("this session's key belongs to another agent")
		}
		if !descendsFrom(peer, k.harness, tab) {
			return nil, errors.New("the caller does not run under the harness that opened this session")
		}
		if req.Digest == "" || req.Nonce == "" || req.TS <= 0 {
			return nil, errors.New("digest, ts and nonce are required")
		}
		k.lastUsed = c.now()
		sig := ed25519.Sign(k.priv, []byte(sessionSigningString(req.SessionID, req.Agent, req.Digest, req.TS, req.Nonce)))
		return map[string]any{"sig": "ed25519:" + base64.StdEncoding.EncodeToString(sig)}, nil
	case "forget":
		if k != nil && descendsFrom(peer, k.harness, tab) {
			delete(c.keys, req.SessionID)
		}
		return map[string]any{"ok": true}, nil
	}
	return nil, errors.New("unknown op")
}

// Keys idle a day, or whose harness is gone, are dropped.
func (c *custody) sweep() {
	tab, err := c.table()
	c.mu.Lock()
	defer c.mu.Unlock()
	for sid, k := range c.keys {
		gone := false
		if err == nil {
			p, ok := tab[k.harness.pid]
			gone = !ok || p.start != k.harness.start
		}
		if gone || c.now().Sub(k.lastUsed) > custodyIdle {
			delete(c.keys, sid)
		}
	}
}

func custodySocketPath() string {
	if p := os.Getenv("CLEVR_CUSTODY_SOCK"); p != "" {
		return p
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".clevr", "custody.sock")
}

func (c *custody) serve(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	reply := func(v map[string]any) { b, _ := json.Marshal(v); _, _ = conn.Write(append(b, '\n')) }
	peer, err := peerPID(conn)
	if err != nil || peer <= 0 {
		reply(map[string]any{"error": "the caller could not be identified"})
		return
	}
	line, err := bufio.NewReaderSize(conn, 16<<10).ReadBytes('\n')
	if err != nil && len(line) == 0 {
		return
	}
	var req custodyReq
	if json.Unmarshal(line, &req) != nil {
		reply(map[string]any{"error": "unreadable request"})
		return
	}
	out, err := c.handle(req, peer)
	if err != nil {
		reply(map[string]any{"error": err.Error()})
		return
	}
	reply(out)
}

func runCustody() {
	if !custodySupported {
		fmt.Fprintln(os.Stderr, "Session key custody is not available on this platform yet (macOS and Linux only).")
		os.Exit(2)
	}
	path := custodySocketPath()
	_ = os.MkdirAll(filepath.Dir(path), 0o700)
	_ = os.Chmod(filepath.Dir(path), 0o700)
	if conn, err := net.DialTimeout("unix", path, time.Second); err == nil {
		conn.Close()
		fmt.Fprintln(os.Stderr, "Session key custody is already running on", path)
		os.Exit(0)
	}
	_ = os.Remove(path)
	ln, err := net.Listen("unix", path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "custody: cannot listen on", path, err)
		os.Exit(1)
	}
	_ = os.Chmod(path, 0o600)
	if hasArg("--install") {
		installCustody()
	}
	c := newCustody()
	go func() {
		for range time.Tick(time.Hour) {
			c.sweep()
		}
	}()
	fmt.Fprintf(os.Stderr, "Session key custody on %s. Keys are held in memory only.\n", path)
	for {
		conn, err := ln.Accept()
		if err != nil {
			continue
		}
		go c.serve(conn)
	}
}
