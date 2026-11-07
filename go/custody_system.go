// The system custody (docs-internal/SPEC-MACHINE-KEY-2026-11-06.md).
//
//	clevr-endpoint --custody --system   run by deploy/mdm under its own account
//
// The custody of custody.go, run once for the machine under an account of its
// own (_clevr on macOS, clevr on Linux), on a socket every account can open
// (the kernel still names each caller). It holds the session keys as the
// per-user custody does, and one key for the machine, in a file only its
// account can read: the model's shell, running as the person, cannot carry it
// away. It signs the three machine signing strings it builds itself, never
// bytes a caller chose:
//
//	{"op":"machine_key"} -> {"public_key","alg","custody"}
//	{"op":"machine_sign","purpose":"session","challenge","agent","session_id","session_public_key","runtime"} -> {"sig"}
//	{"op":"machine_sign","purpose":"enroll","challenge","host"} -> {"sig","public_key","alg","custody"}
//	{"op":"machine_sign","purpose":"token","challenge","machine_id"} -> {"sig"}
//
// "session" signs only for a caller with a harness above it, as "open" does.
// "token" signs for any process of the machine: a machine token
// (docs-internal/SPEC-MACHINE-KEY-LOT3-2026-11-06.md) lives ten minutes and a
// key bound to the machine acts only inside sessions the machine opened.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// The system custody's socket and the machine key's file, the same on every
// caller (hook/go, clevr-common.mjs, brain/src/local/session_proof.ts). On
// Windows, a named pipe and %ProgramData%\Clevr (custody_windows.go).
func systemCustodySocketPath() string { return systemPaths(runtime.GOOS, os.Getenv).sock }
func machineKeyPath() string          { return systemPaths(runtime.GOOS, os.Getenv).key }

type systemPathSet struct{ sock, key string }

func systemPaths(goos string, getenv func(string) string) systemPathSet {
	var p systemPathSet
	switch goos {
	case "darwin":
		p = systemPathSet{"/Library/Application Support/Clevr/custody.sock", "/Library/Application Support/Clevr/machine-key.json"}
	case "linux":
		p = systemPathSet{"/run/clevr/custody.sock", "/var/lib/clevr/machine-key.json"}
	case "windows":
		// Joined by hand: this is read on every system, the Windows path too.
		p = systemPathSet{`\\.\pipe\clevr-custody-system`, strings.TrimRight(firstNonEmpty(getenv("ProgramData"), `C:\ProgramData`), `\`) + `\Clevr\machine-key.json`}
	default:
		return p
	}
	return systemPathSet{firstNonEmpty(getenv("CLEVR_SYSTEM_CUSTODY_SOCK"), p.sock), firstNonEmpty(getenv("CLEVR_MACHINE_KEY_FILE"), p.key)}
}

// Security descriptors in SDDL, built here so a test reads them on any system.
//
// The key file: this account alone, nothing inherited; SYSTEM and the
// administrators hold no entry (they can still take ownership, as root reads
// the file on macOS and Linux).
func privateFileSDDL(self string) string { return "D:P(A;;FA;;;" + self + ")" }

// The per-user pipe: its user alone.
func ownerOnlyPipeSDDL(self string) string { return "D:P(A;;GA;;;" + self + ")" }

// The system pipe: SYSTEM and the service's account in full; every account
// signed in on this machine may read and write (0x12019f, FILE_GENERIC_READ |
// FILE_GENERIC_WRITE: Node's hooks open a pipe with GENERIC_READ |
// GENERIC_WRITE, which asks for both); a network logon is denied, and the pipe
// also rejects remote clients (PIPE_REJECT_REMOTE_CLIENTS). FILE_GENERIC_WRITE
// carries FILE_APPEND_DATA, which on a pipe is FILE_CREATE_PIPE_INSTANCE: a
// local process could add an instance of its own and answer some callers. It
// cannot sign as the machine, so the worst it does is make them fail, which a
// workspace that requires the machine refuses. Never run on Windows: 0x12019b
// (no FILE_APPEND_DATA) is the tighter choice if Node's clients turn out to
// open it.
func systemPipeSDDL(self string) string {
	return "D:P(D;;GA;;;NU)(A;;GA;;;SY)(A;;GA;;;" + self + ")(A;;0x12019f;;;AU)"
}

// The machine key: Ed25519 in a file of the custody's account (level
// "service"), or P-256 in a chip (level "hardware", chip.go).
type machineKey struct {
	pub   string // ed25519: base64 of the raw 32 bytes; es256: base64 of the SPKI DER
	alg   string // ed25519 | es256
	level string // service | hardware
	priv  ed25519.PrivateKey
	chip  func(msg []byte) ([]byte, error) // a chip's raw r||s, when priv is nil
}

// "<alg>:" and the signature in base64, as the engine reads it.
func (m *machineKey) sign(s string) (string, error) {
	if m.priv != nil {
		return "ed25519:" + base64.StdEncoding.EncodeToString(ed25519.Sign(m.priv, []byte(s))), nil
	}
	raw, err := m.chip([]byte(s))
	if err != nil {
		return "", fmt.Errorf("the chip did not sign: %v", err)
	}
	return m.alg + ":" + base64.StdEncoding.EncodeToString(raw), nil
}

type machineKeyFile struct {
	Alg     string `json:"alg"`
	Seed    string `json:"seed,omitempty"`
	Pub     string `json:"pub"`
	Custody string `json:"custody,omitempty"` // "hardware": a chip holds the key
	Chip    string `json:"chip,omitempty"`    // secure-enclave | tpm
	Blob    string `json:"blob,omitempty"`    // the Secure Enclave's opaque blob
	Name    string `json:"name,omitempty"`    // the TPM key's name
}

// Where a key may live: the chip a new key goes in when the custody was asked
// for one (--hardware), and the chip a key file names.
type chipSource struct {
	want  bool
	make  func() (chip, error)
	named func(kind string) (chip, error)
}

func platformChips(want bool) chipSource {
	return chipSource{want: want, make: platformChip, named: chipNamed}
}

func loadMachineKey(path string) (*machineKey, error) {
	return loadMachineKeyFrom(path, platformChips(false))
}

// The machine key, made on the first start. A file that is there is used only
// when it is a plain file of this account that no other account can read or
// write, and holds a key whose public half is its seed's, or the chip's key it
// names; anything else is refused, never replaced: replacing it would change
// the machine's identity.
func loadMachineKeyFrom(path string, src chipSource) (*machineKey, error) {
	fi, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return createMachineKey(path, src)
	}
	if err != nil {
		return nil, fmt.Errorf("the machine key %s cannot be read: %v", path, err)
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("the machine key %s is not a regular file", path)
	}
	if err := keyFilePrivate(path, fi); err != nil {
		return nil, err
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("the machine key %s cannot be read: %v", path, err)
	}
	var kf machineKeyFile
	if json.Unmarshal(b, &kf) != nil {
		return nil, fmt.Errorf("the machine key %s is not a key this custody reads", path)
	}
	switch {
	case kf.Alg == "ed25519" && kf.Custody == "":
		seed, err := base64.StdEncoding.DecodeString(kf.Seed)
		if err != nil || len(seed) != ed25519.SeedSize {
			return nil, fmt.Errorf("the machine key %s has no readable seed", path)
		}
		priv := ed25519.NewKeyFromSeed(seed)
		pub := base64.StdEncoding.EncodeToString(priv.Public().(ed25519.PublicKey))
		if pub != kf.Pub {
			return nil, fmt.Errorf("the machine key %s names a public key that is not its seed's", path)
		}
		return &machineKey{pub: pub, alg: "ed25519", level: "service", priv: priv}, nil
	case kf.Alg == "es256" && kf.Custody == "hardware":
		// Never made again in software: that would be another machine.
		c, err := src.named(kf.Chip)
		if err != nil {
			return nil, fmt.Errorf("the machine key %s is held by the %s, which this custody cannot reach: %v", path, kf.Chip, err)
		}
		k, err := c.open(kf)
		if err != nil {
			return nil, fmt.Errorf("the machine key %s: the %s does not answer for it: %v", path, kf.Chip, err)
		}
		return &machineKey{pub: k.pub, alg: "es256", level: "hardware", chip: k.sign}, nil
	}
	return nil, fmt.Errorf("the machine key %s is not a key this custody reads", path)
}

// In the chip when one was asked for and answers, else in software. Written
// whole to a file of its own, then linked to its name, which fails when the
// name is taken: a key is never half written, nor written over one.
func createMachineKey(path string, src chipSource) (*machineKey, error) {
	dir := filepath.Dir(path)
	// The socket may share the folder (macOS), so others may cross it; the
	// key file itself is 0600.
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("the machine key's folder %s cannot be made: %v", dir, err)
	}
	var k *machineKey
	var kf machineKeyFile
	if src.want {
		c, err := src.make()
		var ck *chipKey
		if err == nil {
			ck, err = c.create()
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "custody: no chip holds the machine key (%v); it is made in software, at the service level\n", err)
		} else {
			k = &machineKey{pub: ck.pub, alg: "es256", level: "hardware", chip: ck.sign}
			kf = machineKeyFile{Alg: "es256", Pub: ck.pub, Custody: "hardware", Chip: c.kind(), Blob: ck.blob, Name: ck.name}
		}
	}
	if k == nil {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, errors.New("no machine key could be made")
		}
		k = &machineKey{pub: base64.StdEncoding.EncodeToString(pub), alg: "ed25519", level: "service", priv: priv}
		kf = machineKeyFile{Alg: "ed25519", Seed: base64.StdEncoding.EncodeToString(priv.Seed()), Pub: k.pub}
	}
	b, _ := json.Marshal(kf)
	tmp, err := createPrivateTemp(dir, ".machine-key-*")
	if err != nil {
		return nil, fmt.Errorf("the machine key cannot be written in %s: %v", dir, err)
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(append(b, '\n')); err != nil {
		tmp.Close()
		return nil, err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return nil, err
	}
	if err := tmp.Close(); err != nil {
		return nil, err
	}
	if err := os.Link(tmp.Name(), path); err != nil {
		if errors.Is(err, os.ErrExist) {
			return loadMachineKeyFrom(path, src)
		}
		return nil, fmt.Errorf("the machine key %s cannot be written: %v", path, err)
	}
	fmt.Fprintf(os.Stderr, "custody: a machine key (%s, %s) was made in %s\n", k.alg, k.level, path)
	return k, nil
}

// What the machine key signs, byte for byte the engine's verifier.
func machineEnrollSigningString(challenge, publicKey, alg, custody, host string) string {
	return strings.Join([]string{"clevr-machine-enroll-v1", challenge, publicKey, alg, custody, host}, "\n")
}

func machineSessionSigningString(challenge, agent, sessionID, sessionPublicKey, rt string) string {
	return strings.Join([]string{"clevr-machine-session-v1", challenge, agent, sessionID, sessionPublicKey, rt}, "\n")
}

func machineTokenSigningString(challenge, machineID string) string {
	return strings.Join([]string{"clevr-machine-token-v1", challenge, machineID}, "\n")
}

// The longest each field may be, as the engine's verifier reads them
// (brain/src/lib/identity/machine_keys.ts cleanField, routes/machines.js).
const (
	machineChallengeMax  = 600
	machineSessionKeyMax = 100
	machineFieldMax      = 200
	machineRuntimeMax    = 60
	machineHostMax       = 120
	machineIDMax         = 64
)

// A field of a signing string: there when required, within its length, and
// never a line break, which would let one field pass for two.
func machineField(name, v string, max int, required bool) error {
	if required && v == "" {
		return fmt.Errorf("%s is required", name)
	}
	if len(v) > max {
		return fmt.Errorf("%s is longer than %d bytes", name, max)
	}
	if strings.ContainsAny(v, "\r\n") {
		return fmt.Errorf("%s contains a line break", name)
	}
	return nil
}

func (c *custody) machineSign(req custodyReq, peer int) (map[string]any, error) {
	m := c.machine
	for name, v := range map[string]string{"challenge": req.Challenge, "agent": req.Agent, "session_id": req.SessionID, "session_public_key": req.SessionPublicKey, "runtime": req.Runtime, "host": req.Host, "machine_id": req.MachineID} {
		if strings.ContainsAny(v, "\r\n") {
			return nil, fmt.Errorf("%s contains a line break", name)
		}
	}
	switch req.Purpose {
	case "session":
		for _, f := range []error{
			machineField("challenge", req.Challenge, machineChallengeMax, true),
			machineField("agent", req.Agent, machineFieldMax, true),
			machineField("session_id", req.SessionID, machineFieldMax, true),
			machineField("session_public_key", req.SessionPublicKey, machineSessionKeyMax, true),
			machineField("runtime", req.Runtime, machineRuntimeMax, false),
		} {
			if f != nil {
				return nil, f
			}
		}
		tab, err := c.table()
		if err != nil {
			return nil, errors.New("the process table could not be read")
		}
		h, ok := harnessOf(peer, tab)
		if !ok {
			return nil, errors.New("no harness process above the caller")
		}
		// Only a session whose key this custody made and holds, for the same
		// agent, asked from under the harness that opened it. A key made
		// elsewhere could leave the machine with the session's token and act
		// from another one until the token expires.
		c.mu.Lock()
		k := c.keys[req.SessionID]
		held := k != nil && k.pub == req.SessionPublicKey && k.agent == req.Agent && descendsFrom(peer, k.harness, tab)
		c.mu.Unlock()
		if !held {
			return nil, errors.New("this custody holds no key for that session under the caller's harness")
		}
		sig, err := m.sign(machineSessionSigningString(req.Challenge, req.Agent, req.SessionID, req.SessionPublicKey, req.Runtime))
		if err != nil {
			return nil, err
		}
		fmt.Fprintf(os.Stderr, "custody: machine proof for %s under %s (pid %d)\n", req.Agent, baseName(h.name), h.pid)
		return map[string]any{"sig": sig}, nil
	case "enroll":
		for _, f := range []error{
			machineField("challenge", req.Challenge, machineChallengeMax, true),
			machineField("host", req.Host, machineHostMax, false),
		} {
			if f != nil {
				return nil, f
			}
		}
		sig, err := m.sign(machineEnrollSigningString(req.Challenge, m.pub, m.alg, m.level, req.Host))
		if err != nil {
			return nil, err
		}
		fmt.Fprintf(os.Stderr, "custody: enrolment signed for host %s (caller pid %d)\n", req.Host, peer)
		return map[string]any{"sig": sig, "public_key": m.pub, "alg": m.alg, "custody": m.level}, nil
	case "token":
		for _, f := range []error{
			machineField("challenge", req.Challenge, machineChallengeMax, true),
			machineField("machine_id", req.MachineID, machineIDMax, true),
		} {
			if f != nil {
				return nil, f
			}
		}
		sig, err := m.sign(machineTokenSigningString(req.Challenge, req.MachineID))
		if err != nil {
			return nil, err
		}
		return map[string]any{"sig": sig}, nil
	}
	return nil, errors.New("purpose must be session, enroll or token")
}
