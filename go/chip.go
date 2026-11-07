// The machine key in a chip (docs-internal/SPEC-MACHINE-KEY-LOT3-2026-11-06.md,
// lot 4).
//
//	clevr-endpoint --custody --system --hardware
//
// With --hardware, a custody that has no machine key yet makes it in the
// chip: the Secure Enclave on macOS (chip_darwin.go, through clevr-se-helper),
// the TPM on Windows (chip_windows.go, the Microsoft Platform Crypto
// Provider). The key is then P-256 (es256), its level "hardware", and the
// private half never leaves the chip: root, or an administrator, can still
// have it sign while on the machine, but cannot carry it away. Where there is
// no chip, or it does not answer, the key is made in software at the
// "service" level, as without the flag. A key already made stays as it is,
// whatever the flag: the installers move a machine to the chip by removing
// its key before a new enrolment. Linux has no chip here.
package main

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const (
	chipSecureEnclave = "secure-enclave"
	chipTPM           = "tpm"
)

// A key a chip holds: its public half and how to have it sign.
type chipKey struct {
	pub  string // base64 of the SPKI DER (P-256)
	blob string // the Secure Enclave's opaque blob, kept in the key file
	name string // the TPM's persisted key name, kept in the key file
	sign func(msg []byte) ([]byte, error)
}

type chip interface {
	kind() string
	create() (*chipKey, error)
	open(kf machineKeyFile) (*chipKey, error)
}

// The P-256 public key in an SPKI DER, base64; an error when it is not one.
func p256FromSPKI(b64 string) (*ecdsa.PublicKey, error) {
	der, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, errors.New("the public key is not base64")
	}
	k, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("the public key is not an SPKI: %v", err)
	}
	ec, ok := k.(*ecdsa.PublicKey)
	if !ok || ec.Curve != elliptic.P256() {
		return nil, errors.New("the public key is not P-256")
	}
	return ec, nil
}

// Whether raw r||s (64 bytes) is pub's ECDSA signature of SHA-256(msg).
func verifyES256(pub *ecdsa.PublicKey, msg, raw []byte) bool {
	if len(raw) != 64 {
		return false
	}
	h := sha256.Sum256(msg)
	return ecdsa.Verify(pub, h[:], new(big.Int).SetBytes(raw[:32]), new(big.Int).SetBytes(raw[32:]))
}

// A chip's signer, checked against the public key it was opened with: a
// signature the engine would refuse is never handed out.
func checkedSigner(pub string, sign func([]byte) ([]byte, error)) (func([]byte) ([]byte, error), error) {
	ec, err := p256FromSPKI(pub)
	if err != nil {
		return nil, err
	}
	return func(msg []byte) ([]byte, error) {
		raw, err := sign(msg)
		if err != nil {
			return nil, err
		}
		if !verifyES256(ec, msg, raw) {
			return nil, errors.New("the chip's signature does not verify with its public key")
		}
		return raw, nil
	}, nil
}

// A BCRYPT_ECCKEY_BLOB (ECCPUBLICBLOB, as NCryptExportKey writes it) as an
// SPKI DER, base64: magic "ECS1" (ECDSA P-256 public), the coordinate length
// (32), X, then Y, little-endian header.
func eccPublicBlobToSPKI(blob []byte) (string, error) {
	const magicECDSAP256Public = 0x31534345
	if len(blob) != 8+64 || binary.LittleEndian.Uint32(blob[0:4]) != magicECDSAP256Public || binary.LittleEndian.Uint32(blob[4:8]) != 32 {
		return "", errors.New("the TPM's public key is not an ECDSA P-256 public blob")
	}
	// The uncompressed point, which ecdh checks is on the curve.
	pt, err := ecdh.P256().NewPublicKey(append([]byte{4}, blob[8:72]...))
	if err != nil {
		return "", errors.New("the TPM's public key is not on P-256")
	}
	der, err := x509.MarshalPKIXPublicKey(pt)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(der), nil
}

// The Secure Enclave, through clevr-se-helper (endpoint-agent/se-helper). The
// blob goes on stdin, never in argv where ps shows it.
type seChip struct{ helper string }

func (seChip) kind() string { return chipSecureEnclave }

func (c seChip) run(stdin string, args ...string) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, c.helper, args...)
	cmd.Stdin = strings.NewReader(stdin)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	cmd.Env = []string{"PATH=/usr/bin:/bin"}
	if err := cmd.Run(); err != nil {
		if msg := strings.TrimSpace(errb.String()); msg != "" {
			return nil, fmt.Errorf("clevr-se-helper %s: %s", args[0], msg)
		}
		return nil, fmt.Errorf("clevr-se-helper %s: %v", args[0], err)
	}
	return strings.Fields(out.String()), nil
}

func (c seChip) key(blob, pub string) (*chipKey, error) {
	sign, err := checkedSigner(pub, func(msg []byte) ([]byte, error) {
		out, err := c.run(blob+"\n"+base64.StdEncoding.EncodeToString(msg)+"\n", "sign")
		if err != nil {
			return nil, err
		}
		if len(out) != 1 {
			return nil, errors.New("clevr-se-helper sign: no signature")
		}
		return base64.StdEncoding.DecodeString(out[0])
	})
	if err != nil {
		return nil, err
	}
	return &chipKey{pub: pub, blob: blob, sign: sign}, nil
}

func (c seChip) create() (*chipKey, error) {
	if _, err := c.run("", "available"); err != nil {
		return nil, err
	}
	out, err := c.run("", "create")
	if err != nil {
		return nil, err
	}
	if len(out) != 2 {
		return nil, errors.New("clevr-se-helper create: no blob and public key")
	}
	return c.key(out[0], out[1])
}

func (c seChip) open(kf machineKeyFile) (*chipKey, error) {
	out, err := c.run(kf.Blob+"\n", "public")
	if err != nil {
		return nil, err
	}
	if len(out) != 1 || out[0] != kf.Pub {
		return nil, errors.New("the Secure Enclave's key is not the one the key file names")
	}
	return c.key(kf.Blob, kf.Pub)
}

// The helper beside this binary (deploy/mdm puts both in /opt/clevr/bin), or
// CLEVR_SE_HELPER; "" when there is none.
func seHelperPath() string {
	if p := os.Getenv("CLEVR_SE_HELPER"); p != "" {
		return p
	}
	exe, err := os.Executable()
	if err != nil {
		return ""
	}
	p := filepath.Join(filepath.Dir(exe), "clevr-se-helper")
	if fi, err := os.Stat(p); err != nil || !fi.Mode().IsRegular() {
		return ""
	}
	return p
}
