// A machine token for the endpoint agent's own calls
// (docs-internal/SPEC-MACHINE-KEY-LOT3-2026-11-06.md, lot 3).
//
// A machine whose file names its id (CLEVR_MACHINE_ID) and whose system
// custody answers presents a token the engine signed, good ten minutes, in
// place of a Clevr key:
//
//	POST {url}/v1/machines/token/challenge {machine_id}           -> {challenge}
//	custody {"op":"machine_sign","purpose":"token",challenge,machine_id} -> {sig}
//	POST {url}/v1/machines/token {machine_id, challenge, sig}     -> {access_token}
//
// Nothing is kept: each run asks again. Otherwise the key, as before.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
)

// The id of this machine when the machine file names it for the engine asked:
// an id belongs to the engine the same file names.
func machineIDFor(base string) string {
	id := machineVar("CLEVR_MACHINE_ID")
	if id == "" || strings.TrimRight(machineVar("CLEVR_URL"), "/") != strings.TrimRight(base, "/") {
		return ""
	}
	return id
}

func machineToken(ctx context.Context, client *http.Client, base, machineID, sock string) (string, error) {
	if sock == "" {
		return "", errors.New("no system custody on this platform")
	}
	hello, err := askSystemCustody(sock, map[string]any{"op": "hello"})
	if err != nil || hello["machine"] != true {
		return "", fmt.Errorf("no system custody answers on %s", sock)
	}
	endpoint := strings.TrimRight(base, "/")
	var ch struct {
		Challenge string `json:"challenge"`
	}
	if err := postEngine(ctx, client, endpoint+"/v1/machines/token/challenge", map[string]any{"machine_id": machineID}, &ch); err != nil {
		return "", fmt.Errorf("no token challenge: %v", err)
	}
	if ch.Challenge == "" {
		return "", errors.New("the engine gave no token challenge")
	}
	signed, err := askSystemCustody(sock, map[string]any{"op": "machine_sign", "purpose": "token", "challenge": ch.Challenge, "machine_id": machineID})
	if err != nil {
		return "", fmt.Errorf("the custody did not sign the token challenge: %v", err)
	}
	sig, _ := signed["sig"].(string)
	if sig == "" {
		e, _ := signed["error"].(string)
		return "", fmt.Errorf("the custody refused to sign the token challenge: %s", e)
	}
	var tok struct {
		AccessToken string `json:"access_token"`
	}
	if err := postEngine(ctx, client, endpoint+"/v1/machines/token", map[string]any{"machine_id": machineID, "challenge": ch.Challenge, "sig": sig}, &tok); err != nil {
		return "", fmt.Errorf("no machine token: %v", err)
	}
	if !strings.HasPrefix(tok.AccessToken, "clevr_mt_") || strings.ContainsAny(tok.AccessToken, " \t\r\n") {
		return "", errors.New("the engine's answer is not a machine token")
	}
	return tok.AccessToken, nil
}

// What the endpoint agent sends as its Bearer: a machine token when this
// machine has an id for that engine and its custody answers, else the key. A
// token that cannot be had falls back to the key, said on stderr; with no key
// either, an error.
func engineBearer(ctx context.Context, client *http.Client, base, key, machineID, sock string, log io.Writer) (string, error) {
	if machineID != "" {
		tok, err := machineToken(ctx, client, base, machineID, sock)
		if err == nil {
			return tok, nil
		}
		if key == "" {
			return "", err
		}
		fmt.Fprintf(log, "clevr: no machine token (%v); the key is used\n", err)
	}
	if key == "" {
		return "", errors.New("no key and no enrolled machine")
	}
	return key, nil
}

// The report's and the helper's Bearer, from the machine file and the system custody.
func machineBearer(ctx context.Context, client *http.Client, base, key string) (string, error) {
	return engineBearer(ctx, client, base, key, machineIDFor(base), systemCustodySocketPath(), os.Stderr)
}
