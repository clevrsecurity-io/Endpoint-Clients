//go:build darwin || linux

package main

import (
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

// Whether this account owns a file (the daemon's journal key, main.go).
func ownedByMe(fi os.FileInfo) bool {
	st, ok := fi.Sys().(*syscall.Stat_t)
	return ok && int(st.Uid) == os.Getuid()
}

// A key file this account owns and no other account can read or write.
func keyFilePrivate(path string, fi os.FileInfo) error {
	if !ownedByMe(fi) {
		return fmt.Errorf("the machine key %s does not belong to the account this custody runs as (uid %d)", path, os.Getuid())
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("the machine key %s is open to other accounts (mode %04o); it must be 0600", path, fi.Mode().Perm())
	}
	return nil
}

// A new file in dir, 0600 before anything is written to it.
func createPrivateTemp(dir, pattern string) (*os.File, error) {
	f, err := os.CreateTemp(dir, pattern)
	if err != nil {
		return nil, err
	}
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		os.Remove(f.Name())
		return nil, err
	}
	return f, nil
}

// The system custody's socket, for --enroll and the machine token.
func dialSystemCustody(path string) (io.ReadWriteCloser, error) {
	conn, err := net.DialTimeout("unix", path, 2*time.Second)
	if err != nil {
		return nil, err
	}
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	return conn, nil
}

// A local socket only this user can open (macOS, Linux); the system
// custody's, every account (its folder is the service's, made by deploy/mdm or
// systemd, and left as it is).
func listenCustody(c *custody, path string) {
	system := c.machine != nil
	if system {
		_ = os.MkdirAll(filepath.Dir(path), 0o755)
	} else {
		_ = os.MkdirAll(filepath.Dir(path), 0o700)
		_ = os.Chmod(filepath.Dir(path), 0o700)
	}
	if conn, err := net.DialTimeout("unix", path, time.Second); err == nil {
		conn.Close()
		fmt.Fprintln(os.Stderr, "Session key custody is already running on", path)
		return
	}
	if fi, err := os.Lstat(path); system && err == nil && fi.Mode()&os.ModeSocket == 0 {
		fmt.Fprintln(os.Stderr, "custody:", path, "is there and is not a socket; it is left as it is")
		os.Exit(1)
	}
	_ = os.Remove(path)
	ln, err := net.Listen("unix", path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "custody: cannot listen on", path, err)
		os.Exit(1)
	}
	if system {
		_ = os.Chmod(path, 0o666)
		fmt.Fprintf(os.Stderr, "System custody on %s, for every account. Session keys in memory; the machine key %s.\n", path, c.machine.pub)
	} else {
		_ = os.Chmod(path, 0o600)
		if hasArg("--install") {
			installCustody()
		}
		fmt.Fprintf(os.Stderr, "Session key custody on %s. Keys are held in memory only.\n", path)
	}
	for {
		conn, err := ln.Accept()
		if err != nil {
			continue
		}
		go c.serve(conn)
	}
}
