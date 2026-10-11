//go:build darwin || linux

package main

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"
)

// A local socket only this user can open (macOS, Linux).
func listenCustody(c *custody, path string) {
	_ = os.MkdirAll(filepath.Dir(path), 0o700)
	_ = os.Chmod(filepath.Dir(path), 0o700)
	if conn, err := net.DialTimeout("unix", path, time.Second); err == nil {
		conn.Close()
		fmt.Fprintln(os.Stderr, "Session key custody is already running on", path)
		return
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
	fmt.Fprintf(os.Stderr, "Session key custody on %s. Keys are held in memory only.\n", path)
	for {
		conn, err := ln.Accept()
		if err != nil {
			continue
		}
		go c.serve(conn)
	}
}
