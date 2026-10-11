//go:build linux

package main

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

const custodySupported = true

// The pid at the other end of a local socket, from the kernel (SO_PEERCRED).
func peerPID(conn net.Conn) (int, error) {
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return 0, errors.New("not a local socket")
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return 0, err
	}
	pid, gerr := 0, error(nil)
	if err := raw.Control(func(fd uintptr) {
		cred, e := syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
		if e != nil {
			gerr = e
			return
		}
		if int(cred.Uid) != os.Getuid() {
			gerr = errors.New("another user")
			return
		}
		pid = int(cred.Pid)
	}); err != nil {
		return 0, err
	}
	return pid, gerr
}

// Every process from /proc: pid, parent, start time (clock ticks since boot)
// and command.
func processTable() (map[int]procInfo, error) {
	ents, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}
	tab := map[int]procInfo{}
	for _, e := range ents {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		b, err := os.ReadFile(filepath.Join("/proc", e.Name(), "stat"))
		if err != nil {
			continue
		}
		s := string(b)
		open, close := strings.IndexByte(s, '('), strings.LastIndexByte(s, ')')
		if open < 0 || close < open {
			continue
		}
		f := strings.Fields(s[close+1:])
		// state ppid ... starttime is field 22 of stat, index 19 after the command
		if len(f) < 20 {
			continue
		}
		ppid, _ := strconv.Atoi(f[1])
		tab[pid] = procInfo{pid: pid, ppid: ppid, start: f[19], name: s[open+1 : close]}
	}
	return tab, nil
}

// A user service that starts custody at sign-in (systemd --user).
func installCustody() {
	exe, _ := os.Executable()
	home, _ := os.UserHomeDir()
	p := filepath.Join(home, ".config", "systemd", "user", "clevr-custody.service")
	unit := fmt.Sprintf("[Unit]\nDescription=Clevr session key custody\n\n[Service]\nExecStart=%s --custody\nRestart=always\n\n[Install]\nWantedBy=default.target\n", exe)
	_ = os.MkdirAll(filepath.Dir(p), 0o755)
	if err := os.WriteFile(p, []byte(unit), 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "custody: could not write", p, err)
		return
	}
	fmt.Fprintf(os.Stderr, "Wrote %s. To start it now and at each sign-in:\n  systemctl --user enable --now clevr-custody\n", p)
}
