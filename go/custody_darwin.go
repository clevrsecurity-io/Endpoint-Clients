//go:build darwin

package main

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

const custodySupported = true

// The pid at the other end of a local socket, from the kernel (LOCAL_PEERPID).
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
		// SOL_LOCAL = 0, LOCAL_PEERPID = 2 (sys/un.h)
		pid, gerr = syscall.GetsockoptInt(int(fd), 0, 2)
	}); err != nil {
		return 0, err
	}
	return pid, gerr
}

// Every process: pid, parent, start time and command, in one read.
func processTable() (map[int]procInfo, error) {
	out, err := exec.Command("/bin/ps", "-A", "-o", "pid=,ppid=,lstart=,comm=").Output()
	if err != nil {
		return nil, err
	}
	tab := map[int]procInfo{}
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Fields(line)
		// pid ppid Wed Oct 11 09:01:47 2026 command...
		if len(f) < 8 {
			continue
		}
		pid, e1 := strconv.Atoi(f[0])
		ppid, e2 := strconv.Atoi(f[1])
		if e1 != nil || e2 != nil {
			continue
		}
		tab[pid] = procInfo{pid: pid, ppid: ppid, start: strings.Join(f[2:7], " "), name: strings.Join(f[7:], " ")}
	}
	return tab, nil
}

// A login item that starts custody at sign-in (~/Library/LaunchAgents).
func installCustody() {
	exe, _ := os.Executable()
	home, _ := os.UserHomeDir()
	p := filepath.Join(home, "Library", "LaunchAgents", "com.clevrsecurity.custody.plist")
	plist := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>com.clevrsecurity.custody</string>
  <key>ProgramArguments</key><array><string>%s</string><string>--custody</string></array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
</dict></plist>
`, exe)
	_ = os.MkdirAll(filepath.Dir(p), 0o755)
	if err := os.WriteFile(p, []byte(plist), 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "custody: could not write", p, err)
		return
	}
	fmt.Fprintf(os.Stderr, "Wrote %s. It starts at the next sign-in; to start it now:\n  launchctl bootstrap gui/%d %s\n", p, os.Getuid(), p)
}
