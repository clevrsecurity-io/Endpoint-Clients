//go:build darwin || linux

package main

// launchd and systemd start the system custody as a plain process.
func runAsService(string, func()) bool { return false }
