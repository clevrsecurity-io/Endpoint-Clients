//go:build !darwin && !linux && !windows

package main

import (
	"errors"
	"fmt"
	"net"
	"os"
)

func peerPID(net.Conn) (int, error)           { return 0, errors.New("unsupported") }
func processTable() (map[int]procInfo, error) { return nil, errors.New("unsupported") }
func installCustody()                         {}
func listenCustody(*custody, string) {
	fmt.Fprintln(os.Stderr, "Session key custody is not available on this platform (macOS, Linux and Windows only).")
	os.Exit(2)
}
