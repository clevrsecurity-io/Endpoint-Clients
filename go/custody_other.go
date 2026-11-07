//go:build !darwin && !linux && !windows

package main

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
)

func peerPID(net.Conn) (int, error)            { return 0, errors.New("unsupported") }
func processTable() (map[int]procInfo, error)  { return nil, errors.New("unsupported") }
func installCustody()                          {}
func ownedByMe(os.FileInfo) bool               { return false }
func keyFilePrivate(string, os.FileInfo) error { return errors.New("unsupported") }
func createPrivateTemp(string, string) (*os.File, error) {
	return nil, errors.New("unsupported")
}
func dialSystemCustody(string) (io.ReadWriteCloser, error) { return nil, errors.New("unsupported") }
func runAsService(string, func()) bool                     { return false }
func listenCustody(*custody, string) {
	fmt.Fprintln(os.Stderr, "Session key custody is not available on this platform (macOS, Linux and Windows only).")
	os.Exit(2)
}
