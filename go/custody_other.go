//go:build !darwin && !linux

package main

import (
	"errors"
	"net"
)

const custodySupported = false

func peerPID(net.Conn) (int, error)           { return 0, errors.New("unsupported") }
func processTable() (map[int]procInfo, error) { return nil, errors.New("unsupported") }
func installCustody()                         {}
