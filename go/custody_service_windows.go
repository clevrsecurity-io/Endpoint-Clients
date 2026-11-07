//go:build windows

package main

// The system custody as a Windows service (Install-ClevrGate.ps1 installs it
// as ClevrCustody, under the virtual account NT SERVICE\ClevrCustody). The
// service control manager starts `clevr-endpoint --custody --system`; this
// answers it and runs the custody until it is asked to stop. A service has no
// console: what the custody says goes to custody.log beside the machine key.
//
// golang.org/x/sys/windows/svc is the endpoint agent's one dependency outside
// the standard library. Built and vetted from macOS; never run on Windows.

import (
	"os"
	"path/filepath"

	"golang.org/x/sys/windows/svc"
)

const custodyServiceName = "ClevrCustody"

type custodyService struct{ run func() }

// The custody runs until it is asked to stop. Should it return on its own (its
// pipe name taken), the service stops with an error, so the SCM's recovery
// restarts it rather than leaving it running with no pipe.
func (s custodyService) Execute(_ []string, req <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	status <- svc.Status{State: svc.StartPending}
	done := make(chan struct{})
	go func() { s.run(); close(done) }()
	status <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for {
		select {
		case <-done:
			return true, 1
		case c := <-req:
			switch c.Cmd {
			case svc.Interrogate:
				status <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				status <- svc.Status{State: svc.StopPending}
				return false, 0
			}
		}
	}
}

// Runs the custody under the service control manager, and says whether it
// did: false when this process was started from a console.
func runAsService(logDir string, run func()) bool {
	if is, err := svc.IsWindowsService(); err != nil || !is {
		return false
	}
	if logDir != "" {
		p := filepath.Join(logDir, "custody.log")
		flags := os.O_CREATE | os.O_WRONLY | os.O_APPEND
		if fi, err := os.Stat(p); err == nil && fi.Size() > 1<<20 {
			flags = os.O_CREATE | os.O_WRONLY | os.O_TRUNC
		}
		if f, err := os.OpenFile(p, flags, 0o600); err == nil {
			os.Stderr = f
		}
	}
	_ = svc.Run(custodyServiceName, custodyService{run: run})
	return true
}
