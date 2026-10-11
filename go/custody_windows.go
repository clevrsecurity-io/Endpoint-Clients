//go:build windows

package main

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"syscall"
	"time"
	"unsafe"
)

// Session key custody on Windows: a named pipe instead of a local socket.
//
// The pipe is created with a security descriptor that lets this user alone
// open it (an owner-only DACL from the process token's SID), rejects clients
// from other machines (PIPE_REJECT_REMOTE_CLIENTS), and the kernel names the
// process at the other end (GetNamedPipeClientProcessId). The process table is
// the Toolhelp snapshot, with each process's creation time, so a pid Windows
// handed out again is not taken for the harness it replaced.
//
// Built and unit-tested from macOS; not yet run on a Windows machine.

var (
	kernel32                        = syscall.NewLazyDLL("kernel32.dll")
	advapi32                        = syscall.NewLazyDLL("advapi32.dll")
	procCreateNamedPipeW            = kernel32.NewProc("CreateNamedPipeW")
	procConnectNamedPipe            = kernel32.NewProc("ConnectNamedPipe")
	procDisconnectNamedPipe         = kernel32.NewProc("DisconnectNamedPipe")
	procGetNamedPipeClientProcessId = kernel32.NewProc("GetNamedPipeClientProcessId")
	procConvertSddl                 = advapi32.NewProc("ConvertStringSecurityDescriptorToSecurityDescriptorW")
)

const (
	pipeAccessDuplex          = 0x3
	fileFlagFirstPipeInstance = 0x00080000
	pipeRejectRemoteClients   = 0x8
	pipeUnlimitedInstances    = 255
	errorPipeConnected        = 535
	processQueryLimitedInfo   = 0x1000
	sddlRevision1             = 1
)

// The named pipe needs no net.Conn: serve() is the local socket's path.
func peerPID(net.Conn) (int, error) { return 0, errors.New("not used on Windows") }

// Every process: pid, parent, creation time and executable name.
func processTable() (map[int]procInfo, error) {
	snap, err := syscall.CreateToolhelp32Snapshot(syscall.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, err
	}
	defer syscall.CloseHandle(snap)
	var e syscall.ProcessEntry32
	e.Size = uint32(unsafe.Sizeof(e))
	tab := map[int]procInfo{}
	for err = syscall.Process32First(snap, &e); err == nil; err = syscall.Process32Next(snap, &e) {
		pid := int(e.ProcessID)
		var n int64
		if h, oerr := syscall.OpenProcess(processQueryLimitedInfo, false, e.ProcessID); oerr == nil {
			var c, x, k, u syscall.Filetime
			if syscall.GetProcessTimes(h, &c, &x, &k, &u) == nil {
				n = c.Nanoseconds()
			}
			syscall.CloseHandle(h)
		}
		tab[pid] = procInfo{pid: pid, ppid: int(e.ParentProcessID), start: strconv.FormatInt(n, 10), startN: n, name: syscall.UTF16ToString(e.ExeFile[:])}
	}
	return tab, nil
}

// A security descriptor that admits this user only.
func ownerOnly() (*syscall.SecurityAttributes, error) {
	tok, err := syscall.OpenCurrentProcessToken()
	if err != nil {
		return nil, err
	}
	defer tok.Close()
	tu, err := tok.GetTokenUser()
	if err != nil {
		return nil, err
	}
	sid, err := tu.User.Sid.String()
	if err != nil {
		return nil, err
	}
	sddl, err := syscall.UTF16PtrFromString("D:P(A;;GA;;;" + sid + ")")
	if err != nil {
		return nil, err
	}
	var sd uintptr
	if r, _, e := procConvertSddl.Call(uintptr(unsafe.Pointer(sddl)), sddlRevision1, uintptr(unsafe.Pointer(&sd)), 0); r == 0 {
		return nil, e
	}
	sa := &syscall.SecurityAttributes{SecurityDescriptor: sd}
	sa.Length = uint32(unsafe.Sizeof(*sa))
	return sa, nil
}

func newPipe(name *uint16, sa *syscall.SecurityAttributes, first bool) (syscall.Handle, error) {
	mode := uint32(pipeAccessDuplex)
	if first {
		mode |= fileFlagFirstPipeInstance
	}
	h, _, e := procCreateNamedPipeW.Call(uintptr(unsafe.Pointer(name)), uintptr(mode), pipeRejectRemoteClients,
		pipeUnlimitedInstances, 4096, 4096, 0, uintptr(unsafe.Pointer(sa)))
	if syscall.Handle(h) == syscall.InvalidHandle {
		return syscall.InvalidHandle, e
	}
	return syscall.Handle(h), nil
}

func listenCustody(c *custody, path string) {
	name, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "custody: bad pipe name", path)
		os.Exit(1)
	}
	sa, err := ownerOnly()
	if err != nil {
		fmt.Fprintln(os.Stderr, "custody: cannot restrict the pipe to this user:", err)
		os.Exit(1)
	}
	// The first instance must be ours: a pipe of that name already open is
	// either custody running or something standing in for it.
	h, err := newPipe(name, sa, true)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Session key custody is already running on", path, "(or the name is taken):", err)
		return
	}
	if hasArg("--install") {
		installCustody()
	}
	fmt.Fprintf(os.Stderr, "Session key custody on %s. Keys are held in memory only.\n", path)
	for {
		if r, _, e := procConnectNamedPipe.Call(uintptr(h), 0); r == 0 && e != syscall.Errno(errorPipeConnected) {
			syscall.CloseHandle(h)
		} else {
			go c.servePipe(h)
		}
		if h, err = newPipe(name, sa, false); err != nil {
			time.Sleep(200 * time.Millisecond)
			h, _ = newPipe(name, sa, false)
		}
	}
}

// One client on one pipe instance: the kernel's word for who it is, one line
// in, one line out.
func (c *custody) servePipe(h syscall.Handle) {
	defer syscall.CloseHandle(h)
	defer procDisconnectNamedPipe.Call(uintptr(h))
	// A client that never writes does not hold the instance.
	timer := time.AfterFunc(5*time.Second, func() { procDisconnectNamedPipe.Call(uintptr(h)) })
	defer timer.Stop()
	var pid uint32
	if r, _, _ := procGetNamedPipeClientProcessId.Call(uintptr(h), uintptr(unsafe.Pointer(&pid))); r == 0 {
		pid = 0
	}
	line := make([]byte, 0, 1024)
	buf := make([]byte, 1024)
	for len(line) < 16<<10 {
		var n uint32
		if err := syscall.ReadFile(h, buf, &n, nil); err != nil || n == 0 {
			break
		}
		line = append(line, buf[:n]...)
		if i := indexByte(line, '\n'); i >= 0 {
			line = line[:i+1]
			break
		}
	}
	out := c.respond(line, int(pid))
	var w uint32
	_ = syscall.WriteFile(h, out, &w, nil)
	_ = syscall.FlushFileBuffers(h)
}

func indexByte(b []byte, c byte) int {
	for i, x := range b {
		if x == c {
			return i
		}
	}
	return -1
}

// A logon task that starts custody: printed, for the person to run.
func installCustody() {
	exe, _ := os.Executable()
	fmt.Fprintf(os.Stderr, "To start custody at each sign-in, run once:\n  schtasks /Create /SC ONLOGON /TN \"Clevr session key custody\" /TR \"\\\"%s\\\" --custody\" /RL LIMITED\n", exe)
}
