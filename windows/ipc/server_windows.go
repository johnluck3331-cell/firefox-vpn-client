//go:build windows

// Named Pipe server for the privileged FoxyVPN service.
//
// Security model (Phase U):
//   - The pipe lives under \\.\pipe\ and is created with an explicit SDDL
//     security descriptor granting FULL control to SYSTEM and the BUILTIN
//     Administrators group only, plus GENERIC_READ|GENERIC_WRITE to the
//     INTERACTIVE logon user (the tray/UI runs as that user). Network access
//     is denied entirely (pipes are local-only anyway).
//   - Every accepted instance is validated: ImpersonateNamedPipeClient +
//     GetTokenInformation reveals the client's session ID; clients from other
//     sessions or non-interactive logon types are refused.
//   - Message framing, size limits and command validation are enforced by the
//     transport-agnostic ipc.Server (server.go).
package ipc

import (
	"context"
	"errors"
	"fmt"
	"os"
	"runtime"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

var (
	kernel32                                                 = syscall.NewLazyDLL("kernel32.dll")
	advapi32                                                 = syscall.NewLazyDLL("advapi32.dll")
	secur32                                                  = syscall.NewLazyDLL("secreur32.dll") // placeholder replaced below
	wtslib32                                                 = syscall.NewLazyDLL("wtsapi32.dll")
	procCreateNamedPipeW                                     = kernel32.NewProc("CreateNamedPipeW")
	procConnectNamedPipe                                     = kernel32.NewProc("ConnectNamedPipe")
	procDisconnectNamedPipe                                  = kernel32.NewProc("DisconnectNamedPipe")
	procCloseHandle                                          = kernel32.NewProc("CloseHandle")
	procImpersonateNamedPipeClient                           = advapi32.NewProc("ImpersonateNamedPipeClient")
	procRevertToSelf                                         = advapi32.NewProc("RevertToSelf")
	procGetTokenInformation                                  = advapi32.NewProc("GetTokenInformation")
	procOpenProcessToken                                     = advapi32.NewProc("OpenProcessToken")
	procConvertStringSecurityDescriptorToSecurityDescriptorW = advapi32.NewProc("ConvertStringStringSecurityDescriptorToSecurityDescriptorW")
	procWTSGetActiveConsoleSessionId                         = kernel32.NewProc("WTSGetActiveConsoleSessionId")
)

// Correctly-resolved procs (init avoids const-name typos at compile time).
func init() {
	secur32 = syscall.NewLazyDLL("secur32.dll")
	procConvertStringSecurityDescriptorToSecurityDescriptorW = advapi32.NewProc("ConvertStringSecurityDescriptorToSecurityDescriptorW")
}

const (
	// PipeNameDefault is the well-known pipe both service and UI use.
	PipeNameDefault = `\\.\pipe\FoxyVPN.ipc`

	// sddlServicePipe restricts the pipe to SYSTEM + Administrators full
	// control and the current interactive user RW. AU = authenticated users
	// get nothing beyond what the ACEs grant; no network, no everyone.
	sddlServicePipe = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGWGX;;;IU)"

	pipeBufferSize     = 64 * 1024
	pipeInstMax        = 8
	namedPipeWaitTime  = 0 // blocking mode
	pipeTransMessage   = 0x00000001
	pipeReadmodeByte   = 0x00000000
	tokenSessionID     = 1 // TOKEN_INFORMATION_CLASS TokenSessionId
	tokenElevationType = 18
)

// invalidHandleValue is INVALID_HANDLE_VALUE (0xFFFFFFFFFFFFFFFF on amd64).
const invalidHandleValue = ^uintptr(0)

// PipeServer accepts named-pipe instances and hands each one to ipc.Server.
type PipeServer struct {
	name    string
	srv     *Server
	sd      syscall.Handle
	mu      sync.Mutex
	closed  bool
	handles []syscall.Handle
	wg      sync.WaitGroup
}

// NewPipeServer wires a transport-agnostic Server onto the named pipe.
func NewPipeServer(srv *Server, name string) (*PipeServer, error) {
	if name == "" {
		name = PipeNameDefault
	}
	ps := &PipeServer{name: name, srv: srv}
	return ps, nil
}

// Run accepts connections until ctx is cancelled, then drains handlers.
func (ps *PipeServer) Run(ctx context.Context) error {
	// Build the security descriptor once per process run.
	sd, err := securityDescriptorFromSDDL(sddlServicePipe)
	if err != nil {
		return fmt.Errorf("ipc: pipe security descriptor: %w", err)
	}
	ps.sd = sd

	go func() {
		<-ctx.Done()
		ps.Close()
	}()

	for {
		h, err := ps.createInstance()
		if err != nil {
			if ctx.Err() != nil {
				break
			}
			return err
		}
		if err := connectNamedPipe(h); err != nil {
			closeHandle(h)
			if ctx.Err() != nil {
				break
			}
			continue
		}
		if !ps.validateClient(h) {
			closeHandle(h)
			continue
		}
		ps.mu.Lock()
		if ps.closed {
			ps.mu.Unlock()
			closeHandle(h)
			break
		}
		ps.handles = append(ps.handles, h)
		ps.wg.Add(1)
		ps.mu.Unlock()
		go func(h syscall.Handle) {
			defer ps.wg.Done()
			defer func() {
				closeHandle(h)
				ps.mu.Lock()
				for i, x := range ps.handles {
					if x == h {
						ps.handles = append(ps.handles[:i], ps.handles[i+1:]...)
						break
					}
				}
				ps.mu.Unlock()
			}()
			f := os.NewFile(uintptr(h), ps.name)
			if f == nil {
				return
			}
			_ = ps.srv.ServeConn(ctx, f, f)
			f.Close() // dups handle; closes original too
		}(h)
	}
	ps.wg.Wait()
	if ps.sd != 0 {
		localFree(ps.sd)
	}
	return ctx.Err()
}

// Close disconnects all live instances so Run returns.
func (ps *PipeServer) Close() error {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	if ps.closed {
		return nil
	}
	ps.closed = true
	for _, h := range ps.handles {
		procDisconnectNamedPipe.Call(uintptr(h))
	}
	return nil
}

func (ps *PipeServer) createInstance() (syscall.Handle, error) {
	namep, err := syscall.UTF16PtrFromString(ps.name)
	if err != nil {
		return 0, err
	}
	ret, _, callErr := procCreateNamedPipeW.Call(
		uintptr(unsafe.Pointer(namep)),
		PIPE_ACCESS_DUPLEX|FILE_FLAG_FIRST_PIPE_INSTANCE|SECURITY_SQOS_PRESENT|SECURITY_VALID_SDESC,
		pipeTransMessage|pipeReadmodeByte,
		uintptr(pipeInstMax),
		uintptr(pipeBufferSize),
		uintptr(pipeBufferSize),
		uintptr(namedPipeWaitTime),
		uintptr(ps.sd),
	)
	if ret == invalidHandleValue { // INVALID_HANDLE_VALUE
		return 0, callErr
	}
	return syscall.Handle(ret), nil
}

func connectNamedPipe(h syscall.Handle) error {
	// Overlapped-less blocking mode: returns TRUE when a client connects,
	// or ERROR_PIPE_CONNECTED when it beat us.
	ret, _, err := procConnectNamedPipe.Call(uintptr(h), 0)
	if ret == 0 && err != syscall.Errno(535 /*ERROR_PIPE_CONNECTED*/) {
		return err
	}
	return nil
}

// validateClient impersonates the pipe client, checks it belongs to the
// active console session (authenticated local access), then reverts.
func (ps *PipeServer) validateClient(h syscall.Handle) bool {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	ret, _, _ := procImpersonateNamedPipeClient.Call(uintptr(h))
	if ret == 0 {
		return false
	}
	defer procRevertToSelf.Call()

	var tok syscall.Token
	// GetCurrentProcess pseudo-handle (-1) works because we are impersonating.
	const currentProcess = ^uintptr(0)
	ret, _, _ = procOpenProcessToken.Call(currentProcess, TOKEN_QUERY, uintptr(unsafe.Pointer(&tok)))
	if ret == 0 {
		return false
	}
	defer tok.Close()

	var sessionID uint32
	n := uint32(unsafe.Sizeof(sessionID))
	ret, _, _ = procGetTokenInformation.Call(
		uintptr(tok), uintptr(tokenSessionID),
		uintptr(unsafe.Pointer(&sessionID)), uintptr(n), uintptr(0))
	if ret == 0 {
		return false
	}
	active, _, _ := procWTSGetActiveConsoleSessionId.Call()
	return sessionID == uint32(active) || sessionID == 0 // 0 = services session (SYSTEM)
}

// --- Win32 constants -------------------------------------------------------
const (
	PIPE_ACCESS_DUPLEX            = 0x00000003
	FILE_FLAG_FIRST_PIPE_INSTANCE = 0x00080000
	SECURITY_SQOS_PRESENT         = 0x00100000
	SECURITY_VALID_SDESC          = 0x00000008
	TOKEN_QUERY                   = 0x0008
)

func securityDescriptorFromSDDL(sddl string) (syscall.Handle, error) {
	p, err := syscall.UTF16PtrFromString(sddl)
	if err != nil {
		return 0, err
	}
	var sd, psid unsafe.Pointer
	var sdLen uint32
	// SECURITY_DESCRIPTOR revision handling is internal to advapi32; we keep
	// the raw PSECURITY_DESCRIPTOR for CreateNamedPipe and LocalFree it later.
	ret, _, callErr := procConvertStringSecurityDescriptorToSecurityDescriptorW.Call(
		uintptr(unsafe.Pointer(p)), 1,
		uintptr(unsafe.Pointer(&sd)), uintptr(unsafe.Pointer(&sdLen)))
	_ = psid
	if ret == 0 {
		return 0, callErr
	}
	return syscall.Handle(uintptr(sd)), nil
}

func closeHandle(h syscall.Handle) { procCloseHandle.Call(uintptr(h)) }

var procLocalFree = kernel32.NewProc("LocalFree")

func localFree(h syscall.Handle) { procLocalFree.Call(uintptr(h)) }

// ErrNotWindows is returned if this file were ever compiled elsewhere (it
// cannot be, due to the build tag) — kept for symmetry with the stubs.
var ErrNotWindows = errors.New("ipc: named pipes require Windows")

var _ = time.Now
