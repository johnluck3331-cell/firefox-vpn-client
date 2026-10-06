//go:build windows

package ipc

import (
	"context"
	"errors"
	"fmt"
	"os"
	"syscall"
	"time"
	"unsafe"
)

var (
	procCreateFileW        = kernel32.NewProc("CreateFileW")
	procWaitNamedPipeW     = kernel32.NewProc("WaitNamedPipeW")
	procGetFileType        = kernel32.NewProc("GetFileType")
	fileTypePipe           = 0x0003
	genericRead            = 0x80000000
	genericWrite           = 0x40000000
	openExisting           = 3
	shareReadWrite         = 0x00000003
	securityIdentification = 0x00080000
	customSecuritySQOSFlag = SECURITY_SQOS_PRESENT | securityIdentification
)

// DialPipeClient connects to the service's named pipe, waiting up to
// waitTimeout for the server to come up, and returns a Client speaking the
// versioned JSONL protocol. Use PipeNameDefault unless overridden.
func DialPipeClient(ctx context.Context, name string, waitTimeout time.Duration) (*Client, error) {
	if name == "" {
		name = PipeNameDefault
	}
	deadline := time.Now().Add(waitTimeout)
	var lastErr error
	for {
		h, err := openPipe(name)
		if err == nil {
			f := os.NewFile(uintptr(h), name)
			if f == nil {
				return nil, errors.New("ipc: os.NewFile failed")
			}
			return NewClient(f), nil
		}
		lastErr = err
		if time.Now().After(deadline) || ctx.Err() != nil {
			return nil, fmt.Errorf("ipc: pipe %s unavailable: %w", name, lastErr)
		}
		// WaitNamedPipe blocks until an instance is available or timeout.
		rem := time.Until(deadline)
		ms := uint32(rem / time.Millisecond)
		if ms == 0 {
			ms = 1
		}
		p, _ := syscall.UTF16PtrFromString(name)
		procWaitNamedPipeW.Call(uintptr(unsafe.Pointer(p)), uintptr(ms))
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(50 * time.Millisecond):
		}
	}
}

func openPipe(name string) (syscall.Handle, error) {
	p, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return 0, err
	}
	ret, _, callErr := procCreateFileW.Call(
		uintptr(unsafe.Pointer(p)),
		uintptr(genericRead|genericWrite),
		uintptr(shareReadWrite),
		0,
		uintptr(openExisting),
		uintptr(customSecuritySQOSFlag),
		0,
	)
	if ret == ^uintptr(0) { // INVALID_HANDLE_VALUE
		return 0, callErr
	}
	// Double-check we actually got a pipe (defence against path confusion).
	ft, _, _ := procGetFileType.Call(ret)
	if ft != uintptr(fileTypePipe) {
		closeHandle(syscall.Handle(ret))
		return 0, errors.New("ipc: target is not a named pipe")
	}
	return syscall.Handle(ret), nil
}
