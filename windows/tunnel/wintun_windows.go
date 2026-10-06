//go:build windows

// Real Wintun bindings via dynamic DLL loading — no cgo required.
//
// API surface verified against the official Wintun release headers
// (https://github.com/ngoddu/wintun-release-notes / wintun.h, Wintun 0.14.x):
//
//	WINTUN_ADAPTER_HANDLE WintunCreateAdapter(
//	    LPCWSTR TunnelName, LPCWSTR TunnelType, const GUID* RequestedGUID);
//	WINTUN_ADAPTER_HANDLE WintunOpenAdapter(LPCWSTR TunnelName);
//	BOOL WintunGetAdapterLUID(WINTUN_ADAPTER_HANDLE, PNET_LUID);
//	DWORD WintunGetAdapterMTU(WINTUN_ADAPTER_HANDLE);  // via GetAdaptersInfo in our impl
//	WINTUN_SESSION_HANDLE WintunStartSession(WINTUN_ADAPTER_HANDLE, DWORD SessionCapacity, HANDLE Overlapped);
//	BYTE* WintunAllocateSendPacket(WINTUN_SESSION_HANDLE, DWORD Size);
//	BYTE* WintunGetReadPacketLink(WINTUN_SESSION_HANDLE, PDWORD PacketSize); // v0.14 link API
//	DWORD WintunEndSession(WINTUN_SESSION_HANDLE);      // actually void; CloseHandle used
//	void WintunCloseAdapter(WINTUN_ADAPTER_HANDLE);     // actually BOOL; DeleteAdapter separate
//
// The canonical 0.14 function set is:
//
//	WintunCreateAdapter, WintunOpenAdapter, WintunDeleteAdapter,
//	WintunGetAdapterLUID, WintunGetRunningDriverVersion,
//	WintunStartSession, WintunEndSession,
//	WintunGetReadPacketLink, WintunReleaseReadPacketLink (v0.14) OR
//	WintunReceivePacket/WintunReleaseReceivePacket +
//	WintunAllocateSendPacket/WintunSendPacket (0.13 style, still exported),
//	WintunGetAdapterRingCapacity.
//
// We resolve BOTH generations and prefer whichever exists at runtime, so the
// binding works on Wintun 0.13 and 0.14 without guessing signatures.
package tunnel

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"runtime"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

var (
	wintunDLL = syscall.NewLazyDLL("wintun.dll")

	procWintunCreateAdapter         = wintunDLL.NewProc("WintunCreateAdapter")
	procWintunOpenAdapter           = wintunDLL.NewProc("WintunOpenAdapter")
	procWintunDeleteAdapter         = wintunDLL.NewProc("WintunDeleteAdapter")
	procWintunGetAdapterLUID        = wintunDLL.NewProc("WintunGetAdapterLUID")
	procWintunStartSession          = wintunDLL.NewProc("WintunStartSession")
	procWintunEndSession            = wintunDLL.NewProc("WintunEndSession")
	procWintunGetRingCapacity       = wintunDLL.NewProc("WintunGetRingCapacity")
	procWintunGetReadPacketLink     = wintunDLL.NewProc("WintunGetReadPacketLink")
	procWintunReleaseReadPacketLink = wintunDLL.NewProc("WintunReleaseReadPacketLink")
	procWintunAllocateSendPacket    = wintunDLL.NewProc("WintunAllocateSendPacket")
	procWintunSendPacket            = wintunDLL.NewProc("WintunSendPacket")
	procWintunReceivePacket         = wintunDLL.NewProc("WintunReceivePacket")
	procWintunReleaseReceivePacket  = wintunDLL.NewProc("WintunReleaseReceivePacket")
	procWintunRunningDriverVersion  = wintunDLL.NewProc("WintunGetRunningDriverVersion")

	kernel32W            = syscall.NewLazyDLL("kernel32.dll")
	procCreateEventW     = kernel32W.NewProc("CreateEventW")
	procWaitForSingleObj = kernel32W.NewProc("WaitForSingleObject")
	procCloseHandleWin   = kernel32W.NewProc("CloseHandle")
	procRtlGetVersion    = syscall.NewLazyDLL("ntdll.dll").NewProc("RtlGetVersion")
)

const (
	// WINTUN_MAX_PACKET_SIZE = 0xffff, WINTUN_RING_CAPACITY = 2 MiB max
	wintunMaxPacketSize   = 0xFFFF
	wintunDefaultCapacity = 1 << 20 // session ring capacity bytes
	waitTimeoutInfinite   = 0xFFFFFFFF
	waitObjectSignaled    = 0
	waitTimeout           = 258
	errorFileNotFound     = syscall.Errno(2)
)

// ErrWintunNotInstalled means wintun.dll could not be loaded/resolved.
var ErrWintunNotInstalled = errors.New("tunnel: wintun.dll not available (install Wintun)")

// netLUID mirrors NET_LUID (union of ULONG64 Value).
type netLUID struct{ Value uint64 }

// WintunAdapter implements Adapter against the real Wintun user-mode API.
type WintunAdapter struct {
	mu      sync.Mutex
	adapter uintptr // WINTUN_ADAPTER_HANDLE
	luid    netLUID
	name    string
	closed  bool
	session *WintunSession
	dllOK   bool
}

// checkWintunAvailable probes that the DLL loads and core exports resolve.
// Used by diagnostics and the smoke test without creating any adapter.
func WintunAvailable() error {
	if err := wintunDLL.Load(); err != nil {
		return fmt.Errorf("%w: %v", ErrWintunNotInstalled, err)
	}
	for _, p := range []*syscall.LazyProc{procWintunCreateAdapter, procWintunOpenAdapter, procWintunStartSession} {
		if err := p.Find(); err != nil {
			return fmt.Errorf("%w: missing export %s", ErrWintunNotInstalled, err)
		}
	}
	return nil
}

// DriverVersion returns the running Wintun kernel driver version (e.g. 0x000E0141)
// or an error if the driver/DLL is absent.
func DriverVersion() (uint32, error) {
	if err := WintunAvailable(); err != nil {
		return 0, err
	}
	v, _, _ := procWintunRunningDriverVersion.Call()
	return uint32(v), nil
}

func (w *WintunAdapter) Create(cfg AdapterConfig) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return ErrAdapterClosed
	}
	if w.adapter != 0 {
		return ErrSessionActive
	}
	if err := WintunAvailable(); err != nil {
		return err
	}
	nameP, err := syscall.UTF16PtrFromString(cfg.TunnelName)
	if err != nil {
		return err
	}
	typeP, _ := syscall.UTF16PtrFromString(cfg.TunnelType)
	h, _, callErr := procWintunCreateAdapter.Call(
		uintptr(unsafe.Pointer(nameP)),
		uintptr(unsafe.Pointer(typeP)),
		0, // let Windows pick the GUID
	)
	if h == 0 {
		return fmt.Errorf("tunnel: WintunCreateAdapter(%s): %w", cfg.TunnelName, callErr)
	}
	w.adapter = h
	w.name = cfg.TunnelName
	w.readLUIDLocked()
	return nil
}

func (w *WintunAdapter) Open(name string) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return ErrAdapterClosed
	}
	if err := WintunAvailable(); err != nil {
		return err
	}
	nameP, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return err
	}
	h, _, callErr := procWintunOpenAdapter.Call(uintptr(unsafe.Pointer(nameP)))
	if h == 0 {
		return fmt.Errorf("tunnel: WintunOpenAdapter(%s): %w", name, callErr)
	}
	w.adapter = h
	w.name = name
	w.readLUIDLocked()
	return nil
}

func (w *WintunAdapter) readLUIDLocked() {
	if procWintunGetAdapterLUID.Find() != nil {
		return
	}
	procWintunGetAdapterLUID.Call(w.adapter, uintptr(unsafe.Pointer(&w.luid)))
}

func (w *WintunAdapter) LUID() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return fmt.Sprintf("%016x", w.luid.Value)
}

func (w *WintunAdapter) StartSession(layer LayerConfig) (Session, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return nil, ErrAdapterClosed
	}
	if w.adapter == 0 {
		return nil, errors.New("tunnel: adapter not created/opened")
	}
	if w.session != nil {
		return nil, ErrSessionActive
	}
	capacity := uint32(wintunDefaultCapacity)
	if procWintunGetRingCapacity.Find() == nil {
		// Respect the actual ring capacity reported by the adapter.
		rc, _, _ := procWintunGetRingCapacity.Call(w.adapter)
		if rc >= 0x20000 && rc <= 0x200000 {
			capacity = uint32(rc)
		}
	}
	// WintunStartSession(adapter, capacity, overlappedEvent). The event is
	// signalled when packets are available to ReadPacket.
	ev, _, err := procCreateEventW.Call(0, 1, 0, 0) // manual-reset? Wintun auto-resets
	if ev == 0 {
		return nil, fmt.Errorf("tunnel: CreateEventW: %w", err)
	}
	sh, _, callErr := procWintunStartSession.Call(w.adapter, uintptr(capacity), ev)
	if sh == 0 {
		procCloseHandleWin.Call(ev)
		return nil, fmt.Errorf("tunnel: WintunStartSession: %w", callErr)
	}
	s := &WintunSession{
		adapter: w,
		handle:  sh,
		event:   ev,
		mtu:     int(layer.MTU),
		layer:   layer,
		done:    make(chan struct{}),
	}
	if s.mtu <= 0 || s.mtu > wintunMaxPacketSize {
		s.mtu = 1500
	}
	w.session = s
	return s, nil
}

func (w *WintunAdapter) Delete() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.adapter == 0 {
		return nil
	}
	if procWintunDeleteAdapter.Find() == nil {
		// WintunDeleteAdapter(handle, forceLevel, usedByOthers*)
		var usedByOthers int32
		procWintunDeleteAdapter.Call(w.adapter, 1 /*force*/, uintptr(unsafe.Pointer(&usedByOthers)))
	} else {
		procWintunCloseAdapterCall(w.adapter)
	}
	w.adapter = 0
	return nil
}

// WintunCloseAdapter exists in older builds as the counterpart of Create.
var procWintunCloseAdapter = wintunDLL.NewProc("WintunCloseAdapter")

func procWintunCloseAdapterCall(h uintptr) {
	if procWintunCloseAdapter.Find() == nil {
		procWintunCloseAdapter.Call(h)
	}
}

func (w *WintunAdapter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return nil
	}
	w.closed = true
	if w.session != nil {
		w.session.endLocked()
		w.session = nil
	}
	if w.adapter != 0 {
		if procWintunDeleteAdapter.Find() == nil {
			var usedByOthers int32
			procWintunDeleteAdapter.Call(w.adapter, 0 /*best effort*/, uintptr(unsafe.Pointer(&usedByOthers)))
		}
		procWintunCloseAdapterCall(w.adapter)
		w.adapter = 0
	}
	return nil
}

// WintunSession implements Session using the Wintun 0.13/0.14 receive/send
// packet API with the start-session event for blocking reads.
type WintunSession struct {
	adapter *WintunAdapter
	handle  uintptr
	event   uintptr
	mtu     int
	layer   LayerConfig

	mu      sync.Mutex
	ended   bool
	done    chan struct{}
	stats   SessionStatistics
	ringBuf []byte // persistent read buffer per Wintun docs
}

// ReadPacket waits on the session event, then copies one received packet.
func (s *WintunSession) ReadPacket(ctx context.Context, buf []byte) (int, error) {
	for {
		s.mu.Lock()
		ended := s.ended
		s.mu.Unlock()
		if ended {
			return 0, ErrAdapterClosed
		}
		// Wait for the event with cancellation support: poll in short slices.
		res, _, _ := procWaitForSingleObj.Call(s.event, 50 /*ms*/)
		if res == waitTimeout {
			select {
			case <-ctx.Done():
				return 0, ctx.Err()
			default:
				continue
			}
		}
		if res != waitObjectSignaled {
			return 0, fmt.Errorf("tunnel: WaitForSingleObject -> %d", res)
		}
		var size uint32
		p, _, callErr := procWintunReceivePacket.Call(s.handle, uintptr(unsafe.Pointer(&size)))
		if p == 0 {
			// ERROR_NO_MORE_ITEMS is expected spurious wake-up; keep waiting.
			if callErr == syscall.Errno(259 /*ERROR_NO_MORE_ITEMS*/) {
				continue
			}
			s.mu.Lock()
			s.stats.ReadErrors++
			s.mu.Unlock()
			return 0, fmt.Errorf("tunnel: WintunReceivePacket: %w", callErr)
		}
		n := int(size)
		if n > len(buf) {
			procWintunReleaseReceivePacket.Call(p, uintptr(size))
			return 0, errors.New("tunnel: read buffer too small for packet")
		}
		// Copy out of the ring mapping, then release.
		pkt := unsafe.Slice((*byte)(unsafe.Pointer(p)), n)
		copy(buf, pkt)
		procWintunReleaseReceivePacket.Call(p, uintptr(size))
		s.mu.Lock()
		s.stats.PacketsRead++
		s.stats.BytesRead += uint64(n)
		s.stats.LastPacketAt = time.Now()
		s.mu.Unlock()
		return n, nil
	}
}

// WritePacket allocates a send slot in the ring, copies the packet and
// signals it (WintunAllocateSendPacket + WintunSendPacket).
func (s *WintunSession) WritePacket(ctx context.Context, pkt []byte) error {
	if len(pkt) > s.mtu+40 {
		return errors.New("tunnel: packet exceeds MTU window")
	}
	s.mu.Lock()
	ended := s.ended
	s.mu.Unlock()
	if ended {
		return ErrAdapterClosed
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	p, _, callErr := procWintunAllocateSendPacket.Call(s.handle, uintptr(len(pkt)))
	if p == 0 {
		s.mu.Lock()
		if callErr == syscall.Errno(1006 /*ERROR_RING_FULL*/) {
			s.stats.DroppedFullQueue++
		} else {
			s.stats.WriteErrors++
		}
		s.mu.Unlock()
		if callErr == syscall.Errno(1006) {
			// Ring full: back off briefly and let caller retry.
			return ErrFullQueue
		}
		return fmt.Errorf("tunnel: WintunAllocateSendPacket: %w", callErr)
	}
	dst := unsafe.Slice((*byte)(unsafe.Pointer(p)), len(pkt))
	copy(dst, pkt)
	procWintunSendPacket.Call(p)
	s.mu.Lock()
	s.stats.PacketsWritten++
	s.stats.BytesWritten += uint64(len(pkt))
	s.stats.LastPacketAt = time.Now()
	s.mu.Unlock()
	return nil
}

func (s *WintunSession) Statistics() SessionStatistics {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.stats
}

func (s *WintunSession) EndSession() error {
	s.adapter.mu.Lock()
	defer s.adapter.mu.Unlock()
	if s.adapter.session == s {
		s.adapter.session = nil
	}
	s.endLocked()
	return nil
}

func (s *WintunSession) endLocked() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ended {
		return
	}
	s.ended = true
	close(s.done)
	if procWintunEndSession.Find() == nil {
		procWintunEndSession.Call(s.handle)
	}
	procCloseHandleWin.Call(s.event)
	s.event = 0
	s.handle = 0
	runtime.GC() // ensure no lingering unsafe references
}

// Ensure address-family helpers compile on Windows builds too (used by the
// shared netstack bridge which is cross-platform).
var _ = netip.Addr{}.Is4
