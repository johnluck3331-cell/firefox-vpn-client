// Package tunnel implements the FoxyVPN Windows data plane:
//
//	Windows IP packets -> Wintun -> userspace TCP/IP stack (gVisor netstack)
//	-> TCP flow termination -> engine.OpenTunnel(dest) -> Firefox VPN
//
// The Adapter interface abstracts the packet device so real Wintun sessions
// (Windows-only, wintun_windows.go) and in-memory fakes (Linux tests) share
// one code path.
package tunnel

import (
	"context"
	"errors"
	"net/netip"
	"time"
)

// ErrAdapterClosed is returned by all operations after Close.
var ErrAdapterClosed = errors.New("tunnel: adapter closed")

// ErrSessionActive means StartSession was called while a session is running.
var ErrSessionActive = errors.New("tunnel: session already active")

// SessionStatistics reports cumulative counters for one adapter session.
type SessionStatistics struct {
	PacketsRead      uint64
	PacketsWritten   uint64
	BytesRead        uint64
	BytesWritten     uint64
	ReadErrors       uint64
	WriteErrors      uint64
	DroppedFullQueue uint64
	LastPacketAt     time.Time
}

// AdapterConfig describes how to create/open a tunnel adapter.
type AdapterConfig struct {
	TunnelName string // e.g. "FoxyVPN"
	TunnelType string // e.g. "FoxyVPN Data Plane"
	MediaName  string // Windows media name hint (informational)
}

// LayerConfig assigns addresses/routes to the virtual adapter.
type LayerConfig struct {
	IPv4Address netip.Prefix // e.g. 10.7.7.1/32 — Wintun expects /32
	Gateway     netip.Addr   // typically the same as IPv4Address for /32
	MTU         uint16
	DNSServers  []netip.Addr
	IPv6Address *netip.Prefix // optional; nil = IPv6 disabled on adapter
}

// Session is an active Wintun-style packet session. Exactly one reader and
// one writer goroutine may use a session concurrently (Wintun semantics).
type Session interface {
	// ReadPacket blocks until an IP packet is available, the context is
	// cancelled, or the session/adapter is closed. Returns the number of
	// bytes written into buf (buf must be >= MTU capacity).
	ReadPacket(ctx context.Context, buf []byte) (int, error)
	// WritePacket enqueues an outbound IP packet toward Windows.
	WritePacket(ctx context.Context, pkt []byte) error
	// Statistics returns a snapshot of cumulative counters.
	Statistics() SessionStatistics
	// EndSession stops the session; subsequent reads/writes fail.
	EndSession() error
}

// Adapter is the versioned abstraction over Wintun (real) and fakes (tests):
//
//	Load DLL → resolve APIs → Open/Create adapter → StartSession →
//	Read/Write packets → EndSession → Close
type Adapter interface {
	// Create makes a new adapter (or reopens an existing one with the same
	// name, matching WintunCreateAdapter semantics) and returns it ready
	// for StartSession.
	Create(cfg AdapterConfig) error
	// Open attaches to an already-existing adapter by name.
	Open(name string) error
	// LUID returns the adapter's locally unique identifier once created.
	LUID() string
	// StartSession begins a packet session with the given layer config.
	StartSession(layer LayerConfig) (Session, error)
	// Delete removes the adapter from the system (best effort on close).
	Delete() error
	// Close releases all resources.
	Close() error
}
