package tunnel

import (
	"context"
	"errors"
	"sync"
	"time"
)

// ErrFakeClosed reports operations against a closed fake adapter/session.
var ErrFakeClosed = errors.New("tunnel: fake closed")

// ErrFullQueue is returned by WritePacket when the configured capacity is
// exhausted and DropPolicy is NoDrop (otherwise packets are dropped and
// counted in DroppedFullQueue).
var ErrFullQueue = errors.New("tunnel: packet queue full")

// DropPolicy governs bounded-queue behaviour under backpressure.
type DropPolicy int

const (
	// Block waits for space (honouring ctx cancellation).
	Block DropPolicy = iota
	// Drop counts and discards new packets when full.
	Drop
	// NoDrop surfaces ErrFullQueue to the writer.
	NoDrop
)

// FakeAdapterConfig tunes the in-memory adapter used by Linux tests and the
// dataplane self-test harness.
type FakeAdapterConfig struct {
	AdapterConfig
	QueueSize  int        // bounded inbound/outbound queues (default 256)
	MTU        uint16     // default 1500
	DropPolicy DropPolicy // default Block
	ReadError  error      // if set, ReadPacket fails with it after injection
	WriteError error      // if set, WritePacket fails with it
}

// FakeAdapter is an in-memory Adapter satisfying the same lifecycle as real
// Wintun: Create/Open → StartSession → Read/Write → EndSession → Close.
// Inbound packets arrive via InjectInbound; outbound packets observed via
// DrainOutbound.
type FakeAdapter struct {
	mu       sync.Mutex
	cfg      FakeAdapterConfig
	luid     string
	created  bool
	closed   bool
	inbound  chan []byte
	outbound chan []byte
	sess     *FakeSession
	stats    SessionStatistics
	now      func() time.Time
}

// NewFakeAdapter builds a fake with sane defaults.
func NewFakeAdapter(cfg FakeAdapterConfig) *FakeAdapter {
	if cfg.QueueSize <= 0 {
		cfg.QueueSize = 256
	}
	if cfg.MTU == 0 {
		cfg.MTU = 1500
	}
	return &FakeAdapter{
		cfg:      cfg,
		inbound:  make(chan []byte, cfg.QueueSize),
		outbound: make(chan []byte, cfg.QueueSize),
		now:      time.Now,
	}
}

func (f *FakeAdapter) Create(cfg AdapterConfig) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return ErrFakeClosed
	}
	if f.created {
		return ErrSessionActive // mirrors "adapter exists"
	}
	f.cfg.AdapterConfig = cfg
	f.created = true
	f.luid = "fake-luid-" + cfg.TunnelName
	return nil
}

func (f *FakeAdapter) Open(name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return ErrFakeClosed
	}
	if !f.created {
		return errors.New("tunnel: fake adapter does not exist: " + name)
	}
	return nil
}

func (f *FakeAdapter) LUID() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.luid
}

func (f *FakeAdapter) StartSession(layer LayerConfig) (Session, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return nil, ErrFakeClosed
	}
	if !f.created {
		return nil, errors.New("tunnel: adapter not created")
	}
	if f.sess != nil {
		return nil, ErrSessionActive
	}
	s := &FakeSession{f: f, layer: layer, ended: make(chan struct{})}
	f.sess = s
	return s, nil
}

func (f *FakeAdapter) Delete() error { return f.Close() }

func (f *FakeAdapter) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return nil
	}
	f.closed = true
	if f.sess != nil {
		close(f.sess.ended)
		f.sess = nil
	}
	return nil
}

// InjectInbound queues an IP packet for the session's ReadPacket side —
// equivalent to Windows sending traffic into the Wintun adapter.
func (f *FakeAdapter) InjectInbound(pkt []byte) error {
	f.mu.Lock()
	closed := f.closed
	f.mu.Unlock()
	if closed {
		return ErrFakeClosed
	}
	cp := append([]byte(nil), pkt...)
	select {
	case f.inbound <- cp:
		return nil
	default:
		f.mu.Lock()
		f.stats.DroppedFullQueue++
		f.mu.Unlock()
		return ErrFullQueue
	}
}

// DrainOutbound returns one packet written toward Windows, blocking up to
// the timeout. Used by tests to observe stack-generated traffic.
func (f *FakeAdapter) DrainOutbound(timeout time.Duration) ([]byte, bool) {
	select {
	case p := <-f.outbound:
		return p, true
	case <-time.After(timeout):
		return nil, false
	}
}

// StatsSnapshot exposes cumulative counters.
func (f *FakeAdapter) StatsSnapshot() SessionStatistics {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.stats
}

// FakeSession implements Session over the FakeAdapter channels.
type FakeSession struct {
	f         *FakeAdapter
	layer     LayerConfig
	ended     chan struct{}
	mu        sync.Mutex
	endedOnce bool
}

func (s *FakeSession) ReadPacket(ctx context.Context, buf []byte) (int, error) {
	select {
	case <-s.ended:
		return 0, ErrFakeClosed
	case <-ctx.Done():
		return 0, ctx.Err()
	default:
	}
	s.f.mu.Lock()
	rerr := s.f.cfg.ReadError
	s.f.mu.Unlock()
	if rerr != nil {
		s.f.mu.Lock()
		s.f.stats.ReadErrors++
		s.f.mu.Unlock()
		return 0, rerr
	}
	select {
	case pkt := <-s.f.inbound:
		if len(pkt) > len(buf) {
			return 0, errors.New("tunnel: read buffer too small")
		}
		n := copy(buf, pkt)
		s.f.mu.Lock()
		s.f.stats.PacketsRead++
		s.f.stats.BytesRead += uint64(n)
		s.f.stats.LastPacketAt = s.f.now()
		s.f.mu.Unlock()
		return n, nil
	case <-s.ended:
		return 0, ErrFakeClosed
	case <-ctx.Done():
		return 0, ctx.Err()
	}
}

func (s *FakeSession) WritePacket(ctx context.Context, pkt []byte) error {
	select {
	case <-s.ended:
		return ErrFakeClosed
	default:
	}
	s.f.mu.Lock()
	werr := s.f.cfg.WriteError
	policy := s.f.cfg.DropPolicy
	closed := s.f.closed
	s.f.mu.Unlock()
	if closed {
		return ErrFakeClosed
	}
	if werr != nil {
		s.f.mu.Lock()
		s.f.stats.WriteErrors++
		s.f.mu.Unlock()
		return werr
	}
	cp := append([]byte(nil), pkt...)
	switch policy {
	case Drop:
		select {
		case s.f.outbound <- cp:
		default:
			s.f.mu.Lock()
			s.f.stats.DroppedFullQueue++
			s.f.mu.Unlock()
			return nil
		}
	case NoDrop:
		select {
		case s.f.outbound <- cp:
		default:
			return ErrFullQueue
		}
	default: // Block
		select {
		case s.f.outbound <- cp:
		case <-s.ended:
			return ErrFakeClosed
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	s.f.mu.Lock()
	s.f.stats.PacketsWritten++
	s.f.stats.BytesWritten += uint64(len(pkt))
	s.f.stats.LastPacketAt = s.f.now()
	s.f.mu.Unlock()
	return nil
}

func (s *FakeSession) Statistics() SessionStatistics {
	s.f.mu.Lock()
	defer s.f.mu.Unlock()
	return s.f.stats
}

func (s *FakeSession) EndSession() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.endedOnce {
		return nil
	}
	s.endedOnce = true
	close(s.ended)
	s.f.mu.Lock()
	if s.f.sess == s {
		s.f.sess = nil
	}
	s.f.mu.Unlock()
	return nil
}

var (
	_ Adapter = (*FakeAdapter)(nil)
	_ Session = (*FakeSession)(nil)
)
