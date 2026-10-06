package tunnel

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// TunnelOpener is the single upstream primitive the data plane needs:
// open a byte-stream tunnel to "host:port" through the VPN engine.
// core/engine.StartUpstream returns exactly this interface, so the Windows
// layer never sees FxA/Guardian/Fastly/HTTP2 internals.
type TunnelOpener interface {
	OpenTunnel(authority string) (net.Conn, error)
	Close() error
}

// FlowState enumerates the explicit TCP flow lifetime (Phase J).
type FlowState int

const (
	StateNew FlowState = iota
	StateAccepted
	StateDialingVPN
	StateUpstreamConnected
	StateForwarding
	StateHalfClosedLocal
	StateHalfClosedRemote
	StateClosing
	StateClosed
	StateFailed
)

func (s FlowState) String() string {
	switch s {
	case StateNew:
		return "New"
	case StateAccepted:
		return "Accepted"
	case StateDialingVPN:
		return "DialingVPN"
	case StateUpstreamConnected:
		return "UpstreamConnected"
	case StateForwarding:
		return "Forwarding"
	case StateHalfClosedLocal:
		return "HalfClosedLocal"
	case StateHalfClosedRemote:
		return "HalfClosedRemote"
	case StateClosing:
		return "Closing"
	case StateClosed:
		return "Closed"
	case StateFailed:
		return "Failed"
	}
	return "Unknown"
}

// FlowInfo describes one accepted TCP flow for diagnostics/statistics.
type FlowInfo struct {
	ID           uint64
	Destination  string // "host:port" extracted from the netstack endpoint
	CreatedAt    time.Time
	LastActivity time.Time
	BytesToUp    uint64 // client -> destination
	BytesToDown  uint64 // destination -> client
	State        FlowState
	Err          string
}

// DataPlaneConfig configures the transparent TCP forwarding layer.
type DataPlaneConfig struct {
	Opener         TunnelOpener
	DialTimeout    time.Duration // default 15s
	IdleTimeout    time.Duration // default 10m; 0 disables
	MaxActiveFlows int           // default 512; <=0 uses default
}

// DataPlane manages the lifecycle of every proxied TCP flow. It is
// transport-agnostic: on Windows the Listener feeds it netstack-accepted
// conns (with original destinations), and Linux tests feed it in-memory
// net.Pipe conns.
type DataPlane struct {
	cfg    DataPlaneConfig
	mu     sync.Mutex
	flows  map[uint64]*flow
	nextID atomic.Uint64
	closed atomic.Bool
	wg     sync.WaitGroup
	Stats  atomic.Pointer[DataPlaneStats]
}

// DataPlaneStats aggregates flow counters.
type DataPlaneStats struct {
	FlowsAccepted  uint64
	FlowsFailed    uint64
	FlowsCompleted uint64
	BytesUp        uint64
	BytesDown      uint64
	ActiveFlows    int64
}

// NewDataPlane validates cfg and returns a ready data plane.
func NewDataPlane(cfg DataPlaneConfig) (*DataPlane, error) {
	if cfg.Opener == nil {
		return nil, errors.New("tunnel: DataPlaneConfig.Opener is required")
	}
	if cfg.DialTimeout <= 0 {
		cfg.DialTimeout = 15 * time.Second
	}
	if cfg.IdleTimeout < 0 {
		return nil, errors.New("tunnel: IdleTimeout must not be negative")
	}
	if cfg.IdleTimeout == 0 {
		cfg.IdleTimeout = 10 * time.Minute
	}
	if cfg.MaxActiveFlows <= 0 {
		cfg.MaxActiveFlows = 512
	}
	dp := &DataPlane{cfg: cfg, flows: map[uint64]*flow{}, Stats: atomic.Pointer[DataPlaneStats]{}}
	dp.Stats.Store(&DataPlaneStats{})
	return dp, nil
}

// Serve accepts flows from listener until ctx is cancelled or Close is called.
// dstOf extracts the ORIGINAL destination ("host:port") the Windows app
// intended to reach (Phase I). On Windows this reads the netstack endpoint's
// LocalAddress; tests can pass any function.
func (dp *DataPlane) Serve(ctx context.Context, listener net.Listener, dstOf func(net.Conn) (string, error)) error {
	if dstOf == nil {
		return errors.New("tunnel: dstOf is required")
	}
	go func() {
		<-ctx.Done()
		_ = dp.Close()
	}()
	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil || dp.closed.Load() {
				return nil
			}
			return err
		}
		if err := dp.AcceptFlow(conn, dstOf); err != nil {
			conn.Close()
		}
	}
}

// AcceptFlow starts one proxied flow over conn.
func (dp *DataPlane) AcceptFlow(conn net.Conn, dstOf func(net.Conn) (string, error)) error {
	if dp.closed.Load() {
		return errors.New("tunnel: data plane closed")
	}
	dest, err := dstOf(conn)
	if err != nil {
		return fmt.Errorf("tunnel: destination extraction failed: %w", err)
	}
	host, portStr, err := net.SplitHostPort(dest)
	if err != nil {
		return fmt.Errorf("tunnel: invalid destination %q: %w", dest, err)
	}
	if host == "" || portStr == "" {
		return fmt.Errorf("tunnel: empty destination component in %q", dest)
	}
	dp.mu.Lock()
	active := len(dp.flows)
	dp.mu.Unlock()
	if active >= dp.cfg.MaxActiveFlows {
		return errors.New("tunnel: too many active flows")
	}
	f := &flow{
		id:   dp.nextID.Add(1),
		dp:   dp,
		dest: dest,
		conn: conn,
		done: make(chan struct{}),
	}
	f.info.Store(&FlowInfo{ID: f.id, Destination: dest, CreatedAt: time.Now(), LastActivity: time.Now(), State: StateAccepted})
	dp.mu.Lock()
	dp.flows[f.id] = f
	dp.mu.Unlock()
	st := dp.Stats.Load()
	atomic.AddUint64(&st.FlowsAccepted, 1)
	atomic.AddInt64(&st.ActiveFlows, 1)
	dp.startFlow(f)
	return nil
}

// record initial state and start the flow goroutine.
func (dp *DataPlane) startFlow(f *flow) { f.start() }

func (f *flow) start() {
	f.dp.wg.Add(1)
	go f.run()
}

type flow struct {
	id       uint64
	dp       *DataPlane
	dest     string
	conn     net.Conn
	up       net.Conn
	info     atomic.Pointer[FlowInfo]
	done     chan struct{}
	closeOne sync.Once
}

func (f *flow) setState(s FlowState, reason error) {
	for {
		old := f.info.Load()
		ni := *old
		ni.State = s
		ni.LastActivity = time.Now()
		if reason != nil {
			ni.Err = reason.Error()
		}
		if f.info.CompareAndSwap(old, &ni) {
			return
		}
	}
}

func (f *flow) run() {
	defer f.dp.wg.Done()
	defer f.finish()

	f.setState(StateDialingVPN, nil)
	type res struct {
		c   net.Conn
		err error
	}
	ch := make(chan res, 1)
	go func() {
		c, err := f.dp.cfg.Opener.OpenTunnel(f.dest)
		ch <- res{c, err}
	}()
	var up net.Conn
	select {
	case r := <-ch:
		if r.err != nil {
			f.setState(StateFailed, r.err)
			return
		}
		up = r.c
	case <-time.After(f.dp.cfg.DialTimeout):
		f.setState(StateFailed, errors.New("dial timeout"))
		return
	}
	f.up = up
	f.setState(StateUpstreamConnected, nil)
	f.setState(StateForwarding, nil)

	var once sync.Once
	fail := func(err error) { once.Do(func() { f.setState(StateFailed, err) }) }

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		if err := f.copy(f.conn, up, true); err != nil && !errors.Is(err, io.EOF) {
			fail(err)
		}
	}()
	go func() {
		defer wg.Done()
		if err := f.copy(up, f.conn, false); err != nil && !errors.Is(err, io.EOF) {
			fail(err)
		}
	}()
	wg.Wait()
}

// copy streams bytes with idle-timeout enforcement and half-close handling.
func (f *flow) copy(src, dst net.Conn, toUp bool) error {
	buf := make([]byte, 32*1024)
	idle := f.dp.cfg.IdleTimeout
	type nerr struct {
		n   int
		err error
	}
	for {
		ch := make(chan nerr, 1)
		go func() {
			n, err := src.Read(buf)
			ch <- nerr{n, err}
		}()
		var r nerr
		if idle > 0 {
			t := time.NewTimer(idle)
			select {
			case r = <-ch:
				t.Stop()
			case <-t.C:
				src.Close() // unblock the pending read
				r = <-ch
				r.err = fmt.Errorf("idle timeout after %s", idle)
			}
		} else {
			r = <-ch
		}
		if r.n > 0 {
			if _, werr := dst.Write(buf[:r.n]); werr != nil {
				return werr
			}
			f.recordActivity(toUp, uint64(r.n))
		}
		if r.err != nil {
			if errors.Is(r.err, io.EOF) {
				// Half-close: signal EOF toward the other direction.
				if hc, ok := dst.(interface{ CloseWrite() error }); ok {
					_ = hc.CloseWrite()
					if toUp {
						f.setState(StateHalfClosedLocal, nil)
					} else {
						f.setState(StateHalfClosedRemote, nil)
					}
				}
			}
			return r.err
		}
	}
}

func (f *flow) recordActivity(toUp bool, n uint64) {
	st := f.dp.Stats.Load()
	if toUp {
		atomic.AddUint64(&st.BytesUp, n)
		inc := f.info.Load().BytesToUp + n
		f.mutate(func(i *FlowInfo) { i.BytesToUp = inc })
	} else {
		atomic.AddUint64(&st.BytesDown, n)
		inc := f.info.Load().BytesToDown + n
		f.mutate(func(i *FlowInfo) { i.BytesToDown = inc })
	}
}

func (f *flow) mutate(fn func(*FlowInfo)) {
	for {
		old := f.info.Load()
		ni := *old
		fn(&ni)
		ni.LastActivity = time.Now()
		if f.info.CompareAndSwap(old, &ni) {
			return
		}
	}
}

func (f *flow) finish() {
	f.closeOne.Do(func() {
		f.setState(StateClosing, nil)
		if f.up != nil {
			f.up.Close()
		}
		f.conn.Close()
		f.dp.mu.Lock()
		delete(f.dp.flows, f.id)
		f.dp.mu.Unlock()
		st := f.dp.Stats.Load()
		atomic.AddInt64(&st.ActiveFlows, -1)
		cur := f.info.Load()
		if cur.State == StateFailed {
			atomic.AddUint64(&st.FlowsFailed, 1)
		} else {
			atomic.AddUint64(&st.FlowsCompleted, 1)
			f.setState(StateClosed, nil)
		}
	})
}

// Flows snapshots current flow table for diagnostics.
func (dp *DataPlane) Flows() []FlowInfo {
	dp.mu.Lock()
	defer dp.mu.Unlock()
	out := make([]FlowInfo, 0, len(dp.flows))
	for _, f := range dp.flows {
		out = append(out, *f.info.Load())
	}
	return out
}

// StopNewFlows prevents new accepts but lets running flows finish.
func (dp *DataPlane) StopNewFlows() { dp.closed.Store(true) }

// Close stops accepting, cancels all flows, and waits for cleanup.
func (dp *DataPlane) Close() error {
	dp.StopNewFlows()
	dp.mu.Lock()
	fs := make([]*flow, 0, len(dp.flows))
	for _, f := range dp.flows {
		fs = append(fs, f)
	}
	dp.mu.Unlock()
	for _, f := range fs {
		if f.up != nil {
			f.up.Close()
		}
		f.conn.Close()
	}
	dp.wg.Wait()
	return nil
}
