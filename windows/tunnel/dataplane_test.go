package tunnel

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"
)

// fakeOpener echoes back everything written to the tunnel, optionally with a
// per-authority failure. It records every authority requested.
type fakeOpener struct {
	mu        sync.Mutex
	authories []string
	failFor   map[string]error
	closed    bool
}

func (o *fakeOpener) OpenTunnel(authority string) (net.Conn, error) {
	o.mu.Lock()
	o.authories = append(o.authories, authority)
	fail := o.failFor[authority]
	o.mu.Unlock()
	if fail != nil {
		return nil, fail
	}
	client, server := net.Pipe()
	go func() {
		defer server.Close()
		io.Copy(server, server) // echo until closed
	}()
	return client, nil
}

func (o *fakeOpener) Close() error {
	o.mu.Lock()
	o.closed = true
	o.mu.Unlock()
	return nil
}

func (o *fakeOpener) requested() []string {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]string(nil), o.authories...)
}

// memConn is an in-memory duplex conn whose LocalAddress reports the ORIGINAL
// destination the Windows app intended to reach — exactly what a netstack
// accepted endpoint provides on Windows (Phase I).
type memConn struct {
	mu       sync.Mutex
	peer     *memConn
	dstHint  string
	local    net.Addr
	remote   net.Addr
	buf      bytes.Buffer
	sig      chan struct{}
	openr    bool
	openw    bool
	closed   bool
	readDead time.Time
}

func newMemPair(localDst string) (client, accepted *memConn) {
	a := &memConn{local: &net.TCPAddr{IP: net.ParseIP("192.0.2.50"), Port: 5000}, remote: &net.TCPAddr{}, openr: true, openw: true, sig: make(chan struct{}, 4)}
	b := &memConn{local: &net.TCPAddr{IP: net.ParseIP("10.7.7.1")}, remote: &net.TCPAddr{IP: net.ParseIP("192.0.2.50"), Port: 5000}, openr: true, openw: true, sig: make(chan struct{}, 4)}
	a.peer, b.peer = b, a
	b.dstHint = localDst
	return a, b
}

func (c *memConn) Read(p []byte) (int, error) {
	for {
		c.mu.Lock()
		if c.buf.Len() > 0 {
			n, _ := c.buf.Read(p)
			c.mu.Unlock()
			return n, nil
		}
		if c.closed || !c.openr {
			c.mu.Unlock()
			return 0, io.EOF
		}
		c.mu.Unlock()
		select {
		case <-c.sig:
		case <-time.After(50 * time.Millisecond):
		}
	}
}

func (c *memConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	if c.closed || !c.openw || c.peer == nil {
		c.mu.Unlock()
		return 0, net.ErrClosed
	}
	peer := c.peer
	c.mu.Unlock()
	peer.mu.Lock()
	peer.buf.Write(p)
	peer.mu.Unlock()
	select {
	case peer.sig <- struct{}{}:
	default:
	}
	return len(p), nil
}

func (c *memConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.closed {
		c.closed = true
		c.openr, c.openw = false, false
		if c.peer != nil {
			select {
			case c.peer.sig <- struct{}{}:
			default:
			}
		}
	}
	return nil
}

func (c *memConn) LocalAddr() net.Addr {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.dstHint != "" {
		host, port, err := net.SplitHostPort(c.dstHint)
		if err == nil {
			p, _ := strconv.Atoi(port)
			return &net.TCPAddr{IP: net.ParseIP(host), Port: p}
		}
	}
	return c.local
}
func (c *memConn) RemoteAddr() net.Addr {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.remote
}
func (c *memConn) SetDeadline(t time.Time) error {
	c.mu.Lock()
	c.readDead = t
	c.mu.Unlock()
	return nil
}
func (c *memConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	c.readDead = t
	c.mu.Unlock()
	return nil
}
func (c *memConn) SetWriteDeadline(t time.Time) error { return nil }

var _ net.Conn = (*memConn)(nil)

// memListener feeds accepted memConns (stands in for the netstack listener).
type memListener struct {
	ch     chan *memConn
	closed chan struct{}
	once   sync.Once
}

func (l *memListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.ch:
		return c, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}
func (l *memListener) Close() error { l.once.Do(func() { close(l.closed) }); return nil }
func (l *memListener) Addr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(10, 7, 7, 1)}
}

// dstOfNetstack extracts host:port from the accepted conn's LOCAL address —
// the same rule the Windows netstack integration uses.
func dstOfNetstack(c net.Conn) (string, error) {
	tcpAddr, ok := c.LocalAddr().(*net.TCPAddr)
	if !ok || tcpAddr.IP == nil {
		return "", errors.New("tunnel: not a TCP local address")
	}
	return net.JoinHostPort(tcpAddr.IP.String(), strconv.Itoa(tcpAddr.Port)), nil
}

func TestDestinationExtraction(t *testing.T) {
	_, acc := newMemPair("192.0.2.10:443")
	dest, err := dstOfNetstack(acc)
	if err != nil || dest != "192.0.2.10:443" {
		t.Fatalf("dest=%q err=%v", dest, err)
	}
	host, port, err := net.SplitHostPort(dest)
	if err != nil || host != "192.0.2.10" || port != "443" {
		t.Fatalf("host=%q port=%q err=%v", host, port, err)
	}
}

func startDP(t *testing.T, op TunnelOpener, cfg DataPlaneConfig) (*DataPlane, *memListener, func()) {
	t.Helper()
	cfg.Opener = op
	dp, err := NewDataPlane(cfg)
	if err != nil {
		t.Fatal(err)
	}
	l := &memListener{ch: make(chan *memConn, 8), closed: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	go dp.Serve(ctx, l, dstOfNetstack)
	return dp, l, func() { cancel(); _ = dp.Close(); l.Close() }
}

func TestDataPlaneBidirectionalEcho(t *testing.T) {
	op := &fakeOpener{}
	dp, l, cleanup := startDP(t, op, DataPlaneConfig{DialTimeout: time.Second})
	defer cleanup()
	client, acc := newMemPair("203.0.113.5:80")
	l.ch <- acc
	payload := bytes.Repeat([]byte("foxy"), 1000)
	go client.Write(payload)
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(client, got); err != nil {
		t.Fatalf("read echoed data: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("echo mismatch")
	}
	if req := op.requested(); len(req) != 1 || req[0] != "203.0.113.5:80" {
		t.Fatalf("opener saw %v", req)
	}
	st := dp.Stats.Load()
	if st.BytesUp < uint64(len(payload)) || st.BytesDown < uint64(len(payload)) {
		t.Fatalf("stats up=%d down=%d", st.BytesUp, st.BytesDown)
	}
}

func TestDataPlaneDialFailureMarksFlowFailed(t *testing.T) {
	op := &fakeOpener{failFor: map[string]error{"198.51.100.7:443": errors.New("upstream refused")}}
	dp, l, cleanup := startDP(t, op, DataPlaneConfig{})
	defer cleanup()
	client, acc := newMemPair("198.51.100.7:443")
	defer client.Close()
	l.ch <- acc
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if dp.Stats.Load().FlowsFailed >= 1 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("flow was never marked failed")
}

type hangingOpener struct{}

func (hangingOpener) OpenTunnel(string) (net.Conn, error) { select {} }
func (hangingOpener) Close() error                        { return nil }

func TestDataPlaneDialTimeout(t *testing.T) {
	dp, l, cleanup := startDP(t, hangingOpener{}, DataPlaneConfig{DialTimeout: 100 * time.Millisecond})
	defer cleanup()
	client, acc := newMemPair("192.0.2.25:443")
	defer client.Close()
	l.ch <- acc
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if dp.Stats.Load().FlowsFailed >= 1 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("dial timeout not enforced")
}

func TestDataPlaneMaxFlows(t *testing.T) {
	op := &fakeOpener{}
	dp, l, cleanup := startDP(t, op, DataPlaneConfig{MaxActiveFlows: 1})
	defer cleanup()
	c1, a1 := newMemPair("192.0.2.1:1")
	defer c1.Close()
	l.ch <- a1
	deadline := time.Now().Add(2 * time.Second)
	for len(dp.Flows()) == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	c2, a2 := newMemPair("192.0.2.2:2")
	defer c2.Close()
	l.ch <- a2
	time.Sleep(300 * time.Millisecond)
	if n := len(dp.Flows()); n > 1 {
		t.Fatalf("expected at most 1 active flow, got %d", n)
	}
}

func TestDataPlaneCloseCleansUp(t *testing.T) {
	op := &fakeOpener{}
	dp, l, cancelSrv := startDP(t, op, DataPlaneConfig{})
	defer cancelSrv()
	client, acc := newMemPair("192.0.2.9:9")
	defer client.Close()
	l.ch <- acc
	deadline := time.Now().Add(2 * time.Second)
	for len(dp.Flows()) == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	done := make(chan struct{})
	go func() { dp.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not finish flows")
	}
	if len(dp.Flows()) != 0 {
		t.Fatalf("flows left: %v", dp.Flows())
	}
	if got := dp.Stats.Load().ActiveFlows; got != 0 {
		t.Fatalf("ActiveFlows=%d", got)
	}
}

func TestFlowStateString(t *testing.T) {
	want := []string{"New", "Accepted", "DialingVPN", "UpstreamConnected", "Forwarding",
		"HalfClosedLocal", "HalfClosedRemote", "Closing", "Closed", "Failed"}
	for i, w := range want {
		if got := FlowState(int(StateNew) + i).String(); got != w {
			t.Errorf("state %d = %q want %q", i, got, w)
		}
	}
}

func TestAcceptFlowRejectsBadDestination(t *testing.T) {
	dp, _ := NewDataPlane(DataPlaneConfig{Opener: &fakeOpener{}})
	defer dp.Close()
	bad := func(net.Conn) (string, error) { return "not-an-address", nil }
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	if err := dp.AcceptFlow(c1, bad); err == nil {
		t.Fatal("expected error for invalid destination")
	}
}
