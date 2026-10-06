package tunnel

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"
)

func mustCreate(t *testing.T, f *FakeAdapter) {
	t.Helper()
	if err := f.Create(AdapterConfig{TunnelName: "FoxyVPN", TunnelType: "test"}); err != nil {
		t.Fatalf("Create: %v", err)
	}
}

func TestFakeLifecycleReadWriteClose(t *testing.T) {
	f := NewFakeAdapter(FakeAdapterConfig{QueueSize: 4})
	mustCreate(t, f)
	sess, err := f.StartSession(LayerConfig{
		IPv4Address: netip.MustParsePrefix("10.7.7.1/32"),
		MTU:         1500,
	})
	if err != nil {
		t.Fatalf("StartSession: %v", err)
	}
	pkt := []byte{0x45, 0x00, 0x00, 0x14}
	if err := f.InjectInbound(pkt); err != nil {
		t.Fatalf("InjectInbound: %v", err)
	}
	buf := make([]byte, 1500)
	n, err := sess.ReadPacket(context.Background(), buf)
	if err != nil || n != len(pkt) || buf[0] != 0x45 {
		t.Fatalf("ReadPacket: n=%d err=%v", n, err)
	}
	out := []byte{0x45, 0x00, 0x00, 0x28}
	if err := sess.WritePacket(context.Background(), out); err != nil {
		t.Fatalf("WritePacket: %v", err)
	}
	got, ok := f.DrainOutbound(time.Second)
	if !ok || len(got) != len(out) {
		t.Fatalf("DrainOutbound: ok=%v got=%v", ok, got)
	}
	st := sess.Statistics()
	if st.PacketsRead != 1 || st.BytesRead != uint64(len(pkt)) ||
		st.PacketsWritten != 1 || st.BytesWritten != uint64(len(out)) {
		t.Fatalf("stats wrong: %+v", st)
	}
	if st.LastPacketAt.IsZero() {
		t.Fatal("LastPacketAt not set")
	}
	if err := sess.EndSession(); err != nil {
		t.Fatalf("EndSession: %v", err)
	}
	if _, err := sess.ReadPacket(context.Background(), buf); !errors.Is(err, ErrFakeClosed) {
		t.Fatalf("read after end: want ErrFakeClosed, got %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := f.StartSession(LayerConfig{}); !errors.Is(err, ErrFakeClosed) {
		t.Fatalf("session after close: want ErrFakeClosed, got %v", err)
	}
}

func TestFakeDoubleSessionRejected(t *testing.T) {
	f := NewFakeAdapter(FakeAdapterConfig{})
	mustCreate(t, f)
	if _, err := f.StartSession(LayerConfig{}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.StartSession(LayerConfig{}); !errors.Is(err, ErrSessionActive) {
		t.Fatalf("want ErrSessionActive, got %v", err)
	}
}

func TestFakeOpenBeforeCreate(t *testing.T) {
	f := NewFakeAdapter(FakeAdapterConfig{})
	if err := f.Open("FoxyVPN"); err == nil {
		t.Fatal("expected error opening non-existent adapter")
	}
}

func TestFakeCancellation(t *testing.T) {
	f := NewFakeAdapter(FakeAdapterConfig{})
	mustCreate(t, f)
	sess, _ := f.StartSession(LayerConfig{})
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	buf := make([]byte, 1500)
	start := time.Now()
	if _, err := sess.ReadPacket(ctx, buf); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("want deadline, got %v", err)
	}
	if d := time.Since(start); d > time.Second {
		t.Fatalf("read blocked too long: %v", d)
	}
	// Write with Block policy into a drained queue then fill it and cancel.
	big := make([]byte, 100)
	for i := 0; i < cap(f.outbound); i++ {
		if err := sess.WritePacket(context.Background(), big); err != nil {
			t.Fatalf("fill write %d: %v", i, err)
		}
	}
	ctx2, cancel2 := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel2()
	if err := sess.WritePacket(ctx2, big); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("want deadline on full block write, got %v", err)
	}
}

func TestFakeQueueDropPolicy(t *testing.T) {
	f := NewFakeAdapter(FakeAdapterConfig{QueueSize: 2, DropPolicy: Drop})
	mustCreate(t, f)
	sess, _ := f.StartSession(LayerConfig{})
	pkt := []byte{1}
	for i := 0; i < 5; i++ {
		if err := sess.WritePacket(context.Background(), pkt); err != nil {
			t.Fatalf("drop-policy write must not error: %v", err)
		}
	}
	st := sess.Statistics()
	if st.DroppedFullQueue != 3 {
		t.Fatalf("want 3 drops, got %d", st.DroppedFullQueue)
	}
}

func TestFakeQueueNoDropPolicy(t *testing.T) {
	f := NewFakeAdapter(FakeAdapterConfig{QueueSize: 1, DropPolicy: NoDrop})
	mustCreate(t, f)
	sess, _ := f.StartSession(LayerConfig{})
	if err := sess.WritePacket(context.Background(), []byte{1}); err != nil {
		t.Fatal(err)
	}
	if err := sess.WritePacket(context.Background(), []byte{2}); !errors.Is(err, ErrFullQueue) {
		t.Fatalf("want ErrFullQueue, got %v", err)
	}
}

func TestFakeInboundOverflowCountsDrop(t *testing.T) {
	f := NewFakeAdapter(FakeAdapterConfig{QueueSize: 1})
	mustCreate(t, f)
	if err := f.InjectInbound([]byte{1}); err != nil {
		t.Fatal(err)
	}
	if err := f.InjectInbound([]byte{2}); !errors.Is(err, ErrFullQueue) {
		t.Fatalf("want ErrFullQueue, got %v", err)
	}
	if f.StatsSnapshot().DroppedFullQueue != 1 {
		t.Fatal("drop not counted")
	}
}

func TestFakeFailureInjection(t *testing.T) {
	readErr := errors.New("wintun read boom")
	writeErr := errors.New("wintun write boom")
	f := NewFakeAdapter(FakeAdapterConfig{ReadError: readErr, WriteError: writeErr})
	mustCreate(t, f)
	sess, _ := f.StartSession(LayerConfig{})
	if _, err := sess.ReadPacket(context.Background(), make([]byte, 10)); !errors.Is(err, readErr) {
		t.Fatalf("want injected read error, got %v", err)
	}
	if err := sess.WritePacket(context.Background(), []byte{9}); !errors.Is(err, writeErr) {
		t.Fatalf("want injected write error, got %v", err)
	}
	st := sess.Statistics()
	if st.ReadErrors != 1 || st.WriteErrors != 1 {
		t.Fatalf("error counters: %+v", st)
	}
}

func TestFakeAdapterCloseUnblocksReader(t *testing.T) {
	f := NewFakeAdapter(FakeAdapterConfig{})
	mustCreate(t, f)
	sess, _ := f.StartSession(LayerConfig{})
	done := make(chan error, 1)
	go func() {
		_, err := sess.ReadPacket(context.Background(), make([]byte, 100))
		done <- err
	}()
	time.Sleep(20 * time.Millisecond)
	f.Close()
	select {
	case err := <-done:
		if !errors.Is(err, ErrFakeClosed) {
			t.Fatalf("want ErrFakeClosed, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("reader not unblocked by Close")
	}
}
