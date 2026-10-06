package tunnel

import (
"errors"
"context"
"testing"
"time"
)

func TestDbgDialFailure(t *testing.T) {
op := &fakeOpener{failFor: map[string]error{"198.51.100.7:443": errors.New("upstream refused")}}
dp, _ := NewDataPlane(DataPlaneConfig{Opener: op})
defer dp.Close()
l := &memListener{ch: make(chan *memConn, 8), closed: make(chan struct{})}
ctx, cancel := context.WithCancel(context.Background())
defer cancel()
go dp.Serve(ctx, l, dstOfNetstack)
client, acc := newMemPair("198.51.100.7:443")
defer client.Close()
l.ch <- acc
for i := 0; i < 100; i++ {
t.Logf("iter %d flows=%v accepted=%d failed=%d active=%d", i, dp.Flows(), dp.Stats.Load().FlowsAccepted, dp.Stats.Load().FlowsFailed, dp.Stats.Load().ActiveFlows)
if dp.Stats.Load().FlowsFailed >= 1 { return }
time.Sleep(50 * time.Millisecond)
}
}
