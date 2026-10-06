package ipc

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// newTestServerClient pairs a Server with a Client over net.Pipe so the
// full protocol can be exercised on Linux without Windows named pipes.
func newTestServerClient(t *testing.T, handlers map[string]Handler) (*Client, context.CancelFunc) {
	t.Helper()
	srv := NewServer(handlers)
	ctx, cancel := context.WithCancel(context.Background())
	cConn, sConn := net.Pipe()
	go func() { _ = srv.ServeConn(ctx, sConn, sConn) }()
	client := NewClient(cConn)
	t.Cleanup(func() {
		client.Close()
		cancel()
		sConn.Close()
	})
	return client, cancel
}

func TestRoundTripStatus(t *testing.T) {
	want := StatusPayload{State: "Connected", LoggedIn: true, PublicIP: "1.2.3.4", Transport: "http2"}
	handlers := map[string]Handler{
		CmdGetStatus: func(ctx context.Context, r *Request) *Response {
			b, _ := json.Marshal(want)
			return &Response{OK: true, Payload: b}
		},
	}
	client, _ := newTestServerClient(t, handlers)
	var got StatusPayload
	err := client.CallInto(context.Background(), CmdGetStatus, nil, &got, 0)
	if err != nil {
		t.Fatalf("CallInto: %v", err)
	}
	if got.State != want.State || got.PublicIP != want.PublicIP || got.Transport != "http2" {
		t.Fatalf("payload mismatch: %+v", got)
	}
}

func TestCommandValidationRejectsUnknown(t *testing.T) {
	client, _ := newTestServerClient(t, map[string]Handler{})
	// Manually craft an invalid command frame bypassing Call's marshalling.
	cConn := client.rwc
	w := bufio.NewWriter(cConn)
	w.WriteString(`{"version":1,"request_id":"x","command":"FormatC:"}` + "\n")
	w.Flush()
	resp, err := DecodeResponse(bufio.NewReader(cConn))
	if err != nil {
		t.Fatal(err)
	}
	if resp.OK || resp.ErrorCode != ErrCodeProtocol {
		t.Fatalf("expected PROTOCOL_ERROR rejection, got %+v", resp)
	}
}

func TestVersionMismatchRejected(t *testing.T) {
	rd := bufio.NewReader(strings.NewReader(`{"version":99,"request_id":"a","command":"GetStatus"}` + "\n"))
	_, err := DecodeRequest(rd)
	if !errors.Is(err, ErrVersionMismatch) {
		t.Fatalf("want ErrVersionMismatch, got %v", err)
	}
}

func TestMalformedJSONRejected(t *testing.T) {
	rd := bufio.NewReader(strings.NewReader(`{not json` + "\n"))
	_, err := DecodeRequest(rd)
	if err == nil || !strings.Contains(err.Error(), "malformed") {
		t.Fatalf("want malformed error, got %v", err)
	}
}

func TestMessageTooLargeRejected(t *testing.T) {
	// Writer side: a valid-JSON payload that pushes the frame past the limit.
	inner := strings.Repeat("A", MaxMessageBytes)
	bigPayload, _ := json.Marshal(map[string]string{"blob": inner})
	resp := Response{RequestID: "z", OK: true, Payload: bigPayload}
	var buf bytes.Buffer
	err := WriteResponse(&buf, &resp)
	if !errors.Is(err, ErrMessageTooLarge) {
		t.Fatalf("WriteResponse: want ErrMessageTooLarge, got %v", err)
	}
	// Reader side: feed an oversized line into a limited reader.
	longLine := append(bytes.Repeat([]byte("B"), MaxMessageBytes+1), '\n')
	rd := bufio.NewReaderSize(bytes.NewReader(longLine), MaxMessageBytes+1)
	if _, err := DecodeRequest(rd); !errors.Is(err, ErrMessageTooLarge) {
		t.Fatalf("DecodeRequest: want ErrMessageTooLarge, got %v", err)
	}
}

func TestHandlerErrorPropagation(t *testing.T) {
	handlers := map[string]Handler{
		CmdConnect: func(ctx context.Context, r *Request) *Response {
			return &Response{OK: false, ErrorCode: ErrCodeAuth, Error: "login first"}
		},
	}
	client, _ := newTestServerClient(t, handlers)
	_, err := client.Call(context.Background(), CmdConnect, ConnectRequest{}, 0)
	if err != nil {
		t.Fatal(err)
	}
	// Re-call through CallInto to observe RemoteError mapping.
	err = client.CallInto(context.Background(), CmdConnect, ConnectRequest{}, nil, 0)
	var re *RemoteError
	if !errors.As(err, &re) || re.Code != ErrCodeAuth {
		t.Fatalf("want AUTH_REQUIRED RemoteError, got %v", err)
	}
}

func TestHandlerTimeout(t *testing.T) {
	handlers := map[string]Handler{
		CmdRepairNetwork: func(ctx context.Context, r *Request) *Response {
			<-ctx.Done()
			return &Response{OK: false, ErrorCode: ErrCodeTimeout, Error: "timed out"}
		},
	}
	client, _ := newTestServerClient(t, handlers)
	err := client.CallInto(context.Background(), CmdRepairNetwork, nil, nil, 50) // 50ms
	var re *RemoteError
	if !errors.As(err, &re) || re.Code != ErrCodeTimeout {
		t.Fatalf("want TIMEOUT, got %v", err)
	}
}

func TestPanicRecovered(t *testing.T) {
	handlers := map[string]Handler{
		CmdLogout: func(ctx context.Context, r *Request) *Response { panic("boom") },
	}
	client, _ := newTestServerClient(t, handlers)
	err := client.CallInto(context.Background(), CmdLogout, nil, nil, 0)
	var re *RemoteError
	if !errors.As(err, &re) || re.Code != ErrCodeInternal {
		t.Fatalf("want INTERNAL_ERROR after panic, got %v", err)
	}
}

func TestMissingRequestIDRejected(t *testing.T) {
	rd := bufio.NewReader(strings.NewReader(`{"version":1,"command":"GetStatus"}` + "\n"))
	if _, err := DecodeRequest(rd); err == nil || !strings.Contains(err.Error(), "request_id") {
		t.Fatalf("want request_id error, got %v", err)
	}
}

func TestEOFCleanShutdown(t *testing.T) {
	srv := NewServer(map[string]Handler{})
	c, s := net.Pipe()
	done := make(chan error, 1)
	go func() { done <- srv.ServeConn(context.Background(), s, s) }()
	c.Close()
	s.Close()
	select {
	case err := <-done:
		if err != nil && !errors.Is(err, io.ErrClosedPipe) {
			t.Fatalf("ServeConn returned %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("ServeConn did not return after peer close")
	}
}
