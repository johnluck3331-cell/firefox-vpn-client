package ipc

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"sync"
	"sync/atomic"
)

// Handler executes one validated request and returns a response. Handlers
// must honour ctx cancellation/deadlines; the server enforces per-request
// timeouts derived from Request.TimeoutMs or DefaultTimeout.
type Handler func(ctx context.Context, req *Request) *Response

// Server serves the JSONL IPC protocol over an arbitrary duplex connection.
// On Windows each accepted named-pipe instance is handed to ServeConn; unit
// tests use net.Pipe(). The server processes requests sequentially per
// connection (matching the request/response pipelining of the clients).
type Server struct {
	handlers map[string]Handler

	mu        sync.Mutex
	inFlight  int32
	MaxInFlt  int32 // advisory cap per connection (0 = unlimited)
	ReadLimit int   // bufio reader size; defaults to MaxMessageBytes
}

// NewServer creates a server with the given command→handler table. Unknown
// commands are rejected automatically before dispatch.
func NewServer(handlers map[string]Handler) *Server {
	return &Server{handlers: handlers, ReadLimit: MaxMessageBytes}
}

// ErrNoHandler is synthesised into a NOT_FOUND response.
var ErrNoHandler = errors.New("ipc: no handler registered")

// ServeConn reads requests from r, dispatches them and writes responses to w
// until EOF or a fatal framing error. It is safe to call concurrently for
// different connections.
func (s *Server) ServeConn(ctx context.Context, r io.Reader, w io.Writer) error {
	limit := s.ReadLimit
	if limit <= 0 {
		limit = MaxMessageBytes
	}
	rd := bufio.NewReaderSize(r, limit+1)
	var wm sync.Mutex
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		req, err := DecodeRequest(rd)
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			// Framing/security violation: reply once (best effort) then drop
			// the connection — malformed messages are never retried against
			// the privileged service.
			resp := &Response{OK: false, ErrorCode: ErrCodeProtocol, Error: err.Error()}
			wm.Lock()
			_ = WriteResponse(w, resp)
			wm.Unlock()
			return err
		}
		atomic.AddInt32(&s.inFlight, 1)
		resp := s.dispatch(ctx, req)
		atomic.AddInt32(&s.inFlight, -1)
		wm.Lock()
		err = WriteResponse(w, resp)
		wm.Unlock()
		if err != nil {
			return err
		}
	}
}

func (s *Server) dispatch(ctx context.Context, req *Request) *Response {
	h, ok := s.handlers[req.Command]
	if !ok || !isValidCommand(req.Command) {
		return &Response{RequestID: req.RequestID, OK: false,
			ErrorCode: ErrCodeNotFound, Error: ErrNoHandler.Error()}
	}
	timeout := DefaultTimeout
	if req.TimeoutMs > 0 {
		timeout = milliseconds(req.TimeoutMs)
	}
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	resp := runHandlerSafe(cctx, h, req)
	resp.RequestID = req.RequestID
	resp.Version = ProtocolVersion
	return resp
}

// runHandlerSafe converts panics into INTERNAL_ERROR responses so a buggy
// handler cannot take down the privileged service.
func runHandlerSafe(ctx context.Context, h Handler, req *Request) (resp *Response) {
	defer func() {
		if r := recover(); r != nil {
			resp = &Response{OK: false, ErrorCode: ErrCodeInternal,
				Error: "internal panic"}
		}
	}()
	resp = h(ctx, req)
	if resp == nil {
		resp = &Response{OK: false, ErrorCode: ErrCodeInternal, Error: "nil response"}
	}
	switch ctx.Err() {
	case context.DeadlineExceeded:
		if resp.OK {
			resp = &Response{OK: false, ErrorCode: ErrCodeTimeout, Error: "request timed out"}
		}
	case context.Canceled:
		if resp.OK {
			resp = &Response{OK: false, ErrorCode: ErrCodeTimeout, Error: "server shutting down"}
		}
	}
	return resp
}

// Client is the request/response side used by UI/tray/CLI processes.
type Client struct {
	mu     sync.Mutex
	rwc    io.ReadWriteCloser
	rd     *bufio.Reader
	nextID atomic.Uint64
}

// NewClient wraps an already-connected duplex stream.
func NewClient(rwc io.ReadWriteCloser) *Client {
	return &Client{rwc: rwc, rd: bufio.NewReaderSize(rwc, MaxMessageBytes+1)}
}

func (c *Client) NextRequestID() string {
	n := c.nextID.Add(1)
	return formatRequestID(n)
}

// Call sends one request and waits for its matching response. Requests are
// serialised per client (mutex) which matches the sequential server loop.
func (c *Client) Call(ctx context.Context, command string, payload any, timeoutMs int64) (*Response, error) {
	var raw json.RawMessage
	if payload != nil {
		b, err := json.Marshal(payload)
		if err != nil {
			return nil, err
		}
		raw = b
	}
	req := &Request{
		RequestID: c.NextRequestID(),
		Command:   command,
		Payload:   raw,
		TimeoutMs: timeoutMs,
	}
	type result struct {
		resp *Response
		err  error
	}
	done := make(chan result, 1)
	go func() {
		c.mu.Lock()
		defer c.mu.Unlock()
		if err := WriteRequest(c.rwc, req); err != nil {
			done <- result{nil, err}
			return
		}
		resp, err := DecodeResponse(c.rd)
		done <- result{resp, err}
	}()
	select {
	case <-ctx.Done():
		// Abandonment closes the connection; the caller must Reconnect.
		_ = c.Close()
		return nil, ctx.Err()
	case res := <-done:
		if res.err != nil {
			return nil, res.err
		}
		if res.resp.RequestID != req.RequestID {
			return nil, errors.New("ipc: response request_id mismatch")
		}
		return res.resp, nil
	}
}

// CallInto performs Call and unmarshals a successful payload into out.
func (c *Client) CallInto(ctx context.Context, command string, payload, out any, timeoutMs int64) error {
	resp, err := c.Call(ctx, command, payload, timeoutMs)
	if err != nil {
		return err
	}
	if !resp.OK {
		return &RemoteError{Code: resp.ErrorCode, Message: resp.Error}
	}
	if out != nil && len(resp.Payload) > 0 {
		return json.Unmarshal(resp.Payload, out)
	}
	return nil
}

// Close tears down the underlying connection.
func (c *Client) Close() error { return c.rwc.Close() }

// RemoteError describes a service-side failure with its stable error code.
type RemoteError struct {
	Code    string
	Message string
}

func (e *RemoteError) Error() string { return "service error " + e.Code + ": " + e.Message }
