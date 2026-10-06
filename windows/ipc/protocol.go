// Package ipc implements the versioned request/response protocol spoken
// between the FoxyVPN tray/UI client and the privileged FoxyVPNService.
//
// Wire format (both directions): one JSON object per line ("JSONL"), size
// limited to MaxMessageBytes. The protocol is transport-agnostic: on Windows
// it rides a Named Pipe (server_windows.go / client_windows.go), and Linux
// unit tests drive it over net.Pipe().
package ipc

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"
)

// ProtocolVersion is bumped when message semantics change incompatibly.
// Servers reject requests with a different major version.
const ProtocolVersion = 1

// MaxMessageBytes bounds a single JSONL message to protect the privileged
// service from memory-exhaustion by a malicious local client.
const MaxMessageBytes = 1 << 20 // 1 MiB

// DefaultTimeout is applied to requests that do not carry their own deadline.
const DefaultTimeout = 30 * time.Second

// Command names supported by the service. Keep in sync with Commands().
const (
	CmdGetStatus      = "GetStatus"
	CmdConnect        = "Connect"
	CmdDisconnect     = "Disconnect"
	CmdReconnect      = "Reconnect"
	CmdGetLocations   = "GetLocations"
	CmdSetLocation    = "SetLocation"
	CmdGetStatistics  = "GetStatistics"
	CmdGetDiagnostics = "GetDiagnostics"
	CmdLogin          = "Login"
	CmdVerifySession  = "VerifySession"
	CmdLogout         = "Logout"
	CmdRepairNetwork  = "RepairNetwork"
)

// Commands returns the allow-list of valid command names. Anything outside
// this set is rejected before dispatch (command validation).
func Commands() []string {
	return []string{
		CmdGetStatus, CmdConnect, CmdDisconnect, CmdReconnect,
		CmdGetLocations, CmdSetLocation, CmdGetStatistics, CmdGetDiagnostics,
		CmdLogin, CmdVerifySession, CmdLogout, CmdRepairNetwork,
	}
}

func isValidCommand(c string) bool {
	for _, v := range Commands() {
		if c == v {
			return true
		}
	}
	return false
}

// Request is a single client→service call.
type Request struct {
	Version   int             `json:"version"`
	RequestID string          `json:"request_id"`
	Command   string          `json:"command"`
	Payload   json.RawMessage `json:"payload,omitempty"`
	// TimeoutMs optionally overrides DefaultTimeout for long operations
	// such as Connect or Login.
	TimeoutMs int64 `json:"timeout_ms,omitempty"`
}

// Response is the service's reply to a Request (matched by RequestID).
type Response struct {
	Version   int             `json:"version"`
	RequestID string          `json:"request_id"`
	OK        bool            `json:"ok"`
	Error     string          `json:"error,omitempty"`
	ErrorCode string          `json:"error_code,omitempty"`
	Payload   json.RawMessage `json:"payload,omitempty"`
}

// Error codes surfaced to clients.
const (
	ErrCodeProtocol   = "PROTOCOL_ERROR"
	ErrCodeAuth       = "AUTH_REQUIRED"
	ErrCodeState      = "INVALID_STATE"
	ErrCodeInternal   = "INTERNAL_ERROR"
	ErrCodeTimeout    = "TIMEOUT"
	ErrCodeNotFound   = "NOT_FOUND"
	ErrCodeQuota      = "QUOTA_EXCEEDED"
	ErrCodeUnsupported = "UNSUPPORTED"
)

// StatusPayload is the reply body for GetStatus.
type StatusPayload struct {
	State           string    `json:"state"` // Disconnected/Connecting/Connected/Error...
	LoggedIn        bool      `json:"logged_in"`
	Email           string    `json:"email,omitempty"` // display-only, may be masked
	Location        string    `json:"location,omitempty"`
	Transport       string    `json:"transport,omitempty"` // http2 | http3
	PublicIP        string    `json:"public_ip,omitempty"`
	UptimeSeconds   int64     `json:"uptime_seconds,omitempty"`
	BytesSent       uint64    `json:"bytes_sent"`
	BytesReceived   uint64    `json:"bytes_received"`
	ActiveFlows     int       `json:"active_flows"`
	KillSwitchArmed bool      `json:"kill_switch_armed"`
	UDPBlocked      bool      `json:"udp_blocked"`
	IPv6Protected   bool      `json:"ipv6_protected"`
	ServerTimestamp time.Time `json:"server_timestamp"`
}

// ConnectRequest carries optional per-connection overrides.
type ConnectRequest struct {
	LocationCode string `json:"location_code,omitempty"` // e.g. "us-atl"; empty = preferred/auto
	UseH3        *bool  `json:"use_h3,omitempty"`        // nil = config default
}

// LocationInfo mirrors engine.Location for IPC clients.
type LocationInfo struct {
	CountryName string `json:"country_name"`
	CountryCode string `json:"country_code"`
	CityName    string `json:"city_name"`
	CityCode    string `json:"city_code"`
	Hostname    string `json:"hostname,omitempty"`
	Port        int    `json:"port,omitempty"`
}

// LocationsPayload is the reply body for GetLocations.
type LocationsPayload struct {
	Locations []LocationInfo `json:"locations"`
	Preferred string         `json:"preferred,omitempty"`
}

// SetLocationRequest persists the preferred location.
type SetLocationRequest struct {
	CityCode string `json:"city_code"`
}

// StatisticsPayload is the reply body for GetStatistics.
type StatisticsPayload struct {
	BytesSent      uint64 `json:"bytes_sent"`
	BytesReceived  uint64 `json:"bytes_received"`
	TotalFlows     uint64 `json:"total_flows"`
	ActiveFlows    int    `json:"active_flows"`
	FailedFlows    uint64 `json:"failed_flows"`
	UptimeSeconds  int64  `json:"uptime_seconds"`
	TunnelOpenFail uint64 `json:"tunnel_open_failures"`
}

// DiagnosticsItem is one PASS/FAIL/NOT_SUPPORTED check result.
type DiagnosticsItem struct {
	Name    string `json:"name"`
	Result  string `json:"result"` // PASS / FAIL / NOT_SUPPORTED / SKIPPED
	Details string `json:"details,omitempty"`
}

// DiagnosticsPayload is the reply body for GetDiagnostics.
type DiagnosticsPayload struct {
	Items []DiagnosticsItem `json:"items"`
}

// LoginRequest supplies credentials. NOTE: the password crosses the pipe in
// cleartext JSON; the pipe is ACL-restricted to SYSTEM+the interactive user
// (see server_windows.go). Clients should prefer cached refresh tokens.
type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// LoginResponse reports whether email verification is pending.
type LoginResponse struct {
	VerificationRequired bool   `json:"verification_required"`
	Message              string `json:"message,omitempty"`
}

// VerifySessionRequest submits the emailed confirmation code.
type VerifySessionRequest struct {
	Code string `json:"code"`
}

var (
	// ErrVersionMismatch is returned by DecodeRequest for wrong protocol versions.
	ErrVersionMismatch = errors.New("ipc: protocol version mismatch")
	// ErrBadCommand is returned for commands outside the allow-list.
	ErrBadCommand = errors.New("ipc: unknown command")
	// ErrMessageTooLarge is returned when a peer exceeds MaxMessageBytes.
	ErrMessageTooLarge = errors.New("ipc: message exceeds size limit")
)

// WriteRequest serialises r as one JSONL frame.
func WriteRequest(w io.Writer, r *Request) error {
	r.Version = ProtocolVersion
	return writeJSON(w, r)
}

// WriteResponse serialises resp as one JSONL frame.
func WriteResponse(w io.Writer, resp *Response) error {
	resp.Version = ProtocolVersion
	return writeJSON(w, resp)
}

// DecodeRequest parses and validates one request frame.
func DecodeRequest(rd *bufio.Reader) (*Request, error) {
	line, err := readLimitedLine(rd)
	if err != nil {
		return nil, err
	}
	var r Request
	if err := json.Unmarshal(line, &r); err != nil {
		return nil, fmt.Errorf("ipc: malformed request JSON: %w", err)
	}
	if r.Version != ProtocolVersion {
		return nil, ErrVersionMismatch
	}
	if !isValidCommand(r.Command) {
		return nil, fmt.Errorf("%w: %q", ErrBadCommand, r.Command)
	}
	if r.RequestID == "" {
		return nil, errors.New("ipc: missing request_id")
	}
	return &r, nil
}

// DecodeResponse parses one response frame.
func DecodeResponse(rd *bufio.Reader) (*Response, error) {
	line, err := readLimitedLine(rd)
	if err != nil {
		return nil, err
	}
	var resp Response
	if err := json.Unmarshal(line, &resp); err != nil {
		return nil, fmt.Errorf("ipc: malformed response JSON: %w", err)
	}
	if resp.Version != ProtocolVersion {
		return nil, ErrVersionMismatch
	}
	return &resp, nil
}

func writeJSON(w io.Writer, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if len(b)+1 > MaxMessageBytes {
		return ErrMessageTooLarge
	}
	b = append(b, '\n')
	_, err = w.Write(b)
	return err
}

// readLimitedLine reads one newline-delimited frame, refusing anything
// larger than MaxMessageBytes (request size limits against the privileged pipe).
func readLimitedLine(rd *bufio.Reader) ([]byte, error) {
	line, err := rd.ReadBytes('\n')
	if errors.Is(err, bufio.ErrBufferFull) {
		return nil, ErrMessageTooLarge
	}
	if err != nil && len(line) == 0 {
		return nil, err // io.EOF etc.
	}
	if len(line) > MaxMessageBytes {
		return nil, ErrMessageTooLarge
	}
	// strip trailing newline
	if n := len(line); n > 0 && line[n-1] == '\n' {
		line = line[:n-1]
		if n := len(line); n > 0 && line[n-1] == '\r' {
			line = line[:n-1]
		}
	}
	if len(line) == 0 {
		return nil, errors.New("ipc: empty frame")
	}
	return line, nil
}
