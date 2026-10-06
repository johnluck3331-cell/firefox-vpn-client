package engine

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

// Structural constants shared by the VPN engine components.
const (
	socksVersion5       = 0x05
	socksCmdConnect     = 0x01
	socksAtypIPv4       = 0x01
	socksAtypDomain     = 0x03
	socksAtypIPv6       = 0x04
	socksAuthNoAuth     = 0x00
	socksAuthNoAccept   = 0xff
	socksReplySuccess   = 0x00
	socksReplyFailure   = 0x01
	socksReplyNotAllow  = 0x02
	socksReplyNetUnrch  = 0x03
	socksReplyHostUnrch = 0x04
	socksReplyCmdUnsup  = 0x07
	socksReplyAtypUnsup = 0x08
)

const (
	proxyPassRenewLead            = 2 * time.Minute
	proxyPassRetryDelay           = 30 * time.Second
	proxyPassRenewTimeout         = 2 * time.Minute
	oauthRefreshLead              = 2 * time.Minute
	maxOpenTunnelRebuildRetries   = 3
	defaultHandshakeTimeout       = 10 * time.Second
	defaultIdleTimeout            = 0
	defaultMaxConnections         = 256
	defaultUpstreamConnections    = 1
	upstreamSessionRetryDelay     = 10 * time.Second
	apiProxyDialTimeout           = 20 * time.Second
	defaultTunnelWriteBufSize     = 1 << 20
	upstreamKeepAliveInterval     = 10 * time.Second
	upstreamKeepAlivePingTimeout  = 5 * time.Second
	copyBufferSize                = 64 * 1024
	halfCloseDrainTimeout         = 2 * time.Minute
	maxDistinctOpenTimeoutTargets = 3
	maxDistinctBadGatewayTargets  = 3
	defaultExitCheckTimeout       = 10 * time.Second
	maxExitCheckResponseSize      = 64 * 1024
	defaultExitCheckURL           = "https://www.cloudflare.com/cdn-cgi/trace"
)

var (
	errProxyHTTP2Unavailable = errors.New("proxy did not negotiate HTTP/2")
	errProxyHTTP3Unavailable = errors.New("proxy did not negotiate HTTP/3")
	errProxySessionUnhealthy = errors.New("upstream proxy session became unhealthy")
	errNoUsableProxySession  = errors.New("no usable upstream proxy session")
	errTunnelDeadline        = errors.New("deadlines are not supported for HTTP CONNECT tunnel streams")
	errTokenPoolExhausted    = errors.New("no session tokens left in the pool; wait for the monthly quota reset or provide a new token file")
	engineVerbose            bool
	logMu                    sync.Mutex
)

var copyBufferPool = sync.Pool{
	New: func() any {
		return make([]byte, copyBufferSize)
	},
}

func logEvent(level, format string, args ...any) {
	logMu.Lock()
	defer logMu.Unlock()
	fmt.Fprintf(os.Stderr, "[%s] %s\n", level, fmt.Sprintf(format, args...))
}

func logDebug(format string, args ...any) {
	if !engineVerbose {
		return
	}
	logEvent("DEBUG", format, args...)
}

func logInfo(format string, args ...any) {
	logEvent("INFO", format, args...)
}

func logWarn(format string, args ...any) {
	logEvent("WARN", format, args...)
}

func logError(format string, args ...any) {
	logEvent("ERROR", format, args...)
}

func logTarget(target string) string {
	if engineVerbose {
		return target
	}
	return strings.Repeat("*", min(len(target), 8))
}

func logErr(err error) string {
	if err == nil {
		return "<nil>"
	}
	msg := err.Error()
	if !engineVerbose {
		// Redact bearer tokens that may leak into error strings.
		for _, part := range strings.Fields(msg) {
			if strings.HasPrefix(part, "Bearer") || len(part) >= 40 && !strings.ContainsAny(part, " .:/") {
				msg = strings.ReplaceAll(msg, part, "[redacted]")
			}
		}
	}
	return msg
}

func logAddr(addr net.Addr) string {
	if addr == nil {
		return "<nil>"
	}
	return addr.String()
}

// SetVerbose enables per-connection debug logging including CONNECT targets.
func SetVerbose(v bool) { engineVerbose = v }

// fatalEngine terminates the process with an exit code. The engine keeps the
// original CLI behaviour of exiting on unrecoverable auth failures; long-lived
// hosts (service/GUI) should avoid paths that reach this by using Login and
// ConnectWithAuth directly.
func fatalEngine(code int) {
	os.Exit(code)
}
