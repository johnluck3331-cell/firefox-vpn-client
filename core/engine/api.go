package engine

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"time"

	core "firefox-vpn-client/core"
)

// NormalizeProxyURL converts a raw proxy value ("host", "host:port", or a
// full URL) into a parsed https URL, the same way the engine does for CLI
// flags. Exported so platform frontends share one canonical form.
func NormalizeProxyURL(raw string) (*url.URL, error) {
	return normalizeProxyURL(raw)
}

// This file exposes a clean, programmatic API over the engine internals so
// that platform frontends (the Windows service, CLI diagnostics, smoke
// tests) never need to understand FxA, Guardian, Fastly, or HTTP/2/HTTP/3
// session details. The Windows layer talks only to these functions and to
// the TunnelOpener returned by StartUpstream.

// Location describes one selectable Firefox VPN server location.
type Location struct {
	CountryName string
	CountryCode string
	CityName    string
	CityCode    string
	Hostname    string // proxy server hostname from the server list
	Port        int    // proxy server port (0 means default 443)
}

// Addr returns the canonical "host:port" form for the location.
func (l Location) Addr() string {
	port := l.Port
	if port == 0 {
		port = 443
	}
	return net.JoinHostPort(l.Hostname, fmt.Sprint(port))
}

// ListLocations fetches the current server list and flattens it into
// selectable locations. Quarantined servers are skipped.
func ListLocations(ctx context.Context) ([]Location, error) {
	countries, err := core.FetchServerList(ctx)
	if err != nil {
		return nil, err
	}
	var out []Location
	for _, country := range countries {
		for _, city := range country.Cities {
			for _, server := range city.Servers {
				if server.Quarantined {
					continue
				}
				out = append(out, Location{
					CountryName: country.Name,
					CountryCode: country.Code,
					CityName:    city.Name,
					CityCode:    city.Code,
					Hostname:    server.Hostname,
					Port:        server.Port,
				})
			}
		}
	}
	return out, nil
}

// EnsureEntitlement verifies the account has an active Firefox Premium VPN
// subscription, activating it when necessary.
func EnsureEntitlement(ctx context.Context, accessToken string) (*core.Entitlement, error) {
	return core.ActivateGuardian(ctx, "", accessToken)
}

// FetchPass obtains a ProxyPass for the given OAuth access token.
func FetchPass(ctx context.Context, accessToken string) (*core.ProxyPassInfo, error) {
	return core.FetchProxyPass(ctx, "", accessToken)
}

// UpstreamConfig describes a fully-resolved upstream connection attempt.
type UpstreamConfig struct {
	AccessToken string           // FxA OAuth access token (kept for renewals)
	ObtainedAt  time.Time        // when the access token was obtained
	Pass        *core.ProxyPassInfo
	ProxyURL    *url.URL         // https://<proxy host>
	UseH3       bool             // prefer HTTP/3; false uses HTTP/2
	Sessions    int              // upstream session pool size (>=1)
	StatusFile  string           // optional runtime status file path
	Timeout     time.Duration    // per-session handshake timeout
}

// TunnelOpener opens byte-stream tunnels to arbitrary destination
// authorities ("host:port") through the connected Firefox VPN upstream.
// This is the single primitive the Windows data plane depends on:
//
//	Wintun -> Netstack TCP -> OpenTunnel(dest) -> HTTP/2|HTTP/3 CONNECT -> Firefox VPN
type TunnelOpener interface {
	OpenTunnel(authority string) (net.Conn, error)
	// Close tears down all upstream sessions. In-flight tunnels opened
	// before Close may continue until they finish.
	Close() error
}

// StartUpstream builds the upstream proxy session(s) for cfg and returns a
// TunnelOpener. Transport negotiation failures fall back according to the
// engine's normal rules (HTTP/3 attempted only when UseH3 is set).
func StartUpstream(cfg UpstreamConfig) (TunnelOpener, error) {
	auth := &runtimeAuth{Token: &core.TokenResponse{
		AccessToken: cfg.AccessToken,
		ExpiresIn:   int(time.Until(cfg.ObtainedAt.Add(90*time.Minute)) / time.Second),
	}, ObtainedAt: cfg.ObtainedAt}
	controller, err := newProxyController(proxyControllerConfig{
		Guardian:   core.GuardianEndpointDefault,
		ProxyURL:   cfg.ProxyURL,
		Timeout:    cfg.Timeout,
		Auth:       auth,
		Pass:       cfg.Pass,
		UseH3:      cfg.UseH3,
		Sessions:   cfg.Sessions,
		StatusFile: cfg.StatusFile,
	})
	if err != nil {
		return nil, err
	}
	return controller, nil
}
