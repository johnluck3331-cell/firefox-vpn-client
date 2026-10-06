package engine

import (
	"context"
	"encoding/json"
	"errors"
	core "firefox-vpn-client/core"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type exitProbeResult struct {
	IP          string
	CountryCode string
	Latency     time.Duration
	ProbeHost   string
}

func logVerifiedExit(opener tunnelOpener, rawURL string, timeout time.Duration, configuredCountryCode string) {
	result, err := verifyExit(opener, rawURL, timeout)
	if err != nil {
		logWarn("exit verification failed probe_host=%s timeout=%s err=%s", exitProbeHost(rawURL), timeout, logErr(err))
		return
	}
	logInfo("exit verified ip=%s country_code=%s data_path_probe_latency=%s probe_host=%s",
		result.IP,
		result.CountryCode,
		result.Latency.Round(time.Millisecond),
		result.ProbeHost,
	)
	if configuredCountryCode != "" && !strings.EqualFold(configuredCountryCode, result.CountryCode) {
		logWarn("verified exit country differs from configured upstream location configured_country_code=%s verified_country_code=%s",
			configuredCountryCode,
			result.CountryCode,
		)
	}
}

func exitProbeHost(rawURL string) string {
	probeURL, err := url.Parse(rawURL)
	if err != nil || probeURL.Hostname() == "" {
		return "<invalid>"
	}
	return probeURL.Hostname()
}

func verifyExit(opener tunnelOpener, rawURL string, timeout time.Duration) (exitProbeResult, error) {
	if opener == nil {
		return exitProbeResult{}, fmt.Errorf("nil tunnel opener")
	}
	probeURL, err := url.Parse(rawURL)
	if err != nil {
		return exitProbeResult{}, fmt.Errorf("parsing exit check URL: %w", err)
	}
	if !strings.EqualFold(probeURL.Scheme, "https") || probeURL.Hostname() == "" {
		return exitProbeResult{}, fmt.Errorf("exit check URL must use HTTPS and include a host")
	}

	transport := &http.Transport{
		Proxy:               nil,
		DisableKeepAlives:   true,
		TLSHandshakeTimeout: timeout,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
		DialContext: func(ctx context.Context, _, authority string) (net.Conn, error) {
			return openTunnelContext(ctx, opener, authority)
		},
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: timeout}

	request, err := http.NewRequest(http.MethodGet, probeURL.String(), nil)
	if err != nil {
		return exitProbeResult{}, fmt.Errorf("creating exit verification request: %w", err)
	}
	request.Header.Set("Accept", "text/plain, application/json")
	request.Header.Set("User-Agent", "firefox-vpn-client-exit-check/1")

	started := time.Now()
	response, err := client.Do(request)
	if err != nil {
		return exitProbeResult{}, fmt.Errorf("requesting exit verification endpoint: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return exitProbeResult{}, fmt.Errorf("exit verification endpoint returned HTTP %d", response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxExitCheckResponseSize+1))
	if err != nil {
		return exitProbeResult{}, fmt.Errorf("reading exit verification response: %w", err)
	}
	if len(body) > maxExitCheckResponseSize {
		return exitProbeResult{}, fmt.Errorf("exit verification response exceeds %d bytes", maxExitCheckResponseSize)
	}
	ip, countryCode, err := parseExitProbeResponse(body)
	if err != nil {
		return exitProbeResult{}, err
	}
	return exitProbeResult{
		IP:          ip,
		CountryCode: countryCode,
		Latency:     time.Since(started),
		ProbeHost:   probeURL.Hostname(),
	}, nil
}

func openTunnelContext(ctx context.Context, opener tunnelOpener, authority string) (net.Conn, error) {
	type tunnelResult struct {
		conn net.Conn
		err  error
	}
	resultCh := make(chan tunnelResult)
	go func() {
		conn, err := opener.OpenTunnel(authority)
		select {
		case resultCh <- tunnelResult{conn: conn, err: err}:
		case <-ctx.Done():
			if conn != nil {
				_ = conn.Close()
			}
		}
	}()

	select {
	case result := <-resultCh:
		return result.conn, result.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func parseExitProbeResponse(body []byte) (string, string, error) {
	fields := make(map[string]string)
	for _, line := range strings.Split(string(body), "\n") {
		key, value, ok := strings.Cut(strings.TrimSpace(line), "=")
		if ok {
			fields[strings.ToLower(strings.TrimSpace(key))] = strings.TrimSpace(value)
		}
	}

	ip := firstNonEmpty(fields["ip"], fields["query"])
	countryCode := firstNonEmpty(fields["loc"], fields["country_code"], fields["countrycode"])
	if ip == "" || countryCode == "" {
		var payload map[string]any
		if err := json.Unmarshal(body, &payload); err == nil {
			ip = firstNonEmpty(ip, jsonString(payload, "ip"), jsonString(payload, "query"))
			countryCode = firstNonEmpty(countryCode, jsonString(payload, "country_code"), jsonString(payload, "countryCode"))
		}
	}

	ip = strings.TrimSpace(ip)
	if net.ParseIP(ip) == nil {
		return "", "", fmt.Errorf("exit verification response did not contain a valid IP address")
	}
	countryCode = strings.ToUpper(strings.TrimSpace(countryCode))
	if len(countryCode) != 2 || countryCode[0] < 'A' || countryCode[0] > 'Z' || countryCode[1] < 'A' || countryCode[1] > 'Z' {
		return "", "", fmt.Errorf("exit verification response did not contain a valid two-letter country code")
	}
	return ip, countryCode, nil
}

func jsonString(payload map[string]any, key string) string {
	value, _ := payload[key].(string)
	return value
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func fetchProxyPassCtx(guardian, accessToken string) (*core.ProxyPassInfo, error) {
	ctx, cancel := context.WithTimeout(context.Background(), apiRequestTimeout)
	pass, err := core.FetchProxyPass(ctx, guardian, accessToken)
	cancel()
	return pass, err
}

func refreshRuntimeAuth(auth *runtimeAuth) (*runtimeAuth, error) {
	if auth == nil || auth.Token == nil || auth.Token.RefreshToken == "" {
		return nil, fmt.Errorf("no refresh token available")
	}
	ctx, cancel := context.WithTimeout(context.Background(), apiRequestTimeout)
	token, err := core.FxaRefreshToken(ctx, auth.Token.RefreshToken)
	cancel()
	if err != nil {
		return nil, err
	}
	if err := core.SaveTokens(token); err != nil {
		logWarn("saving refreshed tokens failed: %v", err)
	}
	return &runtimeAuth{Token: token, ObtainedAt: time.Now()}, nil
}
