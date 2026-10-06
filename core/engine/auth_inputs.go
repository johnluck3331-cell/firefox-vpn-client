package engine

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	core "firefox-vpn-client/core"
	"fmt"
	"golang.org/x/term"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// promptCredentialsStdin reads FxA email/password from the terminal. It is
// used only by the CLI entry point; GUI/service callers use Login directly.
func promptCredentialsStdin() (string, string) {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Firefox Account email: ")
	email, _ := reader.ReadString('\n')
	passwordBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		fmt.Println()
		fatalEngine(1)
	}
	fmt.Println()
	return strings.TrimSpace(email), string(passwordBytes)
}

// prepareDemoInputs resolves authentication inputs and the server list for a
// connection attempt. Sources: session-token pool file, single session token,
// or the cached/interactive FxA flow.
func prepareDemoInputs(forceLogin bool, sessionToken string, needServerList bool) (*runtimeAuth, string, []core.Country, *sessionTokenPool) {
	var token *core.TokenResponse
	var tokenSource string
	var tokenObtainedAt time.Time
	var tokenPool *sessionTokenPool
	var err error

	switch {
	case sessionToken != "" && isExistingFile(sessionToken):
		tokenPool, err = loadSessionTokenPool(sessionToken)
		if err != nil {
			logError("loading session token file failed: %v", err)
			fatalEngine(1)
		}
		logInfo("loaded session tokens file=%s tokens=%d", sessionToken, tokenPool.size())
		if from := tokenPool.resumedIndex(); from > 0 {
			logInfo("resuming from session token %d/%d (saved state)", from, tokenPool.size())
		}
		auth, err := activateNextPoolToken(tokenPool)
		if err != nil {
			logError("activating session token failed: %v", err)
			fatalEngine(1)
		}
		token = auth.Token
		tokenObtainedAt = auth.ObtainedAt
		tokenSource = fmt.Sprintf("session-token file %s (%d tokens)", sessionToken, tokenPool.size())
	case sessionToken != "":
		logInfo("using provided session token")
		ctx, cancel := context.WithTimeout(context.Background(), apiRequestTimeout)
		newToken, err := core.FxaOAuthToken(ctx, sessionToken)
		cancel()
		if err != nil {
			logError("session token exchange failed: %v", err)
			fatalEngine(1)
		}
		token = newToken
		tokenSource = "session-token flag"
		tokenObtainedAt = time.Now()
	default:
		token, tokenSource, tokenObtainedAt, err = obtainOAuthTokenInteractive(forceLogin)
		if err != nil {
			logError("obtaining OAuth token failed: %v", err)
			fatalEngine(1)
		}
	}

	if tokenSource != "cached access token" {
		if err := core.SaveTokens(token); err != nil {
			logWarn("saving tokens failed: %v", err)
		}
	}

	var countries []core.Country
	var err error
	if needServerList {
		ctx, cancel := context.WithTimeout(context.Background(), apiRequestTimeout)
		countries, err = core.FetchServerList(ctx)
		cancel()
		if err != nil {
			logWarn("fetching server list failed: %v", err)
		}
	}

	return &runtimeAuth{
		Token:      token,
		ObtainedAt: tokenObtainedAt,
	}, tokenSource, countries, tokenPool
}

// sessionTokenPool holds session tokens loaded from a text file and hands
// them out one by one as the previous token's monthly quota is exhausted.
type sessionTokenPool struct {
	mu      sync.Mutex
	tokens  []string
	nextIdx int

	statePath   string // persists activation progress next to the token file
	checksum    string // sha256 of the token file; state is discarded if it differs
	resumedFrom int    // 1-based position restored from the state file, 0 if none
}

// sessionPoolState records which token was active when the state was written.
type sessionPoolState struct {
	Checksum       string `json:"checksum"`
	ActivatedIndex int    `json:"activated_index"` // 1-based position of the last activated token
}

// loadSessionTokenPool reads one session token per line from path, skipping
// blank lines, '#' comments and duplicates.
func loadSessionTokenPool(path string) (*sessionTokenPool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading token file: %w", err)
	}
	var tokens []string
	seen := make(map[string]struct{})
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if _, dup := seen[line]; dup {
			continue
		}
		seen[line] = struct{}{}
		tokens = append(tokens, line)
	}
	if len(tokens) == 0 {
		return nil, fmt.Errorf("no session tokens found in %s", path)
	}
	pool := &sessionTokenPool{
		tokens:    tokens,
		statePath: stateFilePath(path),
		checksum:  sha256Hex(data),
	}
	pool.restoreState()
	return pool, nil
}

func stateFilePath(tokenFilePath string) string {
	dir := filepath.Dir(tokenFilePath)
	name := filepath.Base(tokenFilePath) + ".state"
	return filepath.Join(dir, name)
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// restoreState resumes the pool from the persisted activation index when the
// token file is unchanged since the state was written.
func (p *sessionTokenPool) restoreState() {
	data, err := os.ReadFile(p.statePath)
	if err != nil {
		return
	}
	var state sessionPoolState
	if err := json.Unmarshal(data, &state); err != nil {
		return
	}
	if state.Checksum != p.checksum || state.ActivatedIndex < 1 || state.ActivatedIndex > len(p.tokens) {
		return
	}
	// Retry the saved token first: its quota may still have traffic left.
	p.nextIdx = state.ActivatedIndex - 1
	p.resumedFrom = state.ActivatedIndex
}

// saveState persists the 1-based position of the last activated token so a
// restart can resume without replaying already exhausted tokens. The write is
// atomic (temp file + rename) so a hard shutdown mid-write cannot corrupt
// the state file. Failures (e.g. read-only directory) are logged and
// ignored: state persistence must never interrupt the proxy.
func (p *sessionTokenPool) saveState(index int) {
	data, err := json.Marshal(sessionPoolState{Checksum: p.checksum, ActivatedIndex: index})
	if err != nil {
		return
	}
	tmpPath := p.statePath + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0600); err != nil {
		logWarn("saving token pool state failed path=%s err=%v", p.statePath, err)
		return
	}
	if err := os.Rename(tmpPath, p.statePath); err != nil {
		_ = os.Remove(tmpPath)
		logWarn("saving token pool state failed path=%s err=%v", p.statePath, err)
	}
}

func (p *sessionTokenPool) resumedIndex() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.resumedFrom
}

// next returns the next unused token together with its 1-based position.
func (p *sessionTokenPool) next() (token string, index int, total int, ok bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.nextIdx >= len(p.tokens) {
		return "", 0, len(p.tokens), false
	}
	token = p.tokens[p.nextIdx]
	p.nextIdx++
	return token, p.nextIdx, len(p.tokens), true
}

func (p *sessionTokenPool) size() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.tokens)
}

// activateNextPoolToken exchanges the next session token from the pool for
// OAuth tokens, skipping tokens that FxA rejects.
func activateNextPoolToken(pool *sessionTokenPool) (*runtimeAuth, error) {
	for {
		sessionToken, index, total, ok := pool.next()
		if !ok {
			return nil, errTokenPoolExhausted
		}
		logInfo("activating session token %d/%d", index, total)
		ctx, cancel := context.WithTimeout(context.Background(), apiRequestTimeout)
		token, err := core.FxaOAuthToken(ctx, sessionToken)
		cancel()
		if err != nil {
			logWarn("session token %d/%d rejected: %v", index, total, err)
			continue
		}
		pool.saveState(index)
		return &runtimeAuth{Token: token, ObtainedAt: time.Now()}, nil
	}
}

// isQuotaExhausted reports whether the proxy pass quota headers indicate
// that no monthly traffic is left.
func isQuotaExhausted(pass *core.ProxyPassInfo) bool {
	if pass == nil || pass.QuotaLeft == "" {
		return false
	}
	left, err := strconv.ParseInt(pass.QuotaLeft, 10, 64)
	if err != nil {
		return false
	}
	return left <= 0
}

func isExistingFile(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular()
}

// acquireInitialPass fetches the first proxy pass. A Guardian token
// rejection (HTTP 401/403) is recovered from by refreshing the OAuth token
// and activating the account; when the token's monthly quota is exhausted
// (HTTP 429 or zero remaining) and a session token pool is configured, it
// rotates to the next token.
func acquireInitialPass(guardian string, auth *runtimeAuth, pool *sessionTokenPool) (*core.ProxyPassInfo, *runtimeAuth, error) {
	for {
		pass, err := fetchProxyPassCtx(guardian, auth.Token.AccessToken)
		if err == nil && !isQuotaExhausted(pass) {
			return pass, auth, nil
		}

		if errors.Is(err, core.ErrTokenInvalid) {
			logInfo("cached OAuth access was rejected by Guardian; refreshing token")
			if refreshed, refreshErr := refreshRuntimeAuth(auth); refreshErr == nil {
				auth = refreshed
				pass, err = fetchProxyPassCtx(guardian, auth.Token.AccessToken)
			} else {
				logWarn("refreshing OAuth token after Guardian rejection failed: %v", refreshErr)
			}
			if errors.Is(err, core.ErrTokenInvalid) {
				logInfo("Guardian account is not activated for Firefox VPN proxy access; activating")
				ctx, cancel := context.WithTimeout(context.Background(), apiRequestTimeout)
				_, activateErr := core.ActivateGuardian(ctx, guardian, auth.Token.AccessToken)
				cancel()
				if activateErr != nil {
					logWarn("activating Guardian account failed: %v", activateErr)
				} else {
					logInfo("Guardian account activated")
					pass, err = fetchProxyPassCtx(guardian, auth.Token.AccessToken)
				}
			}
			if err == nil && !isQuotaExhausted(pass) {
				return pass, auth, nil
			}
		}

		if err != nil && !errors.Is(err, core.ErrQuotaExceeded) && !errors.Is(err, core.ErrTokenInvalid) {
			// Transient failure (network, server error): no point burning
			// through the pool.
			return nil, nil, err
		}
		if pool == nil {
			if err != nil {
				return nil, nil, err
			}
			return pass, auth, nil
		}
		if errors.Is(err, core.ErrTokenInvalid) {
			logWarn("session token rejected by Guardian; switching to the next token")
		} else {
			logWarn("session token quota exhausted; switching to the next token")
		}
		nextAuth, nextErr := activateNextPoolToken(pool)
		if nextErr != nil {
			if err != nil {
				return nil, nil, err
			}
			return nil, nil, nextErr
		}
		if saveErr := core.SaveTokens(nextAuth.Token); saveErr != nil {
			logWarn("saving tokens failed: %v", saveErr)
		}
		auth = nextAuth
	}
}

func printRuntimeInfo(guardian, accessToken string, pass *core.ProxyPassInfo, countries []core.Country) {
	fmt.Println("=== User Info ===")
	ctx, cancel := context.WithTimeout(context.Background(), apiRequestTimeout)
	ent, err := core.FetchUserInfo(ctx, guardian, accessToken)
	cancel()
	if err != nil {
		fmt.Printf("Warning: could not fetch user info: %v\n", err)
	} else {
		fmt.Printf("Subscribed:    %v\n", ent.Subscribed)
		fmt.Printf("UID:           %d\n", ent.UID)
		fmt.Printf("Max Bytes:     %s\n", ent.MaxBytes)
	}

	fmt.Println()
	fmt.Println("=== Proxy Pass ===")
	fmt.Printf("JWT Token:     %s...%s\n", pass.RawToken[:min(20, len(pass.RawToken))], pass.RawToken[max(0, len(pass.RawToken)-20):])
	fmt.Printf("Subject:       %s\n", pass.Claims.Sub)
	fmt.Printf("Issuer:        %s\n", pass.Claims.Iss)
	fmt.Printf("Audience:      %s\n", pass.Claims.Aud)
	fmt.Printf("Not Before:    %s\n", pass.NotBefore().Format("2006-01-02 15:04:05 UTC"))
	fmt.Printf("Expires At:    %s\n", pass.ExpiresAt().Format("2006-01-02 15:04:05 UTC"))

	if pass.QuotaMax != "" {
		fmt.Println()
		fmt.Println("=== Usage Quota ===")
		fmt.Printf("Limit:         %s bytes\n", pass.QuotaMax)
		fmt.Printf("Remaining:     %s bytes\n", pass.QuotaLeft)
		fmt.Printf("Resets At:     %s\n", pass.QuotaReset)
	}

	fmt.Println()
	fmt.Println("=== Server List ===")
	if len(countries) == 0 {
		fmt.Println("No servers found in Remote Settings.")
		return
	}
	core.PrintServerList(countries)
}

func logProxyPassTimeCorrection(pass *core.ProxyPassInfo) {
	if pass == nil || pass.ClaimTimeCorrection() == 0 {
		return
	}
	logWarn("proxy pass JWT claim time correction applied offset=%s expires_at=%s", pass.ClaimTimeCorrection(), pass.ExpiresAt().Format(time.RFC3339))
}

func upstreamMode(sessions int) string {
	if sessions <= 1 {
		return "single-upstream-connection"
	}
	return fmt.Sprintf("upstream-session-pool size=%d affinity=client-ip failover", sessions)
}

func obtainOAuthTokenInteractive(forceLogin bool) (*core.TokenResponse, string, time.Time, error) {
	email, password := promptCredentialsStdin()
	return obtainOAuthTokenWithCredentials(forceLogin, email, password)
}

// ObtainOAuthTokenWithCredentials performs the full FxA login flow with the
// supplied credentials, including cached-token reuse and refresh. It returns
// ErrVerificationRequired when FxA demands an email confirmation code.
func ObtainOAuthTokenWithCredentials(forceLogin bool, email, password string) (*core.TokenResponse, string, time.Time, error) {
	return obtainOAuthTokenWithCredentials(forceLogin, email, password)
}

var ErrVerificationRequired = errors.New("firefox account verification required: enter the confirmation code sent to your email")

func obtainOAuthTokenWithCredentials(forceLogin bool, email, password string) (*core.TokenResponse, string, time.Time, error) {
	if !forceLogin {
		saved, err := core.LoadTokens()
		if err == nil {
			if saved.AccessTokenValid() {
				logInfo("using cached OAuth access token")
				return &core.TokenResponse{
					AccessToken:  saved.AccessToken,
					RefreshToken: saved.RefreshToken,
					ExpiresIn:    saved.ExpiresIn,
					Scope:        saved.Scope,
					TokenType:    "bearer",
				}, "cached access token", saved.ObtainedAt, nil
			}
			if saved.RefreshToken != "" {
				logInfo("refreshing OAuth token")
				ctx, cancel := context.WithTimeout(context.Background(), apiRequestTimeout)
				token, err := core.FxaRefreshToken(ctx, saved.RefreshToken)
				cancel()
				if err != nil {
					logWarn("token refresh failed: %v; saved tokens were preserved", err)
					return nil, "", time.Time{}, err
				}
				return token, "refresh token", time.Now(), nil
			}
		}
	}

	logInfo("logging in to Firefox Accounts")
	loginCtx, loginCancel := context.WithTimeout(context.Background(), apiRequestTimeout)
	loginResp, err := core.FxaLogin(loginCtx, email, password)
	loginCancel()
	if err != nil {
		logError("Firefox Accounts login failed: %v", err)
		return nil, "", time.Time{}, err
	}

	if !loginResp.Verified {
		// The caller must complete the emailed confirmation code flow via
		// VerifySession before an OAuth token can be issued.
		lastUnverifiedSession = loginResp.SessionToken
		return nil, "", time.Time{}, ErrVerificationRequired
	}

	tokenCtx, tokenCancel := context.WithTimeout(context.Background(), apiRequestTimeout)
	token, err := core.FxaOAuthToken(tokenCtx, loginResp.SessionToken)
	tokenCancel()
	if err != nil {
		logError("OAuth token exchange failed: %v", err)
		return nil, "", time.Time{}, err
	}
	return token, "fresh login", time.Now(), nil
}

// lastUnverifiedSession remembers the FxA session token from the most recent
// login that requires email verification so VerifySession can confirm it.
var lastUnverifiedSession string

// Login starts a Firefox Accounts sign-in with explicit credentials (used by
// GUI/service callers). It returns ErrVerificationRequired when FxA demands
// the emailed confirmation code; call VerifySession with the code next.
func Login(email, password string) (*core.TokenResponse, string, time.Time, error) {
	return obtainOAuthTokenWithCredentials(true, email, password)
}

// VerifySession submits the emailed confirmation code for the pending login
// and completes the OAuth exchange.
func VerifySession(code string) (*core.TokenResponse, string, time.Time, error) {
	if lastUnverifiedSession == "" {
		return nil, "", time.Time{}, errors.New("no pending Firefox Account verification")
	}
	ctx, cancel := context.WithTimeout(context.Background(), apiRequestTimeout)
	err := core.FxaVerifySession(ctx, lastUnverifiedSession, code)
	cancel()
	if err != nil {
		return nil, "", time.Time{}, err
	}
	tokenCtx, tokenCancel := context.WithTimeout(context.Background(), apiRequestTimeout)
	token, err := core.FxaOAuthToken(tokenCtx, lastUnverifiedSession)
	tokenCancel()
	if err != nil {
		return nil, "", time.Time{}, err
	}
	lastUnverifiedSession = ""
	return token, "fresh login after verification", time.Now(), nil
}
