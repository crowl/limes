package openai

import (
	"bytes"
	"cmp"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/crowl/limes/internal/proxy"
)

const (
	oauthTokenURL   = "https://auth.openai.com/oauth/token"
	codexClientID   = "app_EMoamEEZ73f0CkXaXp7hrann"
	refreshMargin   = 5 * time.Minute
	refreshFallback = 55 * time.Minute

	chatGPTResponsesURL = "https://chatgpt.com/backend-api/codex/responses"
)

type storedTokens struct {
	IDToken      string `json:"id_token,omitempty"`
	AccessToken  string `json:"access_token,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	AccountID    string `json:"account_id,omitempty"`
}

type authFile struct {
	Tokens      storedTokens
	LastRefresh string
	fields      map[string]json.RawMessage
}

type subscriptionCredentials struct {
	path     string
	file     *authFile
	store    authStore
	client   *http.Client
	tokenURL string
	now      func() time.Time

	mu sync.Mutex
}

func findSubscriptionCredentials(getenv func(string) string) (string, *authFile, error) {
	return findSubscriptionCredentialsAt(getenv, time.Now())
}

func findSubscriptionCredentialsAt(getenv func(string) string, now time.Time) (string, *authFile, error) {
	store := newAuthStore()
	var candidateErr error
	for _, path := range authFileCandidates(getenv) {
		file, err := store.read(path)
		if err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				candidateErr = err
			}
			continue
		}
		if err := validateAuthFile(file, now); err != nil {
			candidateErr = err
			continue
		}
		return path, file, nil
	}
	if candidateErr != nil {
		return "", nil, fmt.Errorf("load subscription credentials: %w", candidateErr)
	}
	return "", nil, errNoSubscriptionCredentials
}

func authFileCandidates(getenv func(string) string) []string {
	var candidates []string
	if home := getenv("CODEX_HOME"); home != "" {
		candidates = append(candidates, filepath.Join(home, "auth.json"))
	}
	if home := getenv("CHATGPT_LOCAL_HOME"); home != "" {
		candidates = append(candidates, filepath.Join(home, "auth.json"))
	}
	if home := getenv("HOME"); home != "" {
		candidates = append(candidates,
			filepath.Join(home, ".codex", "auth.json"),
			filepath.Join(home, ".chatgpt-local", "auth.json"),
		)
	}
	return candidates
}

func validateAuthFile(file *authFile, now time.Time) error {
	if file == nil || file.Tokens.AccessToken == "" {
		return errors.New("access token is missing")
	}
	if accountID(file.Tokens) == "" {
		return errors.New("account ID is missing")
	}
	if tokenNeedsRefresh(file, now) && file.Tokens.RefreshToken == "" {
		return errors.New("refresh token is missing")
	}
	return nil
}

func accountID(tokens storedTokens) string {
	if tokens.AccountID != "" {
		return tokens.AccountID
	}
	if _, accountID, err := parseJWTClaims(tokens.IDToken); err == nil && accountID != "" {
		return accountID
	}
	_, accountID, _ := parseJWTClaims(tokens.AccessToken)
	return accountID
}

func parseJWTClaims(token string) (int64, string, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return 0, "", errors.New("invalid JWT format")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		payload, err = base64.URLEncoding.DecodeString(parts[1])
	}
	if err != nil {
		return 0, "", fmt.Errorf("decode JWT claims: %w", err)
	}

	var claims struct {
		ExpiresAt int64 `json:"exp"`
		Auth      struct {
			AccountID string `json:"chatgpt_account_id"`
		} `json:"https://api.openai.com/auth"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return 0, "", fmt.Errorf("parse unverified JWT claims: %w", err)
	}
	return claims.ExpiresAt, claims.Auth.AccountID, nil
}

func tokenNeedsRefresh(file *authFile, now time.Time) bool {
	if file == nil || file.Tokens.AccessToken == "" {
		return true
	}
	if expiresAt, _, err := parseJWTClaims(file.Tokens.AccessToken); err == nil && expiresAt > 0 {
		return !now.Add(refreshMargin).Before(time.Unix(expiresAt, 0))
	}
	if file.LastRefresh == "" {
		return true
	}
	lastRefresh, err := time.Parse(time.RFC3339, file.LastRefresh)
	return err != nil || now.Sub(lastRefresh) >= refreshFallback
}

func newSubscriptionCredentials(path string, file *authFile) *subscriptionCredentials {
	return &subscriptionCredentials{
		path:  path,
		file:  file,
		store: newAuthStore(),
		client: &http.Client{
			Timeout: 30 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		tokenURL: oauthTokenURL,
		now:      time.Now,
	}
}

func (credentials *subscriptionCredentials) tokens(ctx context.Context) (storedTokens, error) {
	credentials.mu.Lock()
	defer credentials.mu.Unlock()

	if !tokenNeedsRefresh(credentials.file, credentials.now()) {
		tokens := credentials.file.Tokens
		tokens.AccountID = accountID(tokens)
		return tokens, nil
	}
	if credentials.file.Tokens.RefreshToken == "" {
		return storedTokens{}, errors.New("refresh token is missing")
	}

	updated, err := credentials.refresh(ctx, credentials.file.Tokens)
	if err != nil {
		return storedTokens{}, err
	}
	updatedFile := &authFile{
		Tokens:      updated,
		LastRefresh: credentials.now().UTC().Format(time.RFC3339),
		fields:      credentials.file.fields,
	}
	if err := credentials.store.write(credentials.path, updatedFile); err != nil {
		return storedTokens{}, fmt.Errorf("persist refreshed credentials: %w", err)
	}
	credentials.file = updatedFile
	return updated, nil
}

func (credentials *subscriptionCredentials) refresh(ctx context.Context, previous storedTokens) (storedTokens, error) {
	payload, err := json.Marshal(map[string]string{
		"grant_type":    "refresh_token",
		"refresh_token": previous.RefreshToken,
		"client_id":     codexClientID,
		"scope":         "openid profile email offline_access",
	})
	if err != nil {
		return storedTokens{}, fmt.Errorf("encode OAuth refresh request: %w", err)
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodPost, credentials.tokenURL, bytes.NewReader(payload))
	if err != nil {
		return storedTokens{}, fmt.Errorf("create OAuth refresh request: %w", err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Accept-Language", "en-US,en;q=0.9")
	request.Header.Set("User-Agent", subscriptionUserAgent)

	response, err := credentials.client.Do(request)
	if err != nil {
		return storedTokens{}, fmt.Errorf("refresh OAuth credentials: %w", err)
	}
	defer func() { _ = response.Body.Close() }()

	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4<<10))
		return storedTokens{}, fmt.Errorf("OAuth refresh returned status %d", response.StatusCode)
	}

	var refreshed storedTokens
	decoder := json.NewDecoder(io.LimitReader(response.Body, 1<<20))
	if err := decoder.Decode(&refreshed); err != nil {
		return storedTokens{}, fmt.Errorf("decode OAuth refresh response: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		if err == nil {
			return storedTokens{}, errors.New("OAuth refresh response contains multiple JSON values")
		}
		return storedTokens{}, fmt.Errorf("decode OAuth refresh response: %w", err)
	}
	if refreshed.AccessToken == "" {
		return storedTokens{}, errors.New("OAuth refresh response did not contain an access token")
	}
	refreshed.RefreshToken = cmp.Or(refreshed.RefreshToken, previous.RefreshToken)
	refreshed.AccountID = cmp.Or(accountID(refreshed), accountID(previous))
	if refreshed.AccountID == "" {
		return storedTokens{}, errors.New("OAuth refresh response did not resolve an account ID")
	}
	return refreshed, nil
}

const subscriptionUserAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"

func newSubscriptionProxy(path string, file *authFile) (http.Handler, error) {
	target, err := url.Parse(chatGPTResponsesURL)
	if err != nil {
		return nil, fmt.Errorf("parse ChatGPT Responses URL: %w", err)
	}
	credentials := newSubscriptionCredentials(path, file)
	return newSubscriptionProxyWithDependencies(credentials, target, proxy.NewTransport()), nil
}

func newSubscriptionProxyWithDependencies(credentials *subscriptionCredentials, target *url.URL, transport http.RoundTripper) http.Handler {
	proxy := &httputil.ReverseProxy{
		Rewrite: func(request *httputil.ProxyRequest) {
			request.SetURL(target)
			request.Out.URL.Path = target.Path
			request.Out.URL.RawPath = target.RawPath
			request.Out.URL.RawQuery = ""
			request.Out.URL.ForceQuery = false
		},
		Transport: subscriptionTransport{
			credentials: credentials,
			next:        transport,
		},
		FlushInterval: -1,
		ErrorHandler: func(w http.ResponseWriter, request *http.Request, err error) {
			slog.Error("OpenAI subscription upstream request failed",
				"method", request.Method,
				"path", request.URL.Path,
				"error_type", fmt.Sprintf("%T", err),
			)
			http.Error(w, "upstream request failed", http.StatusBadGateway)
		},
	}

	return http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if !openAISubscriptionRouteAllowed(request.Method, request.URL.Path) {
			http.Error(w, "endpoint not allowed", http.StatusForbidden)
			return
		}
		proxy.ServeHTTP(w, request)
	})
}

type subscriptionTransport struct {
	credentials *subscriptionCredentials
	next        http.RoundTripper
}

func (transport subscriptionTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	tokens, err := transport.credentials.tokens(request.Context())
	if err != nil {
		return nil, fmt.Errorf("subscription authentication unavailable: %w", err)
	}

	outbound := request.Clone(request.Context())
	removeCredentialHeaders(outbound.Header)
	outbound.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
	outbound.Header.Set("chatgpt-account-id", tokens.AccountID)
	outbound.Header.Set("OpenAI-Beta", "responses=experimental")
	outbound.Header.Set("Origin", "https://chatgpt.com")
	outbound.Header.Set("Referer", "https://chatgpt.com")
	outbound.Header.Set("User-Agent", subscriptionUserAgent)
	outbound.Header.Set("Accept", "text/event-stream, application/json, */*")
	outbound.Header.Set("Accept-Language", "en-US,en;q=0.9")
	return transport.next.RoundTrip(outbound)
}

func openAISubscriptionRouteAllowed(method, path string) bool {
	return method == http.MethodPost && path == "/v1/responses"
}

func removeCredentialHeaders(headers http.Header) {
	for _, name := range []string{
		"Authorization",
		"OpenAI-Organization",
		"OpenAI-Project",
		"x-api-key",
		"x-goog-api-key",
		"chatgpt-account-id",
		"x-chatgpt-account-id",
		"OpenAI-Account-ID",
		"x-openai-account-id",
	} {
		headers.Del(name)
	}
}

// Available constructs the fixed OpenAI subscription backend when valid local
// subscription credentials can be discovered.
func Available(getenv func(string) string) (http.Handler, bool, error) {
	path, file, err := findSubscriptionCredentials(getenv)
	if errors.Is(err, errNoSubscriptionCredentials) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	handler, err := newSubscriptionProxy(path, file)
	return handler, err == nil, err
}
