package xai

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
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/crowl/limes/internal/proxy"
)

const (
	xaiIssuer       = "https://auth.x.ai"
	grokClientID    = "b1a00492-073a-47ea-816f-4c329264a828"
	xaiAuthEntryKey = xaiIssuer + "::" + grokClientID
	xaiTokenURL     = xaiIssuer + "/oauth2/token"
	xaiResponsesURL = "https://cli-chat-proxy.grok.com/v1/responses"

	grokClientVersion  = "1.0.13"
	refreshMargin      = 5 * time.Minute
	maxRequestBodySize = 16 << 20
)

type tokenReply struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
	ExpiresIn    int64  `json:"expires_in"`
}

type subscriptionCredentials struct {
	path     string
	file     *authFile
	store    authStore
	client   *http.Client
	tokenURL string
	now      func() time.Time

	mu           sync.Mutex
	forceRefresh bool
}

type modelContextKey struct{}

func findSubscriptionCredentials(getenv func(string) string) (string, *authFile, error) {
	return findSubscriptionCredentialsAt(getenv, time.Now())
}

func findSubscriptionCredentialsAt(getenv func(string) string, now time.Time) (string, *authFile, error) {
	path := authFilePath(getenv)
	if path == "" {
		return "", nil, errNoSubscriptionCredentials
	}
	file, err := newAuthStore().read(path)
	if errors.Is(err, os.ErrNotExist) {
		return "", nil, errNoSubscriptionCredentials
	}
	if err != nil {
		return "", nil, fmt.Errorf("load subscription credentials: %w", err)
	}
	if err := validateAuthFile(file, now); err != nil {
		return "", nil, fmt.Errorf("validate subscription credentials: %w", err)
	}
	return path, file, nil
}

func authFilePath(getenv func(string) string) string {
	if home := getenv("GROK_HOME"); home != "" {
		return filepath.Join(home, "auth.json")
	}
	if home := getenv("HOME"); home != "" {
		return filepath.Join(home, ".grok", "auth.json")
	}
	return ""
}

func validateAuthFile(file *authFile, now time.Time) error {
	if file == nil || file.Entry.AccessToken == "" {
		return errors.New("access token is missing")
	}
	if file.Entry.UserID == "" {
		return errors.New("user ID is missing")
	}
	if tokenNeedsRefresh(file.Entry, now) && file.Entry.RefreshToken == "" {
		return errors.New("refresh token is missing")
	}
	return nil
}

func tokenNeedsRefresh(entry authEntry, now time.Time) bool {
	return entry.ExpiresAt.IsZero() || !now.Add(refreshMargin).Before(entry.ExpiresAt)
}

func jwtExpiry(token string) time.Time {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return time.Time{}
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		payload, err = base64.URLEncoding.DecodeString(parts[1])
	}
	if err != nil {
		return time.Time{}
	}
	var claims struct {
		ExpiresAt int64 `json:"exp"`
	}
	if json.Unmarshal(payload, &claims) != nil || claims.ExpiresAt <= 0 {
		return time.Time{}
	}
	return time.Unix(claims.ExpiresAt, 0)
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
		tokenURL: xaiTokenURL,
		now:      time.Now,
	}
}

func (credentials *subscriptionCredentials) token(ctx context.Context) (authEntry, error) {
	credentials.mu.Lock()
	defer credentials.mu.Unlock()

	if disk, err := credentials.store.read(credentials.path); err == nil && (disk.Entry.AccessToken != credentials.file.Entry.AccessToken || disk.Entry.RefreshToken != credentials.file.Entry.RefreshToken || disk.Entry.ExpiresAt.After(credentials.file.Entry.ExpiresAt)) {
		credentials.file = disk
		credentials.forceRefresh = false
	}
	if !credentials.forceRefresh && !tokenNeedsRefresh(credentials.file.Entry, credentials.now()) {
		return credentials.file.Entry, nil
	}
	if credentials.file.Entry.RefreshToken == "" {
		return authEntry{}, errors.New("refresh token is missing")
	}

	refreshed, err := credentials.refresh(ctx, credentials.file.Entry)
	if err != nil {
		return authEntry{}, err
	}
	updated, err := refreshedAuthFile(credentials.file, refreshed, credentials.now())
	if err != nil {
		return authEntry{}, err
	}
	if err := credentials.store.write(credentials.path, updated); err != nil {
		return authEntry{}, fmt.Errorf("persist refreshed credentials: %w", err)
	}
	credentials.file = updated
	credentials.forceRefresh = false
	return updated.Entry, nil
}

func (credentials *subscriptionCredentials) reject(accessToken string) {
	credentials.mu.Lock()
	defer credentials.mu.Unlock()
	if credentials.file.Entry.AccessToken == accessToken {
		credentials.forceRefresh = true
	}
}

func (credentials *subscriptionCredentials) refresh(ctx context.Context, previous authEntry) (tokenReply, error) {
	form := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {previous.RefreshToken},
		"client_id":     {grokClientID},
	}
	if previous.PrincipalType != "" {
		form.Set("principal_type", previous.PrincipalType)
	}
	if previous.PrincipalID != "" {
		form.Set("principal_id", previous.PrincipalID)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, credentials.tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return tokenReply{}, fmt.Errorf("create OAuth refresh request: %w", err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Accept", "application/json")

	response, err := credentials.client.Do(request)
	if err != nil {
		return tokenReply{}, fmt.Errorf("refresh OAuth credentials: %w", err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4<<10))
		return tokenReply{}, fmt.Errorf("OAuth refresh returned status %d", response.StatusCode)
	}

	var refreshed tokenReply
	decoder := json.NewDecoder(io.LimitReader(response.Body, maxAuthFileSize+1))
	if err := decoder.Decode(&refreshed); err != nil {
		return tokenReply{}, fmt.Errorf("decode OAuth refresh response: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		if err == nil {
			return tokenReply{}, errors.New("OAuth refresh response contains multiple JSON values")
		}
		return tokenReply{}, fmt.Errorf("decode OAuth refresh response: %w", err)
	}
	if refreshed.AccessToken == "" {
		return tokenReply{}, errors.New("OAuth refresh response did not contain an access token")
	}
	refreshed.RefreshToken = cmp.Or(refreshed.RefreshToken, previous.RefreshToken)
	return refreshed, nil
}

func newSubscriptionProxy(path string, file *authFile) (http.Handler, error) {
	target, err := url.Parse(xaiResponsesURL)
	if err != nil {
		return nil, fmt.Errorf("parse xAI Responses URL: %w", err)
	}
	return newSubscriptionProxyWithDependencies(newSubscriptionCredentials(path, file), target, proxy.NewTransport()), nil
}

func newSubscriptionProxyWithDependencies(credentials *subscriptionCredentials, target *url.URL, transport http.RoundTripper) http.Handler {
	reverseProxy := &httputil.ReverseProxy{
		Rewrite: func(request *httputil.ProxyRequest) {
			request.SetURL(target)
			request.Out.URL.Path = target.Path
			request.Out.URL.RawPath = target.RawPath
			request.Out.URL.RawQuery = ""
			request.Out.URL.ForceQuery = false
		},
		Transport:     subscriptionTransport{credentials: credentials, next: transport},
		FlushInterval: -1,
		ErrorHandler: func(w http.ResponseWriter, request *http.Request, err error) {
			slog.Error("xAI subscription upstream request failed",
				"method", request.Method,
				"path", request.URL.Path,
				"error_type", fmt.Sprintf("%T", err),
			)
			http.Error(w, "upstream request failed", http.StatusBadGateway)
		},
	}

	return http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.URL.Path != "/v1/responses" {
			http.Error(w, "endpoint not allowed", http.StatusForbidden)
			return
		}
		model, body, status, err := readRequestModel(request.Body)
		if err != nil {
			http.Error(w, err.Error(), status)
			return
		}
		request.Body = io.NopCloser(bytes.NewReader(body))
		request.ContentLength = int64(len(body))
		request = request.WithContext(context.WithValue(request.Context(), modelContextKey{}, model))
		reverseProxy.ServeHTTP(w, request)
	})
}

func readRequestModel(body io.Reader) (string, []byte, int, error) {
	if body == nil {
		return "", nil, http.StatusBadRequest, errors.New("request body must be a JSON object")
	}
	contents, err := io.ReadAll(io.LimitReader(body, maxRequestBodySize+1))
	if err != nil {
		return "", nil, http.StatusBadRequest, errors.New("could not read request body")
	}
	if len(contents) > maxRequestBodySize {
		return "", nil, http.StatusRequestEntityTooLarge, errors.New("request body exceeds 16 MiB")
	}
	var request struct {
		Model string `json:"model"`
	}
	decoder := json.NewDecoder(bytes.NewReader(contents))
	if err := decoder.Decode(&request); err != nil {
		return "", nil, http.StatusBadRequest, errors.New("request body must be a JSON object")
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return "", nil, http.StatusBadRequest, errors.New("request body must contain one JSON value")
	}
	request.Model = strings.TrimSpace(request.Model)
	if request.Model == "" {
		return "", nil, http.StatusBadRequest, errors.New("request model is required")
	}
	if !validHeaderValue(request.Model) {
		return "", nil, http.StatusBadRequest, errors.New("request model contains invalid characters")
	}
	return request.Model, contents, 0, nil
}

func validHeaderValue(value string) bool {
	for i := range len(value) {
		if value[i] < 0x20 || value[i] == 0x7f {
			return false
		}
	}
	return true
}

type subscriptionTransport struct {
	credentials *subscriptionCredentials
	next        http.RoundTripper
}

func (transport subscriptionTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	entry, err := transport.credentials.token(request.Context())
	if err != nil {
		return nil, fmt.Errorf("subscription authentication unavailable: %w", err)
	}
	model, _ := request.Context().Value(modelContextKey{}).(string)
	if model == "" {
		return nil, errors.New("xAI subscription model is missing")
	}

	outbound := request.Clone(request.Context())
	removeCredentialHeaders(outbound.Header)
	outbound.Header.Set("Authorization", "Bearer "+entry.AccessToken)
	outbound.Header.Set("X-XAI-Token-Auth", "xai-grok-cli")
	outbound.Header.Set("x-authenticateresponse", "authenticate-response")
	outbound.Header.Set("x-grok-model-override", model)
	outbound.Header.Set("x-grok-client-version", grokClientVersion)
	outbound.Header.Set("x-grok-client-identifier", "grok-shell")
	outbound.Header.Set("x-grok-client-surface", "headless")
	outbound.Header.Set("x-grok-client-mode", "headless")
	outbound.Header.Set("x-userid", entry.UserID)
	outbound.Header.Set("x-grok-user-id", entry.UserID)
	outbound.Header.Set("User-Agent", grokUserAgent())
	outbound.Header.Set("Accept", "text/event-stream, application/json")

	response, err := transport.next.RoundTrip(outbound)
	if err == nil && response.StatusCode == http.StatusUnauthorized {
		transport.credentials.reject(entry.AccessToken)
	}
	return response, err
}

func removeCredentialHeaders(headers http.Header) {
	for name := range headers {
		lower := strings.ToLower(name)
		if strings.HasPrefix(lower, "x-grok-") || lower == "authorization" || lower == "x-api-key" || lower == "api-key" || lower == "x-xai-token-auth" || lower == "x-authenticateresponse" || lower == "x-userid" || lower == "x-email" {
			headers.Del(name)
		}
	}
}

func grokUserAgent() string {
	operatingSystem := runtime.GOOS
	if operatingSystem == "darwin" {
		operatingSystem = "macos"
	}
	architecture := runtime.GOARCH
	if architecture == "arm64" {
		architecture = "aarch64"
	}
	return fmt.Sprintf("grok-shell/%s (%s; %s)", grokClientVersion, operatingSystem, architecture)
}

// Available constructs the fixed xAI subscription backend when valid official
// Grok CLI credentials can be discovered.
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
