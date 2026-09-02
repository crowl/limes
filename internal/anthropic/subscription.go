package anthropic

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/crowl/limes/internal/proxy"
)

// InterceptedHost is the host clients address to reach this backend through
// the Limes proxy.
const InterceptedHost = "api.anthropic.com"

const (
	inferenceScope = "user:inference"
	oauthClientID  = "9d1c250a-e61b-44d9-88ed-5944d1962f5e"
	oauthTokenURL  = "https://platform.claude.com/v1/oauth/token"
	messagesURL    = "https://api.anthropic.com/v1/messages"

	oauthBeta             = "oauth-2025-04-20"
	claudeCodeBeta        = "claude-code-20250219"
	anthropicVersion      = "2023-06-01"
	claudeCodeVersion     = "2.1.257.3fb"
	claudeCodeEntrypoint  = "sdk-cli"
	billingHeaderPrefix   = "x-anthropic-billing-header:"
	maxRequestBodySize    = 16 << 20
	refreshMargin         = 5 * time.Minute
	diagnosticCaptureSize = 1 << 20
)

var nowTime = time.Now
var diagnosticSequence atomic.Uint64

var refreshScopes = []string{
	"user:profile",
	inferenceScope,
	"user:sessions:claude_code",
	"user:mcp_servers",
}

type tokenReply struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int64  `json:"expires_in"`
	Scope        string `json:"scope"`
}

type subscriptionCredentials struct {
	store    credentialStore
	file     *credentialFile
	client   *http.Client
	tokenURL string
	now      func() time.Time

	mu           sync.Mutex
	forceRefresh bool
}

func tokenNeedsRefresh(credential oauthCredential, now time.Time) bool {
	if credential.ExpiresAt <= 0 {
		return true
	}
	return !now.Add(refreshMargin).Before(time.UnixMilli(credential.ExpiresAt))
}

func hasScope(scopes []string, wanted string) bool {
	for _, scope := range scopes {
		if scope == wanted {
			return true
		}
	}
	return false
}

func newSubscriptionCredentials(store credentialStore, file *credentialFile) *subscriptionCredentials {
	return &subscriptionCredentials{
		store: store,
		file:  file,
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

func (credentials *subscriptionCredentials) token(ctx context.Context) (oauthCredential, error) {
	credentials.mu.Lock()
	defer credentials.mu.Unlock()

	if !credentials.forceRefresh && !tokenNeedsRefresh(credentials.file.OAuth, credentials.now()) {
		return credentials.file.OAuth, nil
	}
	credentials.adoptNewerStoredCredential()
	if !credentials.forceRefresh && !tokenNeedsRefresh(credentials.file.OAuth, credentials.now()) {
		return credentials.file.OAuth, nil
	}
	if credentials.file.OAuth.RefreshToken == "" {
		return oauthCredential{}, errors.New("refresh token is missing")
	}

	refreshed, err := credentials.refresh(ctx, credentials.file.OAuth)
	if err != nil {
		return oauthCredential{}, err
	}
	updated := refreshedCredentialFile(credentials.file, refreshed, credentials.now())
	if err := validateCredentialFileAt(updated, credentials.now()); err != nil {
		return oauthCredential{}, fmt.Errorf("validate refreshed credentials: %w", err)
	}
	if err := credentials.store.write(updated); err != nil {
		return oauthCredential{}, fmt.Errorf("persist refreshed credentials: %w", err)
	}
	credentials.file = updated
	credentials.forceRefresh = false
	return updated.OAuth, nil
}

func (credentials *subscriptionCredentials) adoptNewerStoredCredential() {
	stored, err := credentials.store.read()
	if err != nil || validateCredentialFileAt(stored, credentials.now()) != nil {
		return
	}
	current := credentials.file.OAuth
	candidate := stored.OAuth
	if candidate.AccessToken != current.AccessToken || candidate.RefreshToken != current.RefreshToken || candidate.ExpiresAt > current.ExpiresAt {
		credentials.file = stored
		if candidate.AccessToken != current.AccessToken {
			credentials.forceRefresh = false
		}
	}
}

func (credentials *subscriptionCredentials) reject(accessToken string) {
	credentials.mu.Lock()
	defer credentials.mu.Unlock()
	if credentials.file.OAuth.AccessToken == accessToken {
		credentials.forceRefresh = true
	}
}

func (credentials *subscriptionCredentials) refresh(ctx context.Context, previous oauthCredential) (tokenReply, error) {
	payload, err := json.Marshal(map[string]string{
		"grant_type":    "refresh_token",
		"refresh_token": previous.RefreshToken,
		"client_id":     oauthClientID,
		"scope":         strings.Join(refreshScopes, " "),
	})
	if err != nil {
		return tokenReply{}, fmt.Errorf("encode OAuth refresh request: %w", err)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, credentials.tokenURL, bytes.NewReader(payload))
	if err != nil {
		return tokenReply{}, fmt.Errorf("create OAuth refresh request: %w", err)
	}
	request.Header.Set("Content-Type", "application/json")
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
	decoder := json.NewDecoder(io.LimitReader(response.Body, maxCredentialSize+1))
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
	if refreshed.ExpiresIn <= 0 {
		return tokenReply{}, errors.New("OAuth refresh response did not contain a valid expiry")
	}
	refreshed.RefreshToken = cmp.Or(refreshed.RefreshToken, previous.RefreshToken)
	return refreshed, nil
}

func refreshedCredentialFile(file *credentialFile, reply tokenReply, now time.Time) *credentialFile {
	oauth := file.OAuth
	oauth.AccessToken = reply.AccessToken
	oauth.RefreshToken = reply.RefreshToken
	oauth.ExpiresAt = now.Add(time.Duration(reply.ExpiresIn) * time.Second).UnixMilli()
	if scopes := strings.Fields(reply.Scope); len(scopes) > 0 {
		oauth.Scopes = scopes
	}
	oauth.fields = cloneFields(file.OAuth.fields)
	return &credentialFile{OAuth: oauth, fields: cloneFields(file.fields)}
}

func newSubscriptionProxy(store credentialStore, file *credentialFile) (http.Handler, error) {
	target, err := url.Parse(messagesURL)
	if err != nil {
		return nil, fmt.Errorf("parse Anthropic Messages URL: %w", err)
	}
	return newSubscriptionProxyWithDependencies(newSubscriptionCredentials(store, file), target, proxy.NewTransport()), nil
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
			slog.Error("Anthropic subscription upstream request failed",
				"method", request.Method,
				"path", request.URL.Path,
				"error_type", fmt.Sprintf("%T", err),
			)
			http.Error(w, "upstream request failed", http.StatusBadGateway)
		},
	}
	return http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.URL.Path != "/v1/messages" {
			http.Error(w, "endpoint not allowed", http.StatusForbidden)
			return
		}
		body, status, err := prepareSubscriptionBody(request.Body)
		if err != nil {
			http.Error(w, err.Error(), status)
			return
		}
		request.Body = io.NopCloser(bytes.NewReader(body))
		request.ContentLength = int64(len(body))
		reverseProxy.ServeHTTP(w, request)
	})
}

func prepareSubscriptionBody(body io.Reader) ([]byte, int, error) {
	if body == nil {
		return nil, http.StatusBadRequest, errors.New("request body must be a JSON object")
	}
	contents, err := io.ReadAll(io.LimitReader(body, maxRequestBodySize+1))
	if err != nil {
		return nil, http.StatusBadRequest, errors.New("could not read request body")
	}
	if len(contents) > maxRequestBodySize {
		return nil, http.StatusRequestEntityTooLarge, errors.New("request body exceeds 16 MiB")
	}

	var request map[string]json.RawMessage
	decoder := json.NewDecoder(bytes.NewReader(contents))
	if err := decoder.Decode(&request); err != nil || request == nil {
		return nil, http.StatusBadRequest, errors.New("request body must be a JSON object")
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return nil, http.StatusBadRequest, errors.New("request body must contain one JSON value")
	}

	system, err := subscriptionSystem(request["system"])
	if err != nil {
		return nil, http.StatusBadRequest, err
	}
	request["system"], err = json.Marshal(system)
	if err != nil {
		return nil, http.StatusBadRequest, errors.New("could not encode request system prompt")
	}
	prepared, err := json.Marshal(request)
	if err != nil {
		return nil, http.StatusBadRequest, errors.New("could not encode request body")
	}
	return prepared, 0, nil
}

type systemBlock struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

func subscriptionSystem(encoded json.RawMessage) ([]json.RawMessage, error) {
	attribution, err := json.Marshal(systemBlock{
		Type: "text",
		Text: fmt.Sprintf("%s cc_version=%s; cc_entrypoint=%s;", billingHeaderPrefix, claudeCodeVersion, claudeCodeEntrypoint),
	})
	if err != nil {
		return nil, errors.New("could not encode Anthropic attribution")
	}
	blocks := []json.RawMessage{attribution}
	if len(encoded) == 0 {
		return blocks, nil
	}

	var text string
	if err := json.Unmarshal(encoded, &text); err == nil {
		block, err := json.Marshal(systemBlock{Type: "text", Text: text})
		if err != nil {
			return nil, errors.New("could not encode request system prompt")
		}
		return append(blocks, block), nil
	}

	var existing []json.RawMessage
	if err := json.Unmarshal(encoded, &existing); err != nil {
		return nil, errors.New("request system prompt must be a string or array")
	}
	for _, block := range existing {
		var textBlock systemBlock
		if json.Unmarshal(block, &textBlock) == nil && textBlock.Type == "text" && strings.HasPrefix(textBlock.Text, billingHeaderPrefix) {
			continue
		}
		blocks = append(blocks, block)
	}
	return blocks, nil
}

type subscriptionTransport struct {
	credentials *subscriptionCredentials
	next        http.RoundTripper
}

func (transport subscriptionTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	credential, err := transport.credentials.token(request.Context())
	if err != nil {
		return nil, fmt.Errorf("subscription authentication unavailable: %w", err)
	}
	outbound := request.Clone(request.Context())
	removeCredentialHeaders(outbound.Header)
	outbound.Header.Set("Authorization", "Bearer "+credential.AccessToken)
	outbound.Header.Set("anthropic-version", anthropicVersion)
	betas := append([]string{claudeCodeBeta}, outbound.Header.Values("anthropic-beta")...)
	outbound.Header.Set("anthropic-beta", mergeBetaHeader(betas, oauthBeta))
	outbound.Header.Set("x-app", "cli")

	captureID := diagnosticSequence.Add(1)
	requestBody := newDiagnosticBody(outbound.Body)
	if requestBody != nil {
		outbound.Body = requestBody
	}
	response, err := transport.next.RoundTrip(outbound)
	logDiagnosticRequest(captureID, outbound, requestBody)
	if err != nil {
		slog.Error("Anthropic diagnostic transport error",
			"capture_id", captureID,
			"error_type", fmt.Sprintf("%T", err),
			"error", err,
		)
		return nil, err
	}

	slog.Info("Anthropic diagnostic response",
		"capture_id", captureID,
		"status", response.StatusCode,
		"protocol", response.Proto,
		"headers", redactedDiagnosticHeaders(response.Header),
		"content_length", response.ContentLength,
	)
	response.Body = newDiagnosticResponseBody(captureID, response.Body)
	if response.StatusCode == http.StatusUnauthorized {
		transport.credentials.reject(credential.AccessToken)
	}
	return response, nil
}

type diagnosticCapture struct {
	mu       sync.Mutex
	contents bytes.Buffer
	total    int64
}

func (capture *diagnosticCapture) Write(contents []byte) (int, error) {
	capture.mu.Lock()
	defer capture.mu.Unlock()

	capture.total += int64(len(contents))
	remaining := diagnosticCaptureSize - capture.contents.Len()
	if remaining > 0 {
		_, _ = capture.contents.Write(contents[:min(len(contents), remaining)])
	}
	return len(contents), nil
}

func (capture *diagnosticCapture) snapshot() (string, int64, bool) {
	capture.mu.Lock()
	defer capture.mu.Unlock()
	return capture.contents.String(), capture.total, capture.total > int64(capture.contents.Len())
}

type diagnosticBody struct {
	body     io.ReadCloser
	reader   io.Reader
	capture  *diagnosticCapture
	complete atomic.Bool
}

func newDiagnosticBody(body io.ReadCloser) *diagnosticBody {
	if body == nil {
		return nil
	}
	capture := &diagnosticCapture{}
	return &diagnosticBody{body: body, reader: io.TeeReader(body, capture), capture: capture}
}

func (body *diagnosticBody) Read(contents []byte) (int, error) {
	read, err := body.reader.Read(contents)
	if err == io.EOF {
		body.complete.Store(true)
	}
	return read, err
}

func (body *diagnosticBody) Close() error {
	return body.body.Close()
}

func logDiagnosticRequest(captureID uint64, request *http.Request, body *diagnosticBody) {
	var contents string
	var bodyBytes int64
	var truncated bool
	complete := true
	if body != nil {
		contents, bodyBytes, truncated = body.capture.snapshot()
		complete = body.complete.Load()
	}
	slog.Info("Anthropic diagnostic request",
		"capture_id", captureID,
		"method", request.Method,
		"url", request.URL.String(),
		"host", request.Host,
		"headers", redactedDiagnosticHeaders(request.Header),
		"content_length", request.ContentLength,
		"transfer_encoding", request.TransferEncoding,
		"body", contents,
		"body_bytes", bodyBytes,
		"body_truncated", truncated,
		"body_complete", complete,
	)
}

type diagnosticResponseBody struct {
	body      io.ReadCloser
	reader    io.Reader
	capture   *diagnosticCapture
	captureID uint64
	complete  atomic.Bool
	once      sync.Once
}

func newDiagnosticResponseBody(captureID uint64, body io.ReadCloser) io.ReadCloser {
	if body == nil {
		return nil
	}
	capture := &diagnosticCapture{}
	return &diagnosticResponseBody{
		body:      body,
		reader:    io.TeeReader(body, capture),
		capture:   capture,
		captureID: captureID,
	}
}

func (body *diagnosticResponseBody) Read(contents []byte) (int, error) {
	read, err := body.reader.Read(contents)
	if err == io.EOF {
		body.complete.Store(true)
		body.log()
	}
	return read, err
}

func (body *diagnosticResponseBody) Close() error {
	err := body.body.Close()
	body.log()
	return err
}

func (body *diagnosticResponseBody) log() {
	body.once.Do(func() {
		contents, total, truncated := body.capture.snapshot()
		slog.Info("Anthropic diagnostic response body",
			"capture_id", body.captureID,
			"body", contents,
			"body_bytes", total,
			"body_truncated", truncated,
			"body_complete", body.complete.Load(),
		)
	})
}

func redactedDiagnosticHeaders(headers http.Header) http.Header {
	redacted := headers.Clone()
	for name := range redacted {
		lower := strings.ToLower(name)
		if strings.Contains(lower, "authorization") || strings.Contains(lower, "api-key") || strings.Contains(lower, "token") || strings.Contains(lower, "secret") || lower == "cookie" || lower == "set-cookie" {
			redacted[name] = []string{"[REDACTED]"}
		}
	}
	return redacted
}

func removeCredentialHeaders(headers http.Header) {
	for _, name := range []string{"Authorization", "x-api-key"} {
		headers.Del(name)
	}
}

func mergeBetaHeader(values []string, required string) string {
	features := make([]string, 0, len(values)+1)
	seen := make(map[string]bool)
	for _, value := range values {
		for feature := range strings.SplitSeq(value, ",") {
			feature = strings.TrimSpace(feature)
			if feature != "" && !seen[strings.ToLower(feature)] {
				seen[strings.ToLower(feature)] = true
				features = append(features, feature)
			}
		}
	}
	if !seen[strings.ToLower(required)] {
		features = append(features, required)
	}
	return strings.Join(features, ",")
}

// Available constructs the fixed Anthropic subscription backend when valid
// official Claude Code credentials can be discovered.
func Available(getenv func(string) string) (http.Handler, bool, error) {
	store, file, err := findSubscriptionCredentials(getenv)
	if errors.Is(err, errNoSubscriptionCredentials) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	handler, err := newSubscriptionProxy(store, file)
	return handler, err == nil, err
}
