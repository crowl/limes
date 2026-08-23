package openai

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRefreshRejectsTrailingJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, err := io.WriteString(w, `{"access_token":"token"} malformed`)
		if err != nil {
			t.Error(err)
			return
		}
	}))
	defer server.Close()
	credentials := newSubscriptionCredentials("unused", &authFile{})
	credentials.tokenURL = server.URL
	_, err := credentials.refresh(t.Context(), storedTokens{RefreshToken: "refresh", AccountID: "account"})
	if err == nil || !strings.Contains(err.Error(), "decode OAuth refresh response") {
		t.Fatalf("refresh() error = %v", err)
	}
}

func TestAuthStoreReadRejectsOversizedFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "auth.json")
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(maxAuthFileSize + 1); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}

	_, err = newAuthStore().read(path)
	if err == nil || !strings.Contains(err.Error(), "exceeds 1 MiB") {
		t.Fatalf("read() error = %v", err)
	}
}

func TestAuthStoreWritePreservesFieldsAndMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "auth.json")
	store := newAuthStore()
	file := &authFile{Tokens: storedTokens{AccessToken: "new", RefreshToken: "refresh", AccountID: "account"}, LastRefresh: "2025-01-01T00:00:00Z", fields: map[string]json.RawMessage{"auth_mode": json.RawMessage(`"chatgpt"`), "OPENAI_API_KEY": json.RawMessage(`"preserved"`)}}
	if err := store.write(path, file); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %o", info.Mode().Perm())
	}
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(contents, &fields); err != nil {
		t.Fatal(err)
	}
	if string(fields["auth_mode"]) != `"chatgpt"` || string(fields["OPENAI_API_KEY"]) != `"preserved"` || !strings.Contains(string(fields["tokens"]), `"access_token": "new"`) || string(fields["last_refresh"]) != `"2025-01-01T00:00:00Z"` {
		t.Fatalf("stored fields = %s", contents)
	}
	matches, err := filepath.Glob(filepath.Join(filepath.Dir(path), ".auth.json.tmp-*"))
	if err != nil || len(matches) != 0 {
		t.Fatalf("temporary files = %v, %v", matches, err)
	}
}

func TestTokensDoesNotReplaceMemoryWhenPersistenceFails(t *testing.T) {
	previous := storedTokens{AccessToken: jwtForTest(1, "account"), RefreshToken: "old", AccountID: "account"}
	credentials := newSubscriptionCredentials(filepath.Join(t.TempDir(), "auth.json"), &authFile{Tokens: previous, fields: map[string]json.RawMessage{}})
	credentials.now = func() time.Time { return time.Unix(100, 0) }
	credentials.store.rename = func(string, string) error { return errors.New("rename failed") }
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if _, err := io.WriteString(w, `{"access_token":"`+jwtForTest(4102444800, "account")+`"}`); err != nil {
			t.Error(err)
		}
	}))
	defer server.Close()
	credentials.tokenURL = server.URL
	_, err := credentials.tokens(t.Context())
	if err == nil || !strings.Contains(err.Error(), "persist refreshed credentials") {
		t.Fatalf("tokens() error = %v", err)
	}
	if credentials.file.Tokens != previous {
		t.Fatalf("in-memory tokens = %#v, want %#v", credentials.file.Tokens, previous)
	}
}

func TestSubscriptionProxyRewritesAndSanitizes(t *testing.T) {
	var got *http.Request
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		got = request.Clone(request.Context())
		body, err := io.ReadAll(request.Body)
		if err != nil {
			t.Error(err)
			return
		}
		if string(body) != "request body" {
			t.Errorf("body = %q", body)
		}
		w.Header().Set("X-Upstream", "safe")
		w.WriteHeader(http.StatusCreated)
		if _, err := io.WriteString(w, "response body"); err != nil {
			t.Error(err)
		}
	}))
	defer upstream.Close()
	target, err := url.Parse(upstream.URL + "/backend-api/codex/responses")
	if err != nil {
		t.Fatal(err)
	}
	credentials := newSubscriptionCredentials("unused", &authFile{Tokens: storedTokens{AccessToken: jwtForTest(4102444800, "account"), AccountID: "account"}})
	handler := newSubscriptionProxyWithDependencies(credentials, target, http.DefaultTransport)
	server := httptest.NewServer(handler)
	defer server.Close()
	request, err := http.NewRequestWithContext(t.Context(), http.MethodPost, server.URL+"/v1/responses?attacker=yes", strings.NewReader("request body"))
	if err != nil {
		t.Fatal(err)
	}
	request.Host = "attacker.test"
	request.Header.Set("Authorization", "Bearer attacker")
	request.Header.Set("chatgpt-account-id", "attacker")
	request.Header.Set("OpenAI-Organization", "attacker-org")
	request.Header.Set("OpenAI-Project", "attacker-project")
	request.Header.Set("x-api-key", "attacker-key")
	request.Header.Set("x-goog-api-key", "attacker-google-key")
	request.Header.Set("x-chatgpt-account-id", "attacker-alt")
	request.Header.Set("OpenAI-Account-ID", "attacker-openai-account")
	request.Header.Set("x-openai-account-id", "attacker-openai-alt")
	request.Header.Set("X-Forwarded-Host", "attacker.test")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	closeErr := response.Body.Close()
	if err != nil || closeErr != nil {
		t.Fatalf("read/close response: %v, %v", err, closeErr)
	}
	if response.StatusCode != http.StatusCreated || response.Header.Get("X-Upstream") != "safe" || string(body) != "response body" {
		t.Fatalf("response = %d %q %q", response.StatusCode, response.Header, body)
	}
	if got == nil || got.URL.Path != "/backend-api/codex/responses" || got.URL.RawQuery != "" || got.Header.Get("Authorization") != "Bearer "+credentials.file.Tokens.AccessToken || got.Header.Get("chatgpt-account-id") != "account" || got.Header.Get("OpenAI-Beta") != "responses=experimental" || got.Header.Get("Origin") != "https://chatgpt.com" || got.Header.Get("Referer") != "https://chatgpt.com" || got.Header.Get("User-Agent") != subscriptionUserAgent || got.Header.Get("Accept") != "text/event-stream, application/json, */*" || got.Header.Get("Accept-Language") != "en-US,en;q=0.9" || got.Header.Get("X-Forwarded-Host") != "" || got.Header.Get("OpenAI-Organization") != "" || got.Header.Get("OpenAI-Project") != "" || got.Header.Get("x-api-key") != "" || got.Header.Get("x-goog-api-key") != "" || got.Header.Get("x-chatgpt-account-id") != "" || got.Header.Get("OpenAI-Account-ID") != "" || got.Header.Get("x-openai-account-id") != "" {
		t.Fatalf("outbound request = %#v", got)
	}
}

func TestSubscriptionProxyHidesOAuthFailure(t *testing.T) {
	const secret = "oauth-transport-secret"
	credentials := newSubscriptionCredentials("unused", &authFile{Tokens: storedTokens{AccessToken: "expired-token", RefreshToken: secret, AccountID: "account"}, fields: map[string]json.RawMessage{}})
	credentials.now = func() time.Time { return time.Unix(100, 0) }
	credentials.client = &http.Client{Transport: openAIRoundTripper(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("OAuth failed with " + secret)
	})}
	target, err := url.Parse("http://upstream.test/backend-api/codex/responses")
	if err != nil {
		t.Fatal(err)
	}
	handler := newSubscriptionProxyWithDependencies(credentials, target, openAIRoundTripper(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("upstream must not be contacted")
	}))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "http://proxy/v1/responses", nil))
	if response.Code != http.StatusBadGateway || response.Body.String() != "upstream request failed\n" || strings.Contains(response.Body.String(), secret) || strings.Contains(response.Body.String(), "OAuth failed") {
		t.Fatalf("response = %d %q", response.Code, response.Body.String())
	}
}
func TestSubscriptionProxyHidesCredentialFailure(t *testing.T) {
	credentials := newSubscriptionCredentials("unused", &authFile{Tokens: storedTokens{AccessToken: "expired-token", RefreshToken: "refresh-secret", AccountID: "account"}, fields: map[string]json.RawMessage{}})
	credentials.now = func() time.Time { return time.Unix(100, 0) }
	credentials.store.rename = func(string, string) error { return errors.New("persist raw upstream token") }
	credentials.client = &http.Client{Transport: openAIRoundTripper(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{"access_token":"new-token"}`)), Header: make(http.Header)}, nil
	})}
	target, err := url.Parse("http://upstream.test/backend-api/codex/responses")
	if err != nil {
		t.Fatal(err)
	}
	handler := newSubscriptionProxyWithDependencies(credentials, target, openAIRoundTripper(func(*http.Request) (*http.Response, error) {
		t.Error("upstream should not be contacted")
		return nil, errors.New("upstream should not be contacted")
	}))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "http://proxy/v1/responses", nil))
	if response.Code != http.StatusBadGateway || !strings.Contains(response.Body.String(), "upstream request failed") || strings.Contains(response.Body.String(), "refresh-secret") || strings.Contains(response.Body.String(), "new-token") || strings.Contains(response.Body.String(), "persist raw") {
		t.Fatalf("response = %d %q", response.Code, response.Body.String())
	}
}

func TestSubscriptionProxyRejectsOtherRoutesBeforeTransport(t *testing.T) {
	calls := 0
	target, err := url.Parse("http://upstream.test/backend-api/codex/responses")
	if err != nil {
		t.Fatal(err)
	}
	credentials := newSubscriptionCredentials("unused", &authFile{Tokens: storedTokens{AccessToken: "opaque", AccountID: "account"}, LastRefresh: time.Now().Format(time.RFC3339)})
	handler := newSubscriptionProxyWithDependencies(credentials, target, openAIRoundTripper(func(*http.Request) (*http.Response, error) { calls++; return nil, nil }))
	for _, path := range []string{"/v1/responses/", "/v1/responses/input_tokens"} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "http://proxy"+path, nil))
		if response.Code != http.StatusForbidden {
			t.Fatalf("%s status = %d", path, response.Code)
		}
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "http://proxy/v1/responses", nil))
	if response.Code != http.StatusForbidden || calls != 0 {
		t.Fatalf("GET status = %d, calls = %d", response.Code, calls)
	}
}

func TestSubscriptionProxyStreamsFlushedResponse(t *testing.T) {
	firstFlushed := make(chan struct{})
	releaseSecond := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		if _, err := io.WriteString(w, "first\n"); err != nil {
			t.Error(err)
			return
		}
		w.(http.Flusher).Flush()
		close(firstFlushed)
		select {
		case <-releaseSecond:
		case <-t.Context().Done():
			return
		}
		if _, err := io.WriteString(w, "second\n"); err != nil {
			t.Error(err)
			return
		}
		w.(http.Flusher).Flush()
	}))
	defer upstream.Close()
	target, err := url.Parse(upstream.URL + "/backend-api/codex/responses")
	if err != nil {
		t.Fatal(err)
	}
	credentials := newSubscriptionCredentials("unused", &authFile{Tokens: storedTokens{AccessToken: jwtForTest(4102444800, "account"), AccountID: "account"}})
	server := httptest.NewServer(newSubscriptionProxyWithDependencies(credentials, target, http.DefaultTransport))
	defer server.Close()
	request, err := http.NewRequestWithContext(context.Background(), http.MethodPost, server.URL+"/v1/responses", nil)
	if err != nil {
		t.Fatal(err)
	}
	responseResult := make(chan struct {
		response *http.Response
		err      error
	}, 1)
	go func() {
		response, err := (&http.Client{Timeout: time.Second}).Do(request)
		responseResult <- struct {
			response *http.Response
			err      error
		}{response, err}
	}()
	select {
	case <-firstFlushed:
	case <-time.After(time.Second):
		t.Fatal("upstream did not flush the first event")
	}
	result := <-responseResult
	if result.err != nil {
		t.Fatal(result.err)
	}
	response := result.response
	defer response.Body.Close()
	reader := bufio.NewReader(response.Body)
	first, err := reader.ReadString('\n')
	if err != nil || first != "first\n" {
		t.Fatalf("first event = %q, %v", first, err)
	}
	close(releaseSecond)
	second, err := reader.ReadString('\n')
	if err != nil || second != "second\n" {
		t.Fatalf("second event = %q, %v", second, err)
	}
}

type openAIRoundTripper func(*http.Request) (*http.Response, error)

func (fn openAIRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	return fn(request)
}
