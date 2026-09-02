package anthropic

import (
	"bytes"
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

func TestFindSubscriptionCredentialsUsesKeychainBeforePlaintext(t *testing.T) {
	configDirectory := t.TempDir()
	writeCredential(t, filepath.Join(configDirectory, ".credentials.json"), testCredentialDocument("file-token", time.Now().Add(time.Hour), []string{inferenceScope}))
	keychainDocument := testCredentialDocument("keychain-token", time.Now().Add(time.Hour), []string{inferenceScope})
	var gotArgs []string
	store, file, err := findSubscriptionCredentialsAt(func(name string) string {
		switch name {
		case "CLAUDE_CONFIG_DIR":
			return configDirectory
		case "USER":
			return "alice"
		default:
			return ""
		}
	}, "darwin", func(args []string, input string) ([]byte, error) {
		gotArgs = append([]string(nil), args...)
		return []byte(keychainDocument), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	digestStore, ok := store.(*keychainStore)
	if !ok || file.OAuth.AccessToken != "keychain-token" || digestStore.account != "alice" || !strings.HasPrefix(digestStore.service, "Claude Code-credentials-") || len(digestStore.service) != len("Claude Code-credentials-")+8 {
		t.Fatalf("credential = %#v, store = %#v", file, store)
	}
	if strings.Join(gotArgs, " ") != "find-generic-password -a alice -s "+digestStore.service+" -w" {
		t.Fatalf("Keychain args = %#v", gotArgs)
	}
}

func TestFindSubscriptionCredentialsFallsBackToPlaintext(t *testing.T) {
	configDirectory := t.TempDir()
	path := filepath.Join(configDirectory, ".credentials.json")
	writeCredential(t, path, testCredentialDocument("file-token", time.Now().Add(time.Hour), []string{inferenceScope}))
	store, file, err := findSubscriptionCredentialsAt(func(name string) string {
		if name == "CLAUDE_CONFIG_DIR" {
			return configDirectory
		}
		return ""
	}, "darwin", func([]string, string) ([]byte, error) { return nil, errors.New("not found") })
	if err != nil {
		t.Fatal(err)
	}
	plain, ok := store.(*plaintextStore)
	if !ok || plain.path != path || file.OAuth.AccessToken != "file-token" {
		t.Fatalf("credential = %#v, store = %#v", file, store)
	}
}

func TestCredentialValidationUsesProvidedTime(t *testing.T) {
	file, err := parseCredentialFile([]byte(testCredentialDocumentWithoutRefresh("token", time.Unix(1000, 0), []string{inferenceScope})))
	if err != nil {
		t.Fatal(err)
	}
	if err := validateCredentialFileAt(file, time.Unix(0, 0)); err != nil {
		t.Fatalf("valid credential rejected: %v", err)
	}
	if err := validateCredentialFileAt(file, time.Unix(1000, 0)); err == nil || !strings.Contains(err.Error(), "refresh token") {
		t.Fatalf("expired credential error = %v", err)
	}
}

func TestAvailableDistinguishesMissingMalformedAndInvalidCredentials(t *testing.T) {
	missing := t.TempDir()
	if handler, available, err := Available(configGetenv(missing)); err != nil || available || handler != nil {
		t.Fatalf("missing Available() = %v, %v, %v", handler, available, err)
	}
	for name, document := range map[string]string{
		"malformed":     `{`,
		"missing token": `{"claudeAiOauth":{"expiresAt":4102444800000,"scopes":["user:inference"]}}`,
		"missing scope": testCredentialDocument("token", time.Now().Add(time.Hour), []string{"user:profile"}),
		"expired":       testCredentialDocumentWithoutRefresh("token", time.Now().Add(-time.Hour), []string{inferenceScope}),
	} {
		t.Run(name, func(t *testing.T) {
			directory := t.TempDir()
			writeCredential(t, filepath.Join(directory, ".credentials.json"), document)
			if _, available, err := Available(configGetenv(directory)); err == nil || available {
				t.Fatalf("Available() = available %v, error %v", available, err)
			}
		})
	}
}

func TestPlaintextStorePreservesFieldsAndMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".credentials.json")
	document := `{"other":{"preserved":true},"claudeAiOauth":{"accessToken":"old","refreshToken":"refresh","expiresAt":1,"scopes":["user:inference"],"custom":"kept"}}`
	writeCredential(t, path, document)
	store := newPlaintextStore(path)
	file, err := store.read()
	if err != nil {
		t.Fatal(err)
	}
	file.OAuth.AccessToken = "new"
	file.OAuth.ExpiresAt = 4102444800000
	if err := store.write(file); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 || !bytes.Contains(contents, []byte(`"preserved": true`)) || !bytes.Contains(contents, []byte(`"custom": "kept"`)) || !bytes.Contains(contents, []byte(`"accessToken": "new"`)) {
		t.Fatalf("mode = %o, contents = %s", info.Mode().Perm(), contents)
	}
}

func TestKeychainStoreWritesViaStandardInput(t *testing.T) {
	var gotArgs []string
	var gotInput string
	store := &keychainStore{service: `Claude Code-credentials`, account: `user`, run: func(args []string, input string) ([]byte, error) {
		gotArgs = append([]string(nil), args...)
		gotInput = input
		return nil, nil
	}}
	file, err := parseCredentialFile([]byte(testCredentialDocument("secret-token", time.Now().Add(time.Hour), []string{inferenceScope})))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.write(file); err != nil {
		t.Fatal(err)
	}
	if strings.Join(gotArgs, " ") != "-i" || !strings.Contains(gotInput, "add-generic-password") || strings.Contains(gotInput, "secret-token") {
		t.Fatalf("args = %#v, input = %q", gotArgs, gotInput)
	}
}

func TestRefreshUsesOfficialClaudeCodeRequest(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		var payload map[string]string
		if err := json.NewDecoder(request.Body).Decode(&payload); err != nil {
			t.Error(err)
		}
		if request.Method != http.MethodPost || request.Header.Get("Content-Type") != "application/json" || request.Header.Get("Accept") != "application/json" {
			t.Errorf("request = %s %#v", request.Method, request.Header)
		}
		if payload["grant_type"] != "refresh_token" || payload["refresh_token"] != "old-refresh" || payload["client_id"] != oauthClientID || payload["scope"] != strings.Join(refreshScopes, " ") {
			t.Errorf("payload = %#v", payload)
		}
		_, _ = io.WriteString(w, `{"access_token":"new-token","expires_in":3600,"scope":"user:profile user:inference"}`)
	}))
	defer server.Close()
	credentials := newSubscriptionCredentials(&memoryStore{}, testCredentialFile("old", time.Now().Add(-time.Hour)))
	credentials.tokenURL = server.URL
	refreshed, err := credentials.refresh(t.Context(), oauthCredential{RefreshToken: "old-refresh"})
	if err != nil {
		t.Fatal(err)
	}
	if refreshed.AccessToken != "new-token" || refreshed.RefreshToken != "old-refresh" || refreshed.ExpiresIn != 3600 {
		t.Fatalf("refreshed = %#v", refreshed)
	}
}

func TestSubscriptionProxyRewritesAuthenticatesAndPreparesClaudeCodeRequest(t *testing.T) {
	var got *http.Request
	var gotBody string
	target, _ := url.Parse("http://upstream.test/v1/messages")
	credentials := newSubscriptionCredentials(&memoryStore{}, testCredentialFile("real-token", time.Now().Add(time.Hour)))
	handler := newSubscriptionProxyWithDependencies(credentials, target, roundTripper(func(request *http.Request) (*http.Response, error) {
		got = request.Clone(request.Context())
		body, _ := io.ReadAll(request.Body)
		gotBody = string(body)
		return &http.Response{StatusCode: http.StatusCreated, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("response"))}, nil
	}))
	body := `{"model":"claude-sonnet-4-5","max_tokens":64,"messages":[{"role":"user","content":"hello"}],"system":"instructions","stream":true}`
	request := httptest.NewRequest(http.MethodPost, "http://proxy/v1/messages?attacker=true", strings.NewReader(body))
	request.Header.Set("Authorization", "Bearer attacker")
	request.Header.Set("x-api-key", "attacker")
	request.Header.Add("anthropic-beta", "feature-one")
	request.Header.Add("anthropic-beta", "feature-two,oauth-2025-04-20")
	request.Header.Set("anthropic-version", "attacker")
	request.Header.Set("x-app", "attacker")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusCreated || response.Body.String() != "response" {
		t.Fatalf("response = %d %q", response.Code, response.Body.String())
	}
	var prepared map[string]json.RawMessage
	if err := json.Unmarshal([]byte(gotBody), &prepared); err != nil {
		t.Fatal(err)
	}
	var system []systemBlock
	if err := json.Unmarshal(prepared["system"], &system); err != nil {
		t.Fatal(err)
	}
	wantAttribution := billingHeaderPrefix + " cc_version=" + claudeCodeVersion + "; cc_entrypoint=" + claudeCodeEntrypoint + ";"
	if len(system) != 2 || system[0].Type != "text" || system[0].Text != wantAttribution || system[1].Text != "instructions" {
		t.Fatalf("prepared system = %#v", system)
	}
	delete(prepared, "system")
	var original map[string]json.RawMessage
	if err := json.Unmarshal([]byte(body), &original); err != nil {
		t.Fatal(err)
	}
	delete(original, "system")
	if !bytes.Equal(mustJSON(t, prepared), mustJSON(t, original)) {
		t.Fatalf("prepared body = %s", gotBody)
	}
	if got == nil || got.URL.Path != "/v1/messages" || got.URL.RawQuery != "" || got.Header.Get("Authorization") != "Bearer real-token" || got.Header.Get("x-api-key") != "" || got.Header.Get("anthropic-version") != anthropicVersion || got.Header.Get("anthropic-beta") != "claude-code-20250219,feature-one,feature-two,oauth-2025-04-20" || got.Header.Get("x-app") != "cli" {
		t.Fatalf("upstream request = %#v, body = %q", got, gotBody)
	}
}

func TestPrepareSubscriptionBodyReplacesCallerAttributionAndPreservesSystemBlocks(t *testing.T) {
	body := `{"model":"claude-opus-5","system":[{"type":"text","text":"x-anthropic-billing-header: forged"},{"type":"text","text":"instructions","cache_control":{"type":"ephemeral"}}]}`
	prepared, status, err := prepareSubscriptionBody(strings.NewReader(body))
	if err != nil || status != 0 {
		t.Fatalf("prepareSubscriptionBody() = %s, %d, %v", prepared, status, err)
	}
	var request struct {
		System []struct {
			Type         string         `json:"type"`
			Text         string         `json:"text"`
			CacheControl map[string]any `json:"cache_control"`
		} `json:"system"`
	}
	if err := json.Unmarshal(prepared, &request); err != nil {
		t.Fatal(err)
	}
	wantAttribution := billingHeaderPrefix + " cc_version=" + claudeCodeVersion + "; cc_entrypoint=" + claudeCodeEntrypoint + ";"
	if len(request.System) != 2 || request.System[0].Text != wantAttribution || request.System[1].Text != "instructions" || request.System[1].CacheControl["type"] != "ephemeral" {
		t.Fatalf("system = %#v", request.System)
	}
}

func TestPrepareSubscriptionBodyRejectsInvalidAndOversizedBodies(t *testing.T) {
	for name, test := range map[string]struct {
		body       io.Reader
		wantStatus int
	}{
		"missing":    {nil, http.StatusBadRequest},
		"malformed":  {strings.NewReader(`{`), http.StatusBadRequest},
		"non-object": {strings.NewReader(`[]`), http.StatusBadRequest},
		"multiple":   {strings.NewReader(`{} {}`), http.StatusBadRequest},
		"system":     {strings.NewReader(`{"system":42}`), http.StatusBadRequest},
		"oversized":  {io.LimitReader(strings.NewReader(strings.Repeat("x", maxRequestBodySize+1)), maxRequestBodySize+1), http.StatusRequestEntityTooLarge},
	} {
		t.Run(name, func(t *testing.T) {
			_, status, err := prepareSubscriptionBody(test.body)
			if err == nil || status != test.wantStatus {
				t.Fatalf("prepareSubscriptionBody() status = %d, error = %v", status, err)
			}
		})
	}
}

func TestSubscriptionProxyRejectsOtherRoutes(t *testing.T) {
	calls := 0
	target, _ := url.Parse("http://upstream.test/v1/messages")
	handler := newSubscriptionProxyWithDependencies(newSubscriptionCredentials(&memoryStore{}, testCredentialFile("token", time.Now().Add(time.Hour))), target, roundTripper(func(*http.Request) (*http.Response, error) {
		calls++
		return nil, errors.New("unexpected call")
	}))
	for _, request := range []*http.Request{
		httptest.NewRequest(http.MethodGet, "http://proxy/v1/messages", nil),
		httptest.NewRequest(http.MethodPost, "http://proxy/v1/messages/count_tokens", nil),
		httptest.NewRequest(http.MethodPost, "http://proxy/v1/messages/", nil),
	} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusForbidden {
			t.Fatalf("%s %s status = %d", request.Method, request.URL.Path, response.Code)
		}
	}
	if calls != 0 {
		t.Fatalf("upstream calls = %d", calls)
	}
}

func TestAdoptNewerStoredCredentialKeepsRejectedSameTokenMarked(t *testing.T) {
	file, err := parseCredentialFile([]byte(testCredentialDocument("old-token", time.Now().Add(time.Hour), []string{inferenceScope})))
	if err != nil {
		t.Fatal(err)
	}
	credentials := newSubscriptionCredentials(&memoryStore{file: file}, file)
	credentials.forceRefresh = true
	credentials.adoptNewerStoredCredential()
	if !credentials.forceRefresh {
		t.Fatal("same rejected token cleared forced refresh")
	}
}

func TestRejectedTokenRefreshesNextRequestWithoutRetry(t *testing.T) {
	store := &memoryStore{file: testCredentialFile("old-token", time.Now().Add(time.Hour))}
	credentials := newSubscriptionCredentials(store, store.file)
	tokenCalls := 0
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		tokenCalls++
		_, _ = io.WriteString(w, `{"access_token":"new-token","expires_in":3600,"scope":"user:inference"}`)
	}))
	defer tokenServer.Close()
	credentials.tokenURL = tokenServer.URL
	upstreamCalls := 0
	var authorizations []string
	target, _ := url.Parse("http://upstream.test/v1/messages")
	handler := newSubscriptionProxyWithDependencies(credentials, target, roundTripper(func(request *http.Request) (*http.Response, error) {
		upstreamCalls++
		authorizations = append(authorizations, request.Header.Get("Authorization"))
		status := http.StatusOK
		if upstreamCalls == 1 {
			status = http.StatusUnauthorized
		}
		return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("response"))}, nil
	}))
	for _, wantStatus := range []int{http.StatusUnauthorized, http.StatusOK} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "http://proxy/v1/messages", strings.NewReader(`{}`)))
		if response.Code != wantStatus {
			t.Fatalf("status = %d, want %d", response.Code, wantStatus)
		}
	}
	if upstreamCalls != 2 || tokenCalls != 1 || strings.Join(authorizations, ",") != "Bearer old-token,Bearer new-token" || store.file.OAuth.AccessToken != "new-token" {
		t.Fatalf("upstream = %d, token = %d, auth = %#v, stored = %#v", upstreamCalls, tokenCalls, authorizations, store.file)
	}
}

func TestDiagnosticCaptureBoundsContentsAndCountsFullBody(t *testing.T) {
	capture := &diagnosticCapture{}
	contents := bytes.Repeat([]byte("x"), diagnosticCaptureSize+17)
	written, err := capture.Write(contents)
	if err != nil {
		t.Fatal(err)
	}
	got, total, truncated := capture.snapshot()
	if written != len(contents) || len(got) != diagnosticCaptureSize || total != int64(len(contents)) || !truncated {
		t.Fatalf("written = %d, captured = %d, total = %d, truncated = %v", written, len(got), total, truncated)
	}
}

func TestDiagnosticHeadersRedactCredentialsWithoutMutatingRequest(t *testing.T) {
	headers := http.Header{
		"Authorization":        {"Bearer secret"},
		"X-Api-Key":            {"secret"},
		"X-Refresh-Token":      {"secret"},
		"Cookie":               {"session=secret"},
		"Anthropic-Version":    {anthropicVersion},
		"Anthropic-Request-Id": {"request-id"},
	}
	redacted := redactedDiagnosticHeaders(headers)
	for _, name := range []string{"Authorization", "X-Api-Key", "X-Refresh-Token", "Cookie"} {
		if got := redacted.Get(name); got != "[REDACTED]" {
			t.Errorf("redacted %s = %q", name, got)
		}
	}
	if redacted.Get("Anthropic-Version") != anthropicVersion || redacted.Get("Anthropic-Request-Id") != "request-id" {
		t.Fatalf("safe headers = %#v", redacted)
	}
	if headers.Get("Authorization") != "Bearer secret" {
		t.Fatal("source headers were mutated")
	}
}

func TestDiagnosticResponseBodyPreservesStream(t *testing.T) {
	body := newDiagnosticResponseBody(1, io.NopCloser(strings.NewReader("response")))
	contents, err := io.ReadAll(body)
	if err != nil {
		t.Fatal(err)
	}
	if err := body.Close(); err != nil {
		t.Fatal(err)
	}
	if string(contents) != "response" {
		t.Fatalf("body = %q", contents)
	}
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func configGetenv(directory string) func(string) string {
	return func(name string) string {
		if name == "CLAUDE_CONFIG_DIR" {
			return directory
		}
		return ""
	}
}

func testCredentialDocument(token string, expiresAt time.Time, scopes []string) string {
	credential := map[string]any{"accessToken": token, "refreshToken": "refresh", "expiresAt": expiresAt.UnixMilli(), "scopes": scopes, "subscriptionType": "pro", "rateLimitTier": "default"}
	encoded, _ := json.Marshal(map[string]any{"claudeAiOauth": credential})
	return string(encoded)
}

func testCredentialDocumentWithoutRefresh(token string, expiresAt time.Time, scopes []string) string {
	credential := map[string]any{"accessToken": token, "expiresAt": expiresAt.UnixMilli(), "scopes": scopes}
	encoded, _ := json.Marshal(map[string]any{"claudeAiOauth": credential})
	return string(encoded)
}

func testCredentialFile(token string, expiresAt time.Time) *credentialFile {
	file, _ := parseCredentialFile([]byte(testCredentialDocument(token, expiresAt, []string{inferenceScope})))
	return file
}

func writeCredential(t *testing.T, path, contents string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
}

type memoryStore struct {
	file *credentialFile
	err  error
}

func (store *memoryStore) description() string { return "memory" }
func (store *memoryStore) read() (*credentialFile, error) {
	if store.err != nil {
		return nil, store.err
	}
	return store.file, nil
}
func (store *memoryStore) write(file *credentialFile) error {
	if store.err != nil {
		return store.err
	}
	store.file = file
	return nil
}

type roundTripper func(*http.Request) (*http.Response, error)

func (fn roundTripper) RoundTrip(request *http.Request) (*http.Response, error) { return fn(request) }
