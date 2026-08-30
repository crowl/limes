package xai

import (
	"encoding/base64"
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

func TestAvailableDistinguishesMissingAndMalformedCredentials(t *testing.T) {
	missing := t.TempDir()
	if handler, available, err := Available(func(name string) string {
		if name == "GROK_HOME" {
			return missing
		}
		return ""
	}); err != nil || available || handler != nil {
		t.Fatalf("missing Available() = %v, %v, %v", handler, available, err)
	}

	malformed := t.TempDir()
	writeRawAuth(t, filepath.Join(malformed, "auth.json"), `not json`)
	if _, available, err := Available(func(name string) string {
		if name == "GROK_HOME" {
			return malformed
		}
		return ""
	}); err == nil || available {
		t.Fatalf("malformed Available() = available %v, error %v", available, err)
	}
}

func TestFindSubscriptionCredentialsUsesGrokHome(t *testing.T) {
	grokHome := t.TempDir()
	home := t.TempDir()
	writeTestAuth(t, filepath.Join(grokHome, "auth.json"), testAuthEntry("grok-token", "user"))
	writeTestAuth(t, filepath.Join(home, ".grok", "auth.json"), testAuthEntry("home-token", "user"))

	path, file, err := findSubscriptionCredentialsAt(func(name string) string {
		switch name {
		case "GROK_HOME":
			return grokHome
		case "HOME":
			return home
		default:
			return ""
		}
	}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if path != filepath.Join(grokHome, "auth.json") || file.Entry.AccessToken != "grok-token" {
		t.Fatalf("credentials = %q, %#v", path, file.Entry)
	}
}

func TestFindSubscriptionCredentialsRejectsAPIKeyAndInvalidEntries(t *testing.T) {
	for name, document := range map[string]string{
		"API key":         `{"xai::api_key":{"key":"api-key","auth_mode":"api_key"}}`,
		"missing user":    testAuthDocument(`{"key":"token","auth_mode":"oidc","expires_at":"2100-01-01T00:00:00Z"}`),
		"expired no RT":   testAuthDocument(`{"key":"token","auth_mode":"oidc","user_id":"user","expires_at":"2000-01-01T00:00:00Z"}`),
		"wrong issuer":    testAuthDocument(`{"key":"token","auth_mode":"oidc","user_id":"user","expires_at":"2100-01-01T00:00:00Z","oidc_issuer":"https://evil.example"}`),
		"wrong client ID": testAuthDocument(`{"key":"token","auth_mode":"oidc","user_id":"user","expires_at":"2100-01-01T00:00:00Z","oidc_client_id":"other"}`),
	} {
		t.Run(name, func(t *testing.T) {
			home := t.TempDir()
			writeRawAuth(t, filepath.Join(home, "auth.json"), document)
			_, _, err := findSubscriptionCredentialsAt(func(name string) string {
				if name == "GROK_HOME" {
					return home
				}
				return ""
			}, time.Now())
			if !errors.Is(err, errNoSubscriptionCredentials) && !strings.Contains(err.Error(), "subscription credentials") {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestAuthStoreWritePreservesOtherEntriesAndAliases(t *testing.T) {
	path := filepath.Join(t.TempDir(), "auth.json")
	document := `{"other":{"key":"preserved"},"` + xaiAuthEntryKey + `":{"access_token":"old","refresh":"old-refresh","expires":1,"user_id":"user","auth_mode":"oidc","custom":true}}`
	writeRawAuth(t, path, document)
	store := newAuthStore()
	file, err := store.read(path)
	if err != nil {
		t.Fatal(err)
	}
	updated, err := refreshedAuthFile(file, tokenReply{AccessToken: "new", RefreshToken: "new-refresh", ExpiresIn: 3600}, time.Unix(100, 0))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.write(path, updated); err != nil {
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
	var entry map[string]json.RawMessage
	if err := json.Unmarshal(fields[xaiAuthEntryKey], &entry); err != nil {
		t.Fatal(err)
	}
	var other map[string]string
	if err := json.Unmarshal(fields["other"], &other); err != nil {
		t.Fatal(err)
	}
	if other["key"] != "preserved" || firstString(entry, "access_token") != "new" || firstString(entry, "refresh") != "new-refresh" || string(entry["custom"]) != "true" {
		t.Fatalf("stored auth = %s", contents)
	}
	if _, addedCurrentAlias := entry["key"]; addedCurrentAlias {
		t.Fatal("write changed the access token field alias")
	}
}

func TestRefreshSendsOfficialGrokRequest(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.Header.Get("Content-Type") != "application/x-www-form-urlencoded" || request.Header.Get("Accept") != "application/json" {
			t.Errorf("request = %s %#v", request.Method, request.Header)
		}
		if err := request.ParseForm(); err != nil {
			t.Error(err)
		}
		if request.Form.Get("grant_type") != "refresh_token" || request.Form.Get("refresh_token") != "old-refresh" || request.Form.Get("client_id") != grokClientID || request.Form.Get("principal_type") != "Team" || request.Form.Get("principal_id") != "team" {
			t.Errorf("form = %#v", request.Form)
		}
		_, _ = io.WriteString(w, `{"access_token":"new","expires_in":3600}`)
	}))
	defer server.Close()

	credentials := newSubscriptionCredentials("unused", &authFile{})
	credentials.tokenURL = server.URL
	refreshed, err := credentials.refresh(t.Context(), authEntry{RefreshToken: "old-refresh", PrincipalType: "Team", PrincipalID: "team"})
	if err != nil {
		t.Fatal(err)
	}
	if refreshed.AccessToken != "new" || refreshed.RefreshToken != "old-refresh" {
		t.Fatalf("refreshed = %#v", refreshed)
	}
}

func TestSubscriptionProxyRewritesAuthenticatesAndSelectsModel(t *testing.T) {
	var got *http.Request
	var gotBody string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		got = request.Clone(request.Context())
		body, err := io.ReadAll(request.Body)
		if err != nil {
			t.Error(err)
		}
		gotBody = string(body)
		w.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(w, "response")
	}))
	defer upstream.Close()
	target, err := url.Parse(upstream.URL + "/v1/responses")
	if err != nil {
		t.Fatal(err)
	}
	credentials := newSubscriptionCredentials("unused", testAuthFile("real-token", "real-user"))
	handler := newSubscriptionProxyWithDependencies(credentials, target, http.DefaultTransport)
	server := httptest.NewServer(handler)
	defer server.Close()

	body := `{"model":"grok-build","input":"hello","stream":true}`
	request, err := http.NewRequestWithContext(t.Context(), http.MethodPost, server.URL+"/v1/responses?attacker=true", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer attacker")
	request.Header.Set("x-api-key", "attacker")
	request.Header.Set("X-XAI-Token-Auth", "attacker")
	request.Header.Set("x-grok-model-override", "attacker")
	request.Header.Set("x-grok-client-version", "attacker")
	request.Header.Set("x-userid", "attacker")
	request.Header.Set("x-email", "attacker@example.com")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	responseBody, err := io.ReadAll(response.Body)
	closeErr := response.Body.Close()
	if err != nil || closeErr != nil {
		t.Fatalf("read response: %v, %v", err, closeErr)
	}
	if response.StatusCode != http.StatusCreated || string(responseBody) != "response" {
		t.Fatalf("response = %d %q", response.StatusCode, responseBody)
	}
	if got == nil || got.URL.Path != "/v1/responses" || got.URL.RawQuery != "" || gotBody != body || got.Header.Get("Authorization") != "Bearer real-token" || got.Header.Get("X-XAI-Token-Auth") != "xai-grok-cli" || got.Header.Get("x-authenticateresponse") != "authenticate-response" || got.Header.Get("x-grok-model-override") != "grok-build" || got.Header.Get("x-grok-client-version") != grokClientVersion || got.Header.Get("x-grok-client-identifier") != "grok-shell" || got.Header.Get("x-userid") != "real-user" || got.Header.Get("x-grok-user-id") != "real-user" || got.Header.Get("x-api-key") != "" || got.Header.Get("x-email") != "" {
		t.Fatalf("upstream request = %#v, body %q", got, gotBody)
	}
}

func TestSubscriptionProxyValidatesRequestBeforeUpstream(t *testing.T) {
	calls := 0
	target, _ := url.Parse("http://upstream.test/v1/responses")
	handler := newSubscriptionProxyWithDependencies(newSubscriptionCredentials("unused", testAuthFile("token", "user")), target, roundTripper(func(*http.Request) (*http.Response, error) {
		calls++
		return nil, errors.New("unexpected upstream call")
	}))
	tests := []struct {
		name, method, path, body string
		status                   int
	}{
		{"other route", http.MethodPost, "/v1/models", `{}`, http.StatusForbidden},
		{"other method", http.MethodGet, "/v1/responses", `{}`, http.StatusForbidden},
		{"malformed JSON", http.MethodPost, "/v1/responses", `{`, http.StatusBadRequest},
		{"missing model", http.MethodPost, "/v1/responses", `{"input":"x"}`, http.StatusBadRequest},
		{"non-string model", http.MethodPost, "/v1/responses", `{"model":1}`, http.StatusBadRequest},
		{"invalid model header", http.MethodPost, "/v1/responses", "{\"model\":\"grok\\nother\"}", http.StatusBadRequest},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, httptest.NewRequest(test.method, "http://proxy"+test.path, strings.NewReader(test.body)))
			if response.Code != test.status {
				t.Fatalf("status = %d, body = %q", response.Code, response.Body.String())
			}
		})
	}
	oversized := io.LimitReader(strings.NewReader(strings.Repeat("x", maxRequestBodySize+1)), maxRequestBodySize+1)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "http://proxy/v1/responses", oversized))
	if response.Code != http.StatusRequestEntityTooLarge || calls != 0 {
		t.Fatalf("oversized status = %d, calls = %d", response.Code, calls)
	}
}

func TestSubscriptionProxyRefreshesAfterRejectedTokenWithoutRetrying(t *testing.T) {
	path := filepath.Join(t.TempDir(), "auth.json")
	writeTestAuth(t, path, testAuthEntry("old-token", "user"))
	file, err := newAuthStore().read(path)
	if err != nil {
		t.Fatal(err)
	}
	credentials := newSubscriptionCredentials(path, file)
	tokenCalls := 0
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		tokenCalls++
		_, _ = io.WriteString(w, `{"access_token":"new-token","expires_in":3600}`)
	}))
	defer tokenServer.Close()
	credentials.tokenURL = tokenServer.URL

	upstreamCalls := 0
	var authorizations []string
	target, _ := url.Parse("http://upstream.test/v1/responses")
	handler := newSubscriptionProxyWithDependencies(credentials, target, roundTripper(func(request *http.Request) (*http.Response, error) {
		upstreamCalls++
		authorizations = append(authorizations, request.Header.Get("Authorization"))
		status := http.StatusOK
		if upstreamCalls == 1 {
			status = http.StatusUnauthorized
		}
		return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(http.StatusText(status)))}, nil
	}))

	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "http://proxy/v1/responses", strings.NewReader(`{"model":"grok-build"}`)))
	if response.Code != http.StatusUnauthorized || upstreamCalls != 1 || tokenCalls != 0 {
		t.Fatalf("first request = status %d, upstream calls %d, token calls %d", response.Code, upstreamCalls, tokenCalls)
	}
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "http://proxy/v1/responses", strings.NewReader(`{"model":"grok-build"}`)))
	if response.Code != http.StatusOK || upstreamCalls != 2 || tokenCalls != 1 {
		t.Fatalf("second request = status %d, upstream calls %d, token calls %d", response.Code, upstreamCalls, tokenCalls)
	}
	if len(authorizations) != 2 || authorizations[0] != "Bearer old-token" || authorizations[1] != "Bearer new-token" {
		t.Fatalf("authorizations = %#v", authorizations)
	}
	persisted, err := newAuthStore().read(path)
	if err != nil {
		t.Fatal(err)
	}
	if persisted.Entry.AccessToken != "new-token" {
		t.Fatalf("persisted token = %q", persisted.Entry.AccessToken)
	}
}

func TestJWTExpiry(t *testing.T) {
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"exp":4102444800}`))
	if got := jwtExpiry("x." + payload + ".x"); got.Unix() != 4102444800 {
		t.Fatalf("expiry = %v", got)
	}
	if got := jwtExpiry("opaque"); !got.IsZero() {
		t.Fatalf("opaque expiry = %v", got)
	}
}

func testAuthEntry(token, user string) string {
	return `{"key":"` + token + `","auth_mode":"oidc","user_id":"` + user + `","expires_at":"2100-01-01T00:00:00Z","refresh_token":"refresh","oidc_issuer":"` + xaiIssuer + `","oidc_client_id":"` + grokClientID + `"}`
}

func testAuthDocument(entry string) string {
	return `{"` + xaiAuthEntryKey + `":` + entry + `}`
}

func writeTestAuth(t *testing.T, path, entry string) {
	t.Helper()
	writeRawAuth(t, path, testAuthDocument(entry))
}

func writeRawAuth(t *testing.T, path, document string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(document), 0o600); err != nil {
		t.Fatal(err)
	}
}

func testAuthFile(token, user string) *authFile {
	entryFields := map[string]json.RawMessage{}
	setJSONField(entryFields, "key", token)
	setJSONField(entryFields, "auth_mode", "oidc")
	setJSONField(entryFields, "user_id", user)
	setJSONField(entryFields, "expires_at", "2100-01-01T00:00:00Z")
	entry, _ := parseAuthEntry(entryFields)
	encoded, _ := json.Marshal(entryFields)
	return &authFile{EntryKey: xaiAuthEntryKey, Entry: entry, fields: map[string]json.RawMessage{xaiAuthEntryKey: encoded}}
}

type roundTripper func(*http.Request) (*http.Response, error)

func (fn roundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	return fn(request)
}
