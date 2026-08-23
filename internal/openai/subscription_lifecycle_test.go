package openai

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestParseJWTClaimsAreUnverified(t *testing.T) {
	token := jwtForTest(4102444800, "account")
	expiresAt, account, err := parseJWTClaims(token)
	if err != nil || expiresAt != 4102444800 || account != "account" {
		t.Fatalf("parseJWTClaims() = %d, %q, %v", expiresAt, account, err)
	}
	for _, token := range []string{"opaque", "a.%.c", "a." + base64.RawURLEncoding.EncodeToString([]byte("not JSON")) + ".c"} {
		if _, _, err := parseJWTClaims(token); err == nil {
			t.Fatalf("parseJWTClaims(%q) succeeded", token)
		}
	}
}

func TestTokenNeedsRefresh(t *testing.T) {
	now := time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		name string
		file authFile
		want bool
	}{
		{"valid JWT", authFile{Tokens: storedTokens{AccessToken: jwtForTest(now.Add(6*time.Minute).Unix(), "a")}}, false},
		{"refresh margin", authFile{Tokens: storedTokens{AccessToken: jwtForTest(now.Add(5*time.Minute).Unix(), "a")}}, true},
		{"expired", authFile{Tokens: storedTokens{AccessToken: jwtForTest(now.Add(-time.Minute).Unix(), "a")}}, true},
		{"fresh opaque", authFile{Tokens: storedTokens{AccessToken: "opaque"}, LastRefresh: now.Add(-time.Minute).Format(time.RFC3339)}, false},
		{"missing refresh time", authFile{Tokens: storedTokens{AccessToken: "opaque"}}, true},
		{"malformed refresh time", authFile{Tokens: storedTokens{AccessToken: "opaque"}, LastRefresh: "bad"}, true},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			if got := tokenNeedsRefresh(&testCase.file, now); got != testCase.want {
				t.Fatalf("tokenNeedsRefresh() = %v, want %v", got, testCase.want)
			}
		})
	}
}

func TestAccountIDPrecedence(t *testing.T) {
	if got := accountID(storedTokens{AccountID: "stored", IDToken: jwtForTest(1, "id"), AccessToken: jwtForTest(1, "access")}); got != "stored" {
		t.Fatalf("account ID = %q", got)
	}
	if got := accountID(storedTokens{IDToken: jwtForTest(1, "id"), AccessToken: jwtForTest(1, "access")}); got != "id" {
		t.Fatalf("account ID = %q", got)
	}
	if got := accountID(storedTokens{IDToken: "opaque", AccessToken: jwtForTest(1, "access")}); got != "access" {
		t.Fatalf("account ID = %q", got)
	}
}

func TestRefreshSendsCodexRequestAndPreservesOmittedFields(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		var payload map[string]string
		if err := json.NewDecoder(request.Body).Decode(&payload); err != nil {
			t.Error(err)
		}
		if request.Method != http.MethodPost || request.Header.Get("Content-Type") != "application/json" || request.Header.Get("Accept") != "application/json" || request.Header.Get("Accept-Language") != "en-US,en;q=0.9" || request.Header.Get("User-Agent") != subscriptionUserAgent {
			t.Errorf("request = %s %#v", request.Method, request.Header)
		}
		if payload["grant_type"] != "refresh_token" || payload["refresh_token"] != "old-refresh" || payload["client_id"] != codexClientID || payload["scope"] != "openid profile email offline_access" {
			t.Errorf("payload = %#v", payload)
		}
		w.Header().Set("Content-Type", "application/json")
		if _, err := w.Write([]byte(`{"access_token":"` + jwtForTest(4102444800, "") + `"}`)); err != nil {
			t.Error(err)
		}
	}))
	defer server.Close()
	credentials := newSubscriptionCredentials("unused", &authFile{})
	credentials.tokenURL = server.URL
	updated, err := credentials.refresh(t.Context(), storedTokens{RefreshToken: "old-refresh", AccountID: "old-account"})
	if err != nil {
		t.Fatal(err)
	}
	if updated.RefreshToken != "old-refresh" || updated.AccountID != "old-account" {
		t.Fatalf("updated = %#v", updated)
	}
}

func TestAuthStoreRenameFailurePreservesOriginal(t *testing.T) {
	path := filepath.Join(t.TempDir(), "auth.json")
	original := []byte(`{"auth_mode":"x","tokens":{"access_token":"old"}}`)
	if err := os.WriteFile(path, original, 0o600); err != nil {
		t.Fatal(err)
	}
	store := newAuthStore()
	sentinel := errors.New("rename failed")
	store.rename = func(_, _ string) error { return sentinel }
	err := store.write(path, &authFile{Tokens: storedTokens{AccessToken: "new"}, LastRefresh: "2025-01-01T00:00:00Z", fields: map[string]json.RawMessage{"auth_mode": json.RawMessage(`"x"`)}})
	if !errors.Is(err, sentinel) {
		t.Fatalf("write() error = %v", err)
	}
	contents, readErr := os.ReadFile(path)
	if readErr != nil || string(contents) != string(original) {
		t.Fatalf("original = %q, error = %v", contents, readErr)
	}
	matches, globErr := filepath.Glob(filepath.Join(filepath.Dir(path), ".auth.json.tmp-*"))
	if globErr != nil || len(matches) != 0 {
		t.Fatalf("temporary files = %v, error = %v", matches, globErr)
	}
}

func TestConcurrentRefreshOccursOnce(t *testing.T) {
	path := filepath.Join(t.TempDir(), "auth.json")
	file := &authFile{Tokens: storedTokens{AccessToken: jwtForTest(1, "account"), RefreshToken: "refresh", AccountID: "account"}, fields: map[string]json.RawMessage{}}
	started := make(chan struct{})
	release := make(chan struct{})
	var requests int
	var requestMu sync.Mutex
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requestMu.Lock()
		requests++
		requestMu.Unlock()
		close(started)
		select {
		case <-release:
		case <-t.Context().Done():
			return
		}
		if _, err := w.Write([]byte(`{"access_token":"` + jwtForTest(4102444800, "account") + `"}`)); err != nil {
			t.Error(err)
		}
	}))
	defer server.Close()
	credentials := newSubscriptionCredentials(path, file)
	credentials.tokenURL = server.URL
	credentials.now = func() time.Time { return time.Unix(100, 0) }
	results := make(chan storedTokens, 4)
	resultErrors := make(chan error, 4)
	for range 4 {
		go func() {
			tokens, err := credentials.tokens(t.Context())
			results <- tokens
			resultErrors <- err
		}()
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("OAuth refresh did not begin")
	}
	close(release)
	for range 4 {
		if err := <-resultErrors; err != nil {
			t.Fatal(err)
		}
		tokens := <-results
		if tokens.AccessToken != jwtForTest(4102444800, "account") || tokens.AccountID != "account" {
			t.Fatalf("tokens = %#v", tokens)
		}
	}
	requestMu.Lock()
	defer requestMu.Unlock()
	if requests != 1 {
		t.Fatalf("refresh requests = %d", requests)
	}
}

func TestRefreshRejectsRedirectAndInvalidResponses(t *testing.T) {
	tests := []struct {
		name    string
		handler http.HandlerFunc
		want    string
	}{
		{"redirect", func(w http.ResponseWriter, request *http.Request) {
			http.Redirect(w, request, "/other", http.StatusFound)
		}, "status 302"},
		{"non-success", func(w http.ResponseWriter, _ *http.Request) { http.Error(w, "refresh-secret", http.StatusUnauthorized) }, "status 401"},
		{"malformed JSON", func(w http.ResponseWriter, _ *http.Request) {
			if _, err := io.WriteString(w, "{"); err != nil {
				t.Error(err)
			}
		}, "decode OAuth"},
		{"missing access token", func(w http.ResponseWriter, _ *http.Request) {
			if _, err := io.WriteString(w, `{}`); err != nil {
				t.Error(err)
			}
		}, "access token"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(test.handler)
			defer server.Close()
			credentials := newSubscriptionCredentials("unused", &authFile{})
			credentials.tokenURL = server.URL
			_, err := credentials.refresh(t.Context(), storedTokens{RefreshToken: "refresh-secret", AccountID: "account"})
			if err == nil || !strings.Contains(err.Error(), test.want) || strings.Contains(err.Error(), "refresh-secret") {
				t.Fatalf("refresh() error = %v", err)
			}
		})
	}
}

func TestRefreshUsesReplacementTokenAndAccount(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if _, err := io.WriteString(w, `{"access_token":"`+jwtForTest(4102444800, "new-account")+`","refresh_token":"new-refresh"}`); err != nil {
			t.Error(err)
		}
	}))
	defer server.Close()
	credentials := newSubscriptionCredentials("unused", &authFile{})
	credentials.tokenURL = server.URL
	updated, err := credentials.refresh(t.Context(), storedTokens{RefreshToken: "old", AccountID: "old-account"})
	if err != nil {
		t.Fatal(err)
	}
	if updated.RefreshToken != "new-refresh" || updated.AccountID != "new-account" {
		t.Fatalf("updated = %#v", updated)
	}
}

func TestRefreshHonorsCanceledContext(t *testing.T) {
	credentials := newSubscriptionCredentials("unused", &authFile{})
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, err := credentials.refresh(ctx, storedTokens{RefreshToken: "refresh", AccountID: "account"})
	if err == nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("refresh() error = %v", err)
	}
}

func jwtForTest(expiration int64, account string) string {
	payload := `{"exp":` + strconv.FormatInt(expiration, 10) + `,"https://api.openai.com/auth":{"chatgpt_account_id":"` + account + `"}}`
	return "x." + base64.RawURLEncoding.EncodeToString([]byte(payload)) + ".x"
}
