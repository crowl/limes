package app

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/crowl/limes/internal/buildinfo"
	"github.com/crowl/limes/internal/config"
)

func TestCredentialValueSupportsPrefixAndBasicAuthentication(t *testing.T) {
	prefixed := credentialValue(&config.Credential{Prefix: "Bearer "}, "secret")
	if prefixed != "Bearer secret" {
		t.Fatalf("prefixed credential = %q", prefixed)
	}
	basic := credentialValue(&config.Credential{BasicUsername: "x-access-token"}, "secret")
	want := "Basic " + base64.StdEncoding.EncodeToString([]byte("x-access-token:secret"))
	if basic != want {
		t.Fatalf("basic credential = %q, want %q", basic, want)
	}
}

func TestRunPrintsVersionWithoutLoadingConfiguration(t *testing.T) {
	originalVersion, originalRevision := buildinfo.Version, buildinfo.Revision
	buildinfo.Version, buildinfo.Revision = "v1.2.3", "a1b2c3d"
	t.Cleanup(func() {
		buildinfo.Version, buildinfo.Revision = originalVersion, originalRevision
	})

	var output strings.Builder
	bindCalled := false
	err := runWithBind(t.Context(), []string{"-version"}, func(string) string {
		t.Fatal("environment was read for version output")
		return ""
	}, testLogger(), &output, io.Discard, func([]provider) ([]runningProvider, error) {
		bindCalled = true
		return nil, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if bindCalled {
		t.Fatal("listeners were bound for version output")
	}
	if got, want := output.String(), "limes v1.2.3 (a1b2c3d)\n"; got != want {
		t.Fatalf("version output = %q, want %q", got, want)
	}
}

func TestRunKeepsAdminAvailableWhenAllBackendsAreUnavailable(t *testing.T) {
	adminListener := mustListen(t)
	adminAddress := adminListener.Addr().String()
	if err := adminListener.Close(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "config.json")
	contents := `{"admin":{"address":"` + adminAddress + `"},"listeners":[{"name":"unavailable","address":"127.0.0.1:8787","backends":[{"type":"http","upstream":"https://example.test","routes":[{"method":"POST","path":"/x"}],"credential":{"environment":"MISSING","header":"Authorization"}}]}]}`
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	bindCalled := false
	err := runWithBind(ctx, []string{"--config-path", path}, func(string) string { return "" }, testLogger(), io.Discard, io.Discard, func(providers []provider) ([]runningProvider, error) {
		bindCalled = true
		if len(providers) != 0 {
			t.Fatalf("bound providers = %#v", providers)
		}
		return nil, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if !bindCalled {
		t.Fatal("proxy binding was not attempted")
	}
}

func TestRunValidatesAllBackendsBeforeBinding(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	contents := `{"listeners":[` +
		`{"name":"available","address":"127.0.0.1:1","backends":[{"type":"http","upstream":"http://example.test","routes":[{"method":"POST","path":"/x"}],"credential":{"environment":"KEY","header":"Authorization"}}]},` +
		`{"name":"invalid","address":"127.0.0.1:2","backends":[{"type":"http","upstream":"https://example.test:99999","routes":[{"method":"POST","path":"/x"}],"credential":{"environment":"KEY","header":"Authorization"}}]}` +
		`]}`
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	bindCalled := false
	err := runWithBind(context.Background(), []string{"--config-path", path}, func(name string) string {
		if name == "KEY" {
			return "credential"
		}
		return ""
	}, testLogger(), io.Discard, io.Discard, func([]provider) ([]runningProvider, error) {
		bindCalled = true
		t.Fatal("bind was called before invalid configuration was rejected")
		return nil, nil
	})
	if err == nil || !strings.Contains(err.Error(), "invalid explicit port") {
		t.Fatalf("runWithBind() error = %v", err)
	}
	if bindCalled {
		t.Fatal("bind was called before invalid configuration was rejected")
	}
}

func TestSelectProvidersPrefersAvailableAnthropicSubscription(t *testing.T) {
	directory := t.TempDir()
	expiresAt := time.Now().Add(time.Hour).UnixMilli()
	contents := fmt.Sprintf(`{"claudeAiOauth":{"accessToken":"token","refreshToken":"refresh","expiresAt":%d,"scopes":["user:inference"]}}`, expiresAt)
	if err := os.WriteFile(filepath.Join(directory, ".credentials.json"), []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	settings := config.File{Listeners: []config.Listener{{Name: "anthropic", Address: "127.0.0.1:0", Backends: []config.Backend{
		{Type: "anthropic_subscription"}, httpBackend("KEY"),
	}}}}
	providers, err := selectProviders(settings, func(name string) string {
		if name == "CLAUDE_CONFIG_DIR" {
			return directory
		}
		if name == "KEY" {
			return "fallback"
		}
		return ""
	}, testLogger())
	if err != nil {
		t.Fatal(err)
	}
	if len(providers) != 1 || providers[0].authMode != "anthropic_subscription" || providers[0].name != "anthropic" {
		t.Fatalf("selected providers = %#v", providers)
	}
}

func TestSelectProvidersPrefersAvailableSubscription(t *testing.T) {
	directory := t.TempDir()
	contents := `{"tokens":{"access_token":"` + subscriptionTestJWT("account") + `"},"last_refresh":"` + time.Now().UTC().Format(time.RFC3339) + `"}`
	if err := os.WriteFile(filepath.Join(directory, "auth.json"), []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	settings := config.File{Listeners: []config.Listener{{Name: "any", Address: "127.0.0.1:0", Backends: []config.Backend{
		{Type: "openai_subscription"}, httpBackend("KEY"),
	}}}}
	providers, err := selectProviders(settings, func(name string) string {
		if name == "CODEX_HOME" {
			return directory
		}
		if name == "KEY" {
			return "fallback"
		}
		return ""
	}, testLogger())
	if err != nil {
		t.Fatal(err)
	}
	if len(providers) != 1 || providers[0].authMode != "openai_subscription" || providers[0].name != "any" {
		t.Fatalf("selected providers = %#v", providers)
	}
}

func TestSelectProvidersPrefersAvailableXaiSubscription(t *testing.T) {
	directory := t.TempDir()
	entry := `{"key":"token","auth_mode":"oidc","user_id":"user","expires_at":"2100-01-01T00:00:00Z","refresh_token":"refresh","oidc_issuer":"https://auth.x.ai","oidc_client_id":"b1a00492-073a-47ea-816f-4c329264a828"}`
	contents := `{"https://auth.x.ai::b1a00492-073a-47ea-816f-4c329264a828":` + entry + `}`
	if err := os.WriteFile(filepath.Join(directory, "auth.json"), []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	settings := config.File{Listeners: []config.Listener{{Name: "xai", Address: "127.0.0.1:0", Backends: []config.Backend{
		{Type: "xai_subscription"}, httpBackend("KEY"),
	}}}}
	providers, err := selectProviders(settings, func(name string) string {
		if name == "GROK_HOME" {
			return directory
		}
		if name == "KEY" {
			return "fallback"
		}
		return ""
	}, testLogger())
	if err != nil {
		t.Fatal(err)
	}
	if len(providers) != 1 || providers[0].authMode != "xai_subscription" || providers[0].name != "xai" {
		t.Fatalf("selected providers = %#v", providers)
	}
}

func TestSelectProvidersEvaluatesLaterBackendAfterSelection(t *testing.T) {
	directory := t.TempDir()
	contents := `{"tokens":{"access_token":"` + subscriptionTestJWT("account") + `"},"last_refresh":"` + time.Now().UTC().Format(time.RFC3339) + `"}`
	if err := os.WriteFile(filepath.Join(directory, "auth.json"), []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	settings := config.File{Listeners: []config.Listener{{Name: "one", Address: "127.0.0.1:0", Backends: []config.Backend{{Type: "openai_subscription"}, httpBackend("LATER")}}}}
	laterEvaluated := false
	providers, err := selectProviders(settings, func(name string) string {
		if name == "CODEX_HOME" {
			return directory
		}
		if name == "LATER" {
			laterEvaluated = true
			return "fallback"
		}
		return ""
	}, testLogger())
	if err != nil || len(providers) != 1 || providers[0].authMode != "openai_subscription" || !laterEvaluated {
		t.Fatalf("selectProviders() = %#v, %v, later evaluated = %v", providers, err, laterEvaluated)
	}
}

func TestSelectProvidersUsesHTTPAndDisablesUnavailableListener(t *testing.T) {
	settings := config.File{Listeners: []config.Listener{
		{Name: "disabled", Address: "127.0.0.1:1", Backends: []config.Backend{httpBackend("MISSING")}},
		{Name: "enabled", Address: "127.0.0.1:2", Backends: []config.Backend{{Type: "openai_subscription"}, httpBackend("KEY")}},
	}}
	providers, err := selectProviders(settings, func(name string) string {
		if name == "KEY" {
			return "value"
		}
		return ""
	}, testLogger())
	if err != nil {
		t.Fatal(err)
	}
	if len(providers) != 1 || providers[0].name != "enabled" || providers[0].authMode != "http" {
		t.Fatalf("selected providers = %#v", providers)
	}
}

func TestSelectProvidersFailsWhenAllUnavailable(t *testing.T) {
	_, err := selectProviders(config.File{Listeners: []config.Listener{{Name: "none", Address: "127.0.0.1:1", Backends: []config.Backend{httpBackend("MISSING")}}}}, func(string) string { return "" }, testLogger())
	if err == nil || err.Error() != "no configured listener has an available backend" {
		t.Fatalf("selectProviders() error = %v", err)
	}
}

func TestBindProvidersSetsRequestReadTimeout(t *testing.T) {
	listener := mustListen(t)
	running, err := bindProvidersWithListener(
		[]provider{{name: "one", address: "127.0.0.1:0", handler: http.NotFoundHandler()}},
		func(_, _ string) (net.Listener, error) { return listener, nil },
	)
	if err != nil {
		t.Fatal(err)
	}
	defer closeListeners(running)
	if got := running[0].server.ReadTimeout; got != requestReadTimeout {
		t.Fatalf("ReadTimeout = %v, want %v", got, requestReadTimeout)
	}
}

func TestBindProvidersRollsBackEarlierListeners(t *testing.T) {
	first := &recordingListener{Listener: mustListen(t)}
	sentinel := errors.New("second listener unavailable")
	providers := []provider{{name: "first", address: "first", handler: http.NotFoundHandler()}, {name: "second", address: "second", handler: http.NotFoundHandler()}}
	calls := 0
	_, err := bindProvidersWithListener(providers, func(_, _ string) (net.Listener, error) {
		calls++
		if calls == 1 {
			return first, nil
		}
		return nil, sentinel
	})
	if !errors.Is(err, sentinel) || first.closeCalls != 1 || calls != 2 || !strings.Contains(err.Error(), "second") {
		t.Fatalf("error = %v, closes = %d, calls = %d", err, first.closeCalls, calls)
	}
}

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func httpBackend(environment string) config.Backend {
	return config.Backend{Type: "http", Upstream: "https://example.test", Routes: []config.Route{{Method: "POST", Path: "/x"}}, Credential: &config.Credential{Environment: environment, Header: "Authorization"}}
}

func subscriptionTestJWT(account string) string {
	payload := `{"exp":4102444800,"https://api.openai.com/auth":{"chatgpt_account_id":"` + account + `"}}`
	return "x." + base64.RawURLEncoding.EncodeToString([]byte(payload)) + ".x"
}

func mustListen(t *testing.T) net.Listener {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	return listener
}

type recordingListener struct {
	net.Listener
	closeCalls int
}

func (listener *recordingListener) Close() error {
	listener.closeCalls++
	return listener.Listener.Close()
}
