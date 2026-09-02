package app

import (
	"encoding/base64"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"testing"

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
		t.Fatal("proxy was bound for version output")
	}
	if got, want := output.String(), "limes v1.2.3 (a1b2c3d)\n"; got != want {
		t.Fatalf("version output = %q, want %q", got, want)
	}
}

func TestBindProvidersSetsRequestReadTimeout(t *testing.T) {
	listener := mustListen(t)
	running, err := bindProvidersWithListener(
		[]provider{{name: "proxy", address: "127.0.0.1:0", handler: http.NotFoundHandler()}},
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

func TestBindProvidersRollsBackEarlierSockets(t *testing.T) {
	first := &recordingListener{Listener: mustListen(t)}
	sentinel := errors.New("second socket unavailable")
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
	return config.Backend{Type: "http", Upstreams: []string{"https://example.test"}, Routes: []config.Route{{Method: "POST", Path: "/x"}}, Credential: &config.Credential{Environment: environment, Header: "Authorization"}}
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
