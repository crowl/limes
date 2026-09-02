package app

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/crowl/limes/internal/ca"
	"github.com/crowl/limes/internal/config"
)

func TestProxyInterceptsClaimedHostAndAppliesRuleRoutes(t *testing.T) {
	getenv, roots := proxyEnvironment(t, map[string]string{"GITHUB_PAT": "pat"})
	requests := newRequestLog()
	proxy, err := configureProxy(config.Proxy{
		Address: "127.0.0.1:0",
		Rules:   []config.Rule{{Name: "github", Backends: []config.Backend{githubBackend(t)}}},
	}, getenv, testLogger(), requests)
	if err != nil {
		t.Fatal(err)
	}

	server := httptest.NewServer(proxy.handler)
	defer server.Close()
	client := proxyClient(t, server.URL, roots)

	response, err := client.Get("https://api.github.test/repos/owner/name")
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	// The route is not configured, so Limes rejects it without contacting
	// the upstream.
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("response = %d %q", response.StatusCode, body)
	}

	entries := requests.snapshots()
	if len(entries) != 1 {
		t.Fatalf("request log entries = %d", len(entries))
	}
	entry := entries[0]
	if entry.Listener != "github" || entry.Backend != "http" || entry.Path != "/repos/owner/name" || entry.Status != http.StatusForbidden {
		t.Fatalf("request log entry = %#v", entry)
	}
}

func TestProxyDeniesUnclaimedHostsWhenConfigured(t *testing.T) {
	getenv, _ := proxyEnvironment(t, map[string]string{"GITHUB_PAT": "pat"})
	proxy, err := configureProxy(config.Proxy{
		Address:   "127.0.0.1:0",
		Unclaimed: config.Deny,
		Rules:     []config.Rule{{Name: "github", Backends: []config.Backend{githubBackend(t)}}},
	}, getenv, testLogger(), nil)
	if err != nil {
		t.Fatal(err)
	}

	server := httptest.NewServer(proxy.handler)
	defer server.Close()

	connection, err := net.DialTimeout("tcp", strings.TrimPrefix(server.URL, "http://"), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	if _, err := fmt.Fprint(connection, "CONNECT elsewhere.test:443 HTTP/1.1\r\nHost: elsewhere.test:443\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(connection), &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", response.StatusCode, http.StatusForbidden)
	}
}

func TestProxyRejectsRulesThatClaimTheSameHost(t *testing.T) {
	getenv, _ := proxyEnvironment(t, map[string]string{"GITHUB_PAT": "pat"})
	_, err := configureProxy(config.Proxy{
		Address: "127.0.0.1:0",
		Rules: []config.Rule{
			{Name: "first", Backends: []config.Backend{githubBackend(t)}},
			{Name: "second", Backends: []config.Backend{githubBackend(t)}},
		},
	}, getenv, testLogger(), nil)
	if err == nil || !strings.Contains(err.Error(), "another rule already claims") {
		t.Fatalf("error = %v", err)
	}
}

func TestProxyRequiresTheCertificateAuthority(t *testing.T) {
	home := t.TempDir()
	getenv := func(name string) string {
		if name == "HOME" {
			return home
		}
		return ""
	}
	_, err := configureProxy(config.Proxy{
		Address: "127.0.0.1:0",
		Rules:   []config.Rule{{Name: "github", Backends: []config.Backend{githubBackend(t)}}},
	}, getenv, testLogger(), nil)
	if err == nil || !strings.Contains(err.Error(), "load Limes CA") {
		t.Fatalf("error = %v", err)
	}
}

func TestClaimedHosts(t *testing.T) {
	for _, testCase := range []struct {
		name    string
		backend config.Backend
		want    string
	}{
		{"openai subscription", config.Backend{Type: "openai_subscription"}, "api.openai.com"},
		{"anthropic subscription", config.Backend{Type: "anthropic_subscription"}, "api.anthropic.com"},
		{"xai subscription", config.Backend{Type: "xai_subscription"}, "api.x.ai"},
		{"one upstream", config.Backend{Type: "http", Upstreams: []string{"https://API.openai.com"}}, "api.openai.com"},
		{"several upstreams", config.Backend{Type: "http", Upstreams: []string{"https://github.com", "https://api.github.com"}}, "github.com, api.github.com"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			hosts, err := claimedHosts(testCase.backend)
			if err != nil {
				t.Fatal(err)
			}
			if got := strings.Join(hosts, ", "); got != testCase.want {
				t.Fatalf("claimedHosts() = %q, want %q", got, testCase.want)
			}
		})
	}
}

func githubBackend(t *testing.T) config.Backend {
	t.Helper()
	pattern, err := config.CompileRoute("/allowed")
	if err != nil {
		t.Fatal(err)
	}
	return config.Backend{
		Type:      "http",
		Upstreams: []string{"https://api.github.test"},
		Routes: []config.Route{
			{Method: http.MethodPost, Path: "/allowed", Pattern: pattern},
		},
		RemoveHeaders: []string{"Authorization"},
		Credential:    &config.Credential{Environment: "GITHUB_PAT", Header: "Authorization", BasicUsername: "x-access-token"},
	}
}

func proxyEnvironment(t *testing.T, values map[string]string) (func(string) string, *x509.CertPool) {
	t.Helper()
	home := t.TempDir()
	getenv := func(name string) string {
		if name == "HOME" {
			return home
		}
		return values[name]
	}
	if err := ca.Run([]string{"init"}, getenv, io.Discard, io.Discard); err != nil {
		t.Fatal(err)
	}
	var certificate strings.Builder
	if err := ca.Run([]string{"certificate"}, getenv, &certificate, io.Discard); err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(certificate.String())) {
		t.Fatal("append CA certificate")
	}
	return getenv, roots
}

func proxyClient(t *testing.T, address string, roots *x509.CertPool) *http.Client {
	t.Helper()
	proxyURL, err := url.Parse(address)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: &http.Transport{
		Proxy:           http.ProxyURL(proxyURL),
		TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12},
	}}
	t.Cleanup(client.CloseIdleConnections)
	return client
}
