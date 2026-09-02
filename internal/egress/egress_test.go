package egress

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
	"sync/atomic"
	"testing"
	"time"

	"github.com/crowl/limes/internal/ca"
)

func TestInterceptsClaimedHostAndReusesTunnel(t *testing.T) {
	authority, roots := newTestAuthority(t)

	var claims atomic.Int64
	var paths []string
	claimed := http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if err := request.Context().Err(); err != nil {
			t.Errorf("request %s context error = %v", request.URL.Path, err)
		}
		paths = append(paths, request.URL.Path)
		w.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(w, "served "+request.Host)
	})
	proxy := httptest.NewServer(New(Proxy{
		Claim: func(host string) http.Handler {
			if host != "api.limes.test" {
				return nil
			}
			claims.Add(1)
			return claimed
		},
		Authority: authority,
	}))
	defer proxy.Close()

	client := newProxyClient(t, proxy.URL, roots)
	for _, path := range []string{"/first", "/second"} {
		response, err := client.Get("https://api.limes.test" + path)
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(response.Body)
		response.Body.Close()
		if err != nil {
			t.Fatal(err)
		}
		if response.StatusCode != http.StatusCreated || string(body) != "served api.limes.test" {
			t.Fatalf("response = %d %q", response.StatusCode, body)
		}
	}
	if len(paths) != 2 || paths[0] != "/first" || paths[1] != "/second" {
		t.Fatalf("claimed handler saw %v", paths)
	}
	// Both requests share one tunnel, so the host is claimed only once.
	if got := claims.Load(); got != 1 {
		t.Fatalf("claim lookups = %d, want 1", got)
	}
}

func TestDeniesUnclaimedAuthorityWhenConfigured(t *testing.T) {
	proxy := httptest.NewServer(New(Proxy{Unclaimed: Deny}))
	defer proxy.Close()

	response := connect(t, proxy.URL, "untrusted.test:443")
	defer response.Body.Close()
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d", response.StatusCode)
	}
}

func TestRelaysUnclaimedAuthorityUnmodified(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "relayed")
	}))
	defer upstream.Close()
	upstreamURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}

	observations := make(chan string, 1)
	proxy := httptest.NewServer(newHandler(Proxy{
		Unclaimed: Relay,
		Observe: func(authority string, status int, _ time.Time) {
			observations <- fmt.Sprintf("%s %d", authority, status)
		},
	}, loopbackDialer()))
	defer proxy.Close()

	proxyURL, err := url.Parse(proxy.URL)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: &http.Transport{
		Proxy:           http.ProxyURL(proxyURL),
		TLSClientConfig: upstream.Client().Transport.(*http.Transport).TLSClientConfig,
	}}
	defer client.CloseIdleConnections()

	response, err := client.Get(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK || string(body) != "relayed" {
		t.Fatalf("response = %d %q", response.StatusCode, body)
	}

	client.CloseIdleConnections()
	select {
	case observed := <-observations:
		if observed != upstreamURL.Host+" 200" {
			t.Fatalf("observed %q", observed)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("relay was not observed")
	}
}

func TestRefusesToRelayToPrivateDestination(t *testing.T) {
	unreachable := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer unreachable.Close()
	target := strings.TrimPrefix(unreachable.URL, "http://")

	proxy := httptest.NewServer(New(Proxy{Unclaimed: Relay}))
	defer proxy.Close()

	response := connect(t, proxy.URL, target)
	defer response.Body.Close()
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", response.StatusCode, http.StatusForbidden)
	}
}

// A hostname is only known to be private after resolution, so the guard has to
// run between resolution and connect rather than on the requested authority.
func TestRefusesToRelayToHostnameResolvingToPrivateAddress(t *testing.T) {
	proxy := httptest.NewServer(New(Proxy{Unclaimed: Relay}))
	defer proxy.Close()

	response := connect(t, proxy.URL, "localhost:80")
	defer response.Body.Close()
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", response.StatusCode, http.StatusForbidden)
	}
}

func TestForwardsPlainHTTPForUnclaimedHost(t *testing.T) {
	var forwarded *http.Request
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		forwarded = request.Clone(request.Context())
		_, _ = io.WriteString(w, "forwarded")
	}))
	defer upstream.Close()

	proxy := httptest.NewServer(newHandler(Proxy{Unclaimed: Relay}, loopbackDialer()))
	defer proxy.Close()

	body, status := getThroughProxy(t, proxy.URL, upstream.URL+"/path")
	if status != http.StatusOK || body != "forwarded" {
		t.Fatalf("response = %d %q", status, body)
	}
	if forwarded == nil || forwarded.URL.Path != "/path" {
		t.Fatalf("upstream request = %#v", forwarded)
	}
}

func TestRefusesPlainHTTPForClaimedHost(t *testing.T) {
	proxy := httptest.NewServer(newHandler(Proxy{
		Unclaimed: Relay,
		Claim: func(host string) http.Handler {
			if host != "api.limes.test" {
				return nil
			}
			return http.NotFoundHandler()
		},
	}, loopbackDialer()))
	defer proxy.Close()

	_, status := getThroughProxy(t, proxy.URL, "http://api.limes.test/v1/models")
	if status != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", status, http.StatusForbidden)
	}
}

func TestRefusesClaimedHostOnOtherPorts(t *testing.T) {
	proxy := httptest.NewServer(New(Proxy{
		Unclaimed: Relay,
		Claim: func(host string) http.Handler {
			if host != "api.limes.test" {
				return nil
			}
			return http.NotFoundHandler()
		},
	}))
	defer proxy.Close()

	response := connect(t, proxy.URL, "api.limes.test:8443")
	defer response.Body.Close()
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d", response.StatusCode)
	}
}

func TestRejectsRequestHostThatDiffersFromTunnel(t *testing.T) {
	authority, roots := newTestAuthority(t)
	proxy := httptest.NewServer(New(Proxy{
		Claim: func(host string) http.Handler {
			if host != "api.limes.test" {
				return nil
			}
			return http.NotFoundHandler()
		},
		Authority: authority,
	}))
	defer proxy.Close()

	tunnel := dialTunnel(t, proxy.URL, "api.limes.test:443")
	defer tunnel.Close()
	secure := tls.Client(tunnel, &tls.Config{ServerName: "api.limes.test", RootCAs: roots, MinVersion: tls.VersionTLS12})
	if err := secure.Handshake(); err != nil {
		t.Fatal(err)
	}
	defer secure.Close()
	if _, err := fmt.Fprint(secure, "GET /path HTTP/1.1\r\nHost: elsewhere.test\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(secure), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusMisdirectedRequest {
		t.Fatalf("status = %d", response.StatusCode)
	}
}

func TestCanonicalAuthority(t *testing.T) {
	for _, testCase := range []struct {
		value string
		host  string
		port  string
		ok    bool
	}{
		{"API.GITHUB.COM:443", "api.github.com", "443", true},
		{"registry.npmjs.org:80", "registry.npmjs.org", "80", true},
		{"api.github.com.:443", "api.github.com", "443", true},
		{"api.github.com", "", "", false},
		{"api.github.com:0", "", "", false},
		{"api.github.com:https", "", "", false},
		{":443", "", "", false},
	} {
		t.Run(testCase.value, func(t *testing.T) {
			host, port, err := canonicalAuthority(testCase.value)
			if (err == nil) != testCase.ok || host != testCase.host || port != testCase.port {
				t.Fatalf("canonicalAuthority(%q) = %q, %q, %v", testCase.value, host, port, err)
			}
		})
	}
}

func TestPublicAddress(t *testing.T) {
	for _, testCase := range []struct {
		address string
		public  bool
	}{
		{"93.184.216.34", true},
		{"2606:2800:220:1:248:1893:25c8:1946", true},
		{"127.0.0.1", false},
		{"::1", false},
		{"10.1.2.3", false},
		{"172.16.0.1", false},
		{"192.168.1.1", false},
		{"169.254.169.254", false},
		{"fe80::1", false},
		{"fd00::1", false},
		{"0.0.0.0", false},
		{"224.0.0.1", false},
		{"::ffff:127.0.0.1", false},
	} {
		t.Run(testCase.address, func(t *testing.T) {
			err := requirePublicAddress(net.JoinHostPort(testCase.address, "443"))
			if (err == nil) != testCase.public {
				t.Fatalf("requirePublicAddress(%q) = %v", testCase.address, err)
			}
		})
	}
}

func newTestAuthority(t *testing.T) (*ca.Authority, *x509.CertPool) {
	t.Helper()
	home := t.TempDir()
	getenv := func(name string) string {
		if name == "HOME" {
			return home
		}
		return ""
	}
	if err := ca.Run([]string{"init"}, getenv, io.Discard, io.Discard); err != nil {
		t.Fatal(err)
	}
	authority, err := ca.Load(getenv)
	if err != nil {
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
	return authority, roots
}

func newProxyClient(t *testing.T, proxyAddress string, roots *x509.CertPool) *http.Client {
	t.Helper()
	proxyURL, err := url.Parse(proxyAddress)
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

func getThroughProxy(t *testing.T, proxyAddress, target string) (string, int) {
	t.Helper()
	proxyURL, err := url.Parse(proxyAddress)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}
	defer client.CloseIdleConnections()
	response, err := client.Get(target)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(body)), response.StatusCode
}

func dialTunnel(t *testing.T, proxyAddress, target string) net.Conn {
	t.Helper()
	connection, err := net.DialTimeout("tcp", strings.TrimPrefix(proxyAddress, "http://"), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fmt.Fprintf(connection, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target); err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(connection), &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT status = %d", response.StatusCode)
	}
	return connection
}

func connect(t *testing.T, proxyAddress, target string) *http.Response {
	t.Helper()
	connection, err := net.DialTimeout("tcp", strings.TrimPrefix(proxyAddress, "http://"), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { connection.Close() })
	if _, err := fmt.Fprintf(connection, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target); err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(connection), &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatal(err)
	}
	return response
}

// loopbackDialer omits the public-address guard so tests can exercise relay
// and forwarding against local servers.
func loopbackDialer() *net.Dialer {
	return &net.Dialer{Timeout: 5 * time.Second}
}
