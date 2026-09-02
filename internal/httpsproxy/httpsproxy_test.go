package httpsproxy

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
)

func TestHTTPSProxyInterceptsSanitizesAndForwards(t *testing.T) {
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
	certificatePEM, err := caCertificate(getenv)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(certificatePEM) {
		t.Fatal("append CA certificate")
	}

	var got *http.Request
	type observation struct {
		method  string
		path    string
		status  int
		started time.Time
	}
	observations := make(chan observation, 1)
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		got = request.Clone(request.Context())
		w.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(w, "forwarded")
	}))
	defer upstream.Close()
	upstreamURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	transport := upstream.Client().Transport
	proxy := httptest.NewServer(newHandler(Backend{
		Upstreams: map[string]*url.URL{"api.github.test:443": upstreamURL},
		Allowed: func(method, path string) bool {
			return method == http.MethodPost && path == "/owner/repository/git-upload-pack"
		},
		RemoveHeaders:         []string{"Authorization", "X-Remove"},
		RemoveQueryParameters: []string{"secret"},
		CredentialHeader:      "Authorization",
		CredentialValue:       "Bearer real-token",
		Authority:             authority,
		Observe: func(method, path string, status int, started time.Time) {
			observations <- observation{method: method, path: path, status: status, started: started}
		},
	}, transport))
	defer proxy.Close()

	proxyURL, err := url.Parse(proxy.URL)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: &http.Transport{
		Proxy: http.ProxyURL(proxyURL),
		TLSClientConfig: &tls.Config{
			RootCAs:    roots,
			MinVersion: tls.VersionTLS12,
		},
	}}
	request, err := http.NewRequest(http.MethodPost, "https://api.github.test/owner/repository/git-upload-pack?secret=caller&safe=yes", strings.NewReader("body"))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer dummy")
	request.Header.Set("X-Remove", "caller")
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusCreated || string(body) != "forwarded" {
		t.Fatalf("response = %d %q", response.StatusCode, body)
	}
	if got == nil {
		t.Fatal("upstream was not called")
	}
	if got.Header.Get("Authorization") != "Bearer real-token" || got.Header.Get("X-Remove") != "" {
		t.Fatalf("upstream headers = %#v", got.Header)
	}
	if got.URL.Query().Has("secret") || got.URL.Query().Get("safe") != "yes" {
		t.Fatalf("upstream URL = %s", got.URL)
	}
	// The proxy observes the request after flushing the response, so wait for
	// the callback instead of racing it.
	var observed observation
	select {
	case observed = <-observations:
	case <-time.After(5 * time.Second):
		t.Fatal("request was not observed")
	}
	if observed.method != http.MethodPost || observed.path != "/owner/repository/git-upload-pack" || observed.status != http.StatusCreated || observed.started.IsZero() {
		t.Fatalf("observed request = %q %q %d at %v", observed.method, observed.path, observed.status, observed.started)
	}
}

func TestHTTPSProxyRejectsUnconfiguredConnectAuthority(t *testing.T) {
	proxy := httptest.NewServer(New(Backend{Upstreams: map[string]*url.URL{}}))
	defer proxy.Close()
	connection, err := net.DialTimeout("tcp", strings.TrimPrefix(proxy.URL, "http://"), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	if _, err := fmt.Fprint(connection, "CONNECT untrusted.test:443 HTTP/1.1\r\nHost: untrusted.test:443\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(connection), &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d", response.StatusCode)
	}
}

func caCertificate(getenv func(string) string) ([]byte, error) {
	var output strings.Builder
	if err := ca.Run([]string{"certificate"}, getenv, &output, io.Discard); err != nil {
		return nil, err
	}
	return []byte(output.String()), nil
}

func TestCanonicalAuthority(t *testing.T) {
	for _, testCase := range []struct {
		value string
		want  string
		ok    bool
	}{
		{"API.GITHUB.COM:443", "api.github.com:443", true},
		{"api.github.com:80", "", false},
		{"api.github.com", "", false},
	} {
		t.Run(testCase.value, func(t *testing.T) {
			got, err := canonicalAuthority(testCase.value)
			if (err == nil) != testCase.ok || got != testCase.want {
				t.Fatalf("canonicalAuthority() = %q, %v", got, err)
			}
		})
	}
}
