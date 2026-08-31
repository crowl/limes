// Package httpsproxy implements the configured TLS-intercepting HTTPS backend.
package httpsproxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/crowl/limes/internal/ca"
)

const (
	tlsHandshakeTimeout = 10 * time.Second
	requestReadTimeout  = 5 * time.Minute
)

// Route decides whether a method and URL path are allowed.
type Route func(method, path string) bool

// ObserveRequest receives completed intercepted requests. It must return quickly.
type ObserveRequest func(method, path string, status int, started time.Time)

// Backend contains the already-validated HTTPS backend settings.
type Backend struct {
	Upstreams             map[string]*url.URL
	Allowed               Route
	RemoveHeaders         []string
	RemoveQueryParameters []string
	CredentialHeader      string
	CredentialValue       string
	Authority             *ca.Authority
	Observe               ObserveRequest
}

// New returns a handler for an explicit HTTPS proxy.
func New(backend Backend) http.Handler {
	return newHandler(backend, newTransport())
}

func newHandler(backend Backend, transport http.RoundTripper) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodConnect {
			http.Error(w, "HTTPS proxy requires CONNECT", http.StatusMethodNotAllowed)
			return
		}
		authority, err := canonicalAuthority(request.Host)
		if err != nil {
			http.Error(w, "invalid CONNECT authority", http.StatusBadRequest)
			return
		}
		upstream := backend.Upstreams[authority]
		if upstream == nil {
			http.Error(w, "upstream not allowed", http.StatusForbidden)
			return
		}
		hijacker, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "connection hijacking unavailable", http.StatusInternalServerError)
			return
		}
		connection, buffered, err := hijacker.Hijack()
		if err != nil {
			return
		}
		defer connection.Close()
		if buffered.Reader.Buffered() != 0 {
			return
		}
		if _, err := buffered.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
			return
		}
		if err := buffered.Flush(); err != nil {
			return
		}

		connectHost, _, _ := net.SplitHostPort(authority)
		certificate, err := backend.Authority.Certificate(connectHost)
		if err != nil {
			return
		}
		tlsConnection := tls.Server(connection, &tls.Config{
			GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
				sni := strings.ToLower(strings.TrimSuffix(hello.ServerName, "."))
				if sni != connectHost {
					return nil, errors.New("TLS server name does not match CONNECT authority")
				}
				return certificate, nil
			},
			MinVersion: tls.VersionTLS12,
		})
		if err := connection.SetDeadline(time.Now().Add(tlsHandshakeTimeout)); err != nil {
			return
		}
		if err := tlsConnection.HandshakeContext(request.Context()); err != nil {
			return
		}
		if err := connection.SetDeadline(time.Time{}); err != nil {
			return
		}
		defer tlsConnection.Close()
		serveTunnel(request.Context(), tlsConnection, authority, upstream, backend, transport)
	})
}

func serveTunnel(ctx context.Context, connection net.Conn, authority string, upstream *url.URL, backend Backend, transport http.RoundTripper) {
	reader := bufio.NewReader(connection)
	if err := connection.SetReadDeadline(time.Now().Add(requestReadTimeout)); err != nil {
		return
	}
	request, err := http.ReadRequest(reader)
	if err != nil {
		return
	}
	request = request.WithContext(ctx)
	request.RequestURI = ""
	request.Close = true
	started := time.Now()

	requestAuthority, err := requestHost(request)
	if err != nil || requestAuthority != authority {
		writeError(connection, http.StatusMisdirectedRequest, "request host does not match CONNECT authority")
		observe(backend, request.Method, request.URL.Path, http.StatusMisdirectedRequest, started)
		return
	}
	status := http.StatusBadGateway
	if !backend.Allowed(request.Method, request.URL.Path) {
		status = http.StatusForbidden
		writeError(connection, status, "endpoint not allowed")
		observe(backend, request.Method, request.URL.Path, status, started)
		return
	}
	request.URL.Scheme = upstream.Scheme
	request.URL.Host = upstream.Host
	request.Host = upstream.Host
	for _, header := range backend.RemoveHeaders {
		request.Header.Del(header)
	}
	request.Header.Del(backend.CredentialHeader)
	query := request.URL.Query()
	for _, name := range backend.RemoveQueryParameters {
		query.Del(name)
	}
	request.URL.RawQuery = query.Encode()
	request.Header.Set(backend.CredentialHeader, backend.CredentialValue)

	response, err := transport.RoundTrip(request)
	if err != nil {
		writeError(connection, http.StatusBadGateway, "upstream request failed")
		observe(backend, request.Method, request.URL.Path, http.StatusBadGateway, started)
		return
	}
	status = response.StatusCode
	response.Close = true
	if err := response.Write(connection); err != nil {
		response.Body.Close()
		observe(backend, request.Method, request.URL.Path, status, started)
		return
	}
	response.Body.Close()
	observe(backend, request.Method, request.URL.Path, status, started)
}

func observe(backend Backend, method, path string, status int, started time.Time) {
	if backend.Observe != nil {
		backend.Observe(method, path, status, started)
	}
}

func canonicalAuthority(value string) (string, error) {
	host, port, err := net.SplitHostPort(value)
	if err != nil || host == "" || port != "443" {
		return "", errors.New("authority must have port 443")
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if host == "" {
		return "", errors.New("authority host is empty")
	}
	return net.JoinHostPort(host, port), nil
}

func requestHost(request *http.Request) (string, error) {
	host := request.Host
	if _, _, err := net.SplitHostPort(host); err != nil {
		host = net.JoinHostPort(host, "443")
	}
	return canonicalAuthority(host)
}

func writeError(connection net.Conn, status int, message string) {
	body := message + "\n"
	_, _ = fmt.Fprintf(connection, "HTTP/1.1 %d %s\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", status, http.StatusText(status), len(body), body)
}

func newTransport() *http.Transport {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.DialContext = (&net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}).DialContext
	transport.ForceAttemptHTTP2 = true
	transport.MaxIdleConns = 100
	transport.IdleConnTimeout = 90 * time.Second
	transport.TLSHandshakeTimeout = 10 * time.Second
	transport.ExpectContinueTimeout = time.Second
	transport.ResponseHeaderTimeout = 5 * time.Minute
	return transport
}
