// Package proxy implements the provider-agnostic configured HTTP backend.
package proxy

import (
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"
)

// Route decides whether a method and URL path are allowed.
type Route func(method, path string) bool

// Backend contains the already-validated HTTP backend settings.
type Backend struct {
	Upstream              *url.URL
	Allowed               Route
	RemoveHeaders         []string
	RemoveQueryParameters []string
	CredentialHeader      string
	CredentialValue       string
}

// New returns a streaming reverse proxy for one configured backend.
func New(backend Backend) http.Handler {
	return newHandler(backend, NewTransport())
}

func newHandler(backend Backend, transport http.RoundTripper) http.Handler {
	proxy := &httputil.ReverseProxy{
		Rewrite: func(request *httputil.ProxyRequest) {
			request.SetURL(backend.Upstream)
			for _, header := range backend.RemoveHeaders {
				request.Out.Header.Del(header)
			}
			request.Out.Header.Del(backend.CredentialHeader)
			query := request.Out.URL.Query()
			for _, name := range backend.RemoveQueryParameters {
				query.Del(name)
			}
			request.Out.URL.RawQuery = query.Encode()
			request.Out.Header.Set(backend.CredentialHeader, backend.CredentialValue)
		},
		Transport:     transport,
		FlushInterval: -1,
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, _ error) {
			http.Error(w, "upstream request failed", http.StatusBadGateway)
		},
	}
	return http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if !backend.Allowed(request.Method, request.URL.Path) {
			http.Error(w, "endpoint not allowed", http.StatusForbidden)
			return
		}
		proxy.ServeHTTP(w, request)
	})
}

// NewTransport returns a transport with explicit bounds suitable for upstreams.
func NewTransport() *http.Transport {
	return &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           (&net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: time.Second,
		ResponseHeaderTimeout: 5 * time.Minute,
	}
}
