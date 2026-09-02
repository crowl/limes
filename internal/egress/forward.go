package egress

import (
	"errors"
	"net"
	"net/http"
	"net/http/httputil"
	"strings"
	"time"
)

// newForwarder serves proxied plain-HTTP requests, which carry an absolute
// request URI instead of establishing a tunnel.
func newForwarder(proxy Proxy, dialer *net.Dialer) http.Handler {
	reverse := &httputil.ReverseProxy{
		Rewrite: func(request *httputil.ProxyRequest) {
			request.Out.URL = request.In.URL
			request.Out.Host = request.In.Host
		},
		Transport:     newForwardTransport(dialer),
		FlushInterval: -1,
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, err error) {
			if errors.Is(err, errPrivateDestination) {
				http.Error(w, "relay destination is not a public address", http.StatusForbidden)
				return
			}
			http.Error(w, "relay destination is unreachable", http.StatusBadGateway)
		},
	}
	return http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		started := time.Now()
		if !request.URL.IsAbs() || request.URL.Host == "" || request.URL.Scheme != "http" {
			http.Error(w, "proxy requires CONNECT or an absolute http request URI", http.StatusBadRequest)
			return
		}
		authority := request.URL.Host
		host := strings.ToLower(strings.TrimSuffix(request.URL.Hostname(), "."))
		if claimed(proxy, host) != nil {
			reject(w, proxy, authority, http.StatusForbidden, "claimed host is only served over HTTPS", started)
			return
		}
		if proxy.Unclaimed == Deny {
			reject(w, proxy, authority, http.StatusForbidden, "upstream not allowed", started)
			return
		}
		recorder := &statusRecorder{ResponseWriter: w}
		reverse.ServeHTTP(recorder, request)
		if proxy.Observe != nil {
			proxy.Observe(authority, recorder.statusCode(), started)
		}
	})
}

func newForwardTransport(dialer *net.Dialer) *http.Transport {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.DialContext = dialer.DialContext
	transport.ForceAttemptHTTP2 = false
	transport.MaxIdleConns = 100
	transport.IdleConnTimeout = 90 * time.Second
	transport.TLSHandshakeTimeout = 10 * time.Second
	transport.ExpectContinueTimeout = time.Second
	transport.ResponseHeaderTimeout = 5 * time.Minute
	return transport
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (w *statusRecorder) WriteHeader(status int) {
	if status >= 100 && status < 200 {
		w.ResponseWriter.WriteHeader(status)
		return
	}
	if w.status == 0 {
		w.status = status
	}
	w.ResponseWriter.WriteHeader(status)
}

func (w *statusRecorder) Write(body []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.ResponseWriter.Write(body)
}

func (w *statusRecorder) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (w *statusRecorder) statusCode() int {
	if w.status == 0 {
		return http.StatusOK
	}
	return w.status
}
