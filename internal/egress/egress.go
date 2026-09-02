// Package egress implements the Limes egress proxy. It terminates TLS for the
// hosts a rule claims so caller credentials can be replaced by host-held ones,
// and either denies or blindly relays every other destination.
package egress

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/crowl/limes/internal/ca"
)

const (
	tlsHandshakeTimeout    = 10 * time.Second
	interceptHeaderTimeout = 10 * time.Second
	interceptIdleTimeout   = 90 * time.Second
)

// Unclaimed decides what the proxy does with destinations no rule claims.
type Unclaimed int

const (
	// Deny rejects every unclaimed destination.
	Deny Unclaimed = iota
	// Relay forwards unclaimed destinations unmodified and uninspected.
	Relay
)

// Observe receives the outcome of connections the proxy handled itself rather
// than handing to a claimed handler. It must return quickly.
type Observe func(authority string, status int, started time.Time)

// Proxy contains the already-validated egress proxy settings.
type Proxy struct {
	// Claim resolves a lowercase hostname to the handler that owns it and
	// returns nil when no rule claims the host.
	Claim     func(host string) http.Handler
	Unclaimed Unclaimed
	Authority *ca.Authority
	Observe   Observe
}

// New returns a handler for an explicit HTTP and HTTPS proxy.
func New(proxy Proxy) http.Handler {
	return newHandler(proxy, publicDialer())
}

func newHandler(proxy Proxy, dialer *net.Dialer) http.Handler {
	forward := newForwarder(proxy, dialer)
	return http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.Method == http.MethodConnect {
			serveConnect(w, request, proxy, dialer)
			return
		}
		forward.ServeHTTP(w, request)
	})
}

func serveConnect(w http.ResponseWriter, request *http.Request, proxy Proxy, dialer *net.Dialer) {
	started := time.Now()
	host, port, err := canonicalAuthority(request.Host)
	if err != nil {
		http.Error(w, "invalid CONNECT authority", http.StatusBadRequest)
		return
	}
	authority := net.JoinHostPort(host, port)
	if handler := claimed(proxy, host); handler != nil {
		if port != "443" {
			reject(w, proxy, authority, http.StatusForbidden, "claimed host is only served on port 443", started)
			return
		}
		intercept(w, request, authority, host, handler, proxy)
		return
	}
	if proxy.Unclaimed == Deny {
		reject(w, proxy, authority, http.StatusForbidden, "upstream not allowed", started)
		return
	}
	relay(w, request, authority, dialer, proxy, started)
}

func intercept(w http.ResponseWriter, request *http.Request, authority, host string, handler http.Handler, proxy Proxy) {
	certificate, err := proxy.Authority.Certificate(host)
	if err != nil {
		http.Error(w, "interception certificate unavailable", http.StatusInternalServerError)
		return
	}
	connection, err := establishTunnel(w)
	if err != nil {
		return
	}
	defer connection.Close()

	tlsConnection := tls.Server(connection, &tls.Config{
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			name := strings.ToLower(strings.TrimSuffix(hello.ServerName, "."))
			if name != host {
				return nil, errors.New("TLS server name does not match CONNECT authority")
			}
			return certificate, nil
		},
		NextProtos: []string{"http/1.1"},
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
	serveIntercepted(request.Context(), tlsConnection, authority, handler)
}

// serveIntercepted runs a standard HTTP server over the terminated tunnel so
// claimed handlers see ordinary origin requests and keep-alive, chunked
// bodies, and streaming behave as they do on a bound listener.
func serveIntercepted(ctx context.Context, connection net.Conn, authority string, handler http.Handler) {
	server := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
			if !matchesAuthority(request.Host, authority) {
				http.Error(w, "request host does not match CONNECT authority", http.StatusMisdirectedRequest)
				return
			}
			handler.ServeHTTP(w, request)
		}),
		ReadHeaderTimeout: interceptHeaderTimeout,
		IdleTimeout:       interceptIdleTimeout,
		BaseContext:       func(net.Listener) context.Context { return ctx },
	}
	_ = server.Serve(newTunnelListener(connection))
}

func claimed(proxy Proxy, host string) http.Handler {
	if proxy.Claim == nil {
		return nil
	}
	return proxy.Claim(host)
}

func reject(w http.ResponseWriter, proxy Proxy, authority string, status int, message string, started time.Time) {
	http.Error(w, message, status)
	if proxy.Observe != nil {
		proxy.Observe(authority, status, started)
	}
}

// establishTunnel hijacks the connection and confirms the tunnel. The returned
// connection reads any bytes the client pipelined behind CONNECT.
func establishTunnel(w http.ResponseWriter) (net.Conn, error) {
	connection, buffered, err := http.NewResponseController(w).Hijack()
	if err != nil {
		http.Error(w, "connection hijacking unavailable", http.StatusInternalServerError)
		return nil, err
	}
	if _, err := buffered.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		connection.Close()
		return nil, err
	}
	if err := buffered.Flush(); err != nil {
		connection.Close()
		return nil, err
	}
	return bufferedConn{Conn: connection, reader: buffered.Reader}, nil
}

type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (connection bufferedConn) Read(buffer []byte) (int, error) {
	return connection.reader.Read(buffer)
}

func canonicalAuthority(value string) (host, port string, err error) {
	host, port, err = net.SplitHostPort(value)
	if err != nil {
		return "", "", fmt.Errorf("authority must be host:port: %w", err)
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if host == "" {
		return "", "", errors.New("authority host is empty")
	}
	if !validPort(port) {
		return "", "", fmt.Errorf("authority has invalid port %q", port)
	}
	return host, port, nil
}

func validPort(port string) bool {
	if port == "" || len(port) > 5 {
		return false
	}
	number := 0
	for _, digit := range port {
		if digit < '0' || digit > '9' {
			return false
		}
		number = number*10 + int(digit-'0')
	}
	return number > 0 && number <= 65535
}

func matchesAuthority(value, authority string) bool {
	host, port, err := net.SplitHostPort(value)
	if err != nil {
		host, port = value, "443"
	}
	return net.JoinHostPort(strings.ToLower(strings.TrimSuffix(host, ".")), port) == authority
}
