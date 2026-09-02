package app

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/crowl/limes/internal/anthropic"
	"github.com/crowl/limes/internal/config"
	"github.com/crowl/limes/internal/openai"
	"github.com/crowl/limes/internal/proxy"
	"github.com/crowl/limes/internal/xai"
)

type provider struct {
	name     string
	address  string
	hosts    string
	authMode string
	handler  http.Handler
	backends *backendSelector
	rules    []provider
}

type runningProvider struct {
	provider provider
	listener net.Listener
	server   *http.Server
}

type runtimeBackend struct {
	index       int
	typ         string
	target      string
	handler     http.Handler
	unavailable string
}

type backendSelector struct {
	mu        sync.RWMutex
	backends  []runtimeBackend
	active    int
	listening bool
}

type backendSnapshot struct {
	Index       int
	Type        string
	Target      string
	Available   bool
	Active      bool
	Unavailable string
}

func prepareBackend(index int, backend config.Backend, getenv func(string) string) (runtimeBackend, error) {
	result := runtimeBackend{index: index, typ: backend.Type, target: backendTarget(backend)}
	switch backend.Type {
	case "http":
		key := getenv(backend.Credential.Environment)
		if key == "" {
			result.unavailable = "environment credential is not set"
			return result, nil
		}
		handler, err := newUpstreamProxy(backend, key)
		if err != nil {
			result.unavailable = "backend could not be initialized"
			return result, err
		}
		result.handler = handler
	case "anthropic_subscription":
		handler, available, err := anthropic.Available(getenv)
		if err != nil {
			result.unavailable = "subscription credentials could not be loaded"
			return result, err
		}
		if !available {
			result.unavailable = "subscription credentials are unavailable"
			return result, nil
		}
		result.handler = handler
	case "openai_subscription":
		handler, available, err := openai.Available(getenv)
		if err != nil {
			result.unavailable = "subscription credentials could not be loaded"
			return result, err
		}
		if !available {
			result.unavailable = "subscription credentials are unavailable"
			return result, nil
		}
		result.handler = handler
	case "xai_subscription":
		handler, available, err := xai.Available(getenv)
		if err != nil {
			result.unavailable = "subscription credentials could not be loaded"
			return result, err
		}
		if !available {
			result.unavailable = "subscription credentials are unavailable"
			return result, nil
		}
		result.handler = handler
	default:
		result.unavailable = "backend could not be initialized"
		return result, fmt.Errorf("unknown backend type %q", backend.Type)
	}
	return result, nil
}

func backendTarget(backend config.Backend) string {
	switch backend.Type {
	case "anthropic_subscription":
		return "Anthropic subscription"
	case "openai_subscription":
		return "OpenAI subscription"
	case "xai_subscription":
		return "xAI subscription"
	case "http":
		hosts := make([]string, 0, len(backend.Upstreams))
		for _, value := range backend.Upstreams {
			upstream, err := url.Parse(value)
			if err == nil {
				hosts = append(hosts, upstream.Host)
			}
		}
		return strings.Join(hosts, ", ")
	}
	return ""
}

func newBackendSelector(backends []runtimeBackend) *backendSelector {
	selector := &backendSelector{backends: backends, active: -1}
	for i := range backends {
		if backends[i].handler != nil {
			selector.active = i
			break
		}
	}
	return selector
}

func (selector *backendSelector) ServeHTTP(w http.ResponseWriter, request *http.Request) {
	selector.mu.RLock()
	active := selector.active
	var handler http.Handler
	if active >= 0 {
		handler = selector.backends[active].handler
	}
	selector.mu.RUnlock()
	if handler == nil {
		http.Error(w, "no backend is available", http.StatusServiceUnavailable)
		return
	}
	handler.ServeHTTP(w, request)
}

func (selector *backendSelector) switchTo(index int) (backendSnapshot, error) {
	selector.mu.Lock()
	defer selector.mu.Unlock()
	for i := range selector.backends {
		backend := selector.backends[i]
		if backend.index != index {
			continue
		}
		if backend.handler == nil {
			return backendSnapshot{}, errors.New("backend is unavailable")
		}
		selector.active = i
		return snapshotBackend(backend, true), nil
	}
	return backendSnapshot{}, errors.New("backend does not exist")
}

func (selector *backendSelector) activeBackend() (runtimeBackend, bool) {
	selector.mu.RLock()
	defer selector.mu.RUnlock()
	if selector.active < 0 {
		return runtimeBackend{}, false
	}
	return selector.backends[selector.active], true
}

func (selector *backendSelector) snapshots() ([]backendSnapshot, bool) {
	selector.mu.RLock()
	defer selector.mu.RUnlock()
	backends := make([]backendSnapshot, len(selector.backends))
	for i, backend := range selector.backends {
		backends[i] = snapshotBackend(backend, i == selector.active)
	}
	return backends, selector.listening
}

func (selector *backendSelector) setListening(listening bool) {
	selector.mu.Lock()
	selector.listening = listening
	selector.mu.Unlock()
}

func snapshotBackend(backend runtimeBackend, active bool) backendSnapshot {
	return backendSnapshot{
		Index:       backend.index,
		Type:        backend.typ,
		Target:      backend.target,
		Available:   backend.handler != nil,
		Active:      active,
		Unavailable: backend.unavailable,
	}
}

func bindProviders(p []provider) ([]runningProvider, error) {
	return bindProvidersWithListener(p, net.Listen)
}

func bindProvidersWithListener(p []provider, listen func(string, string) (net.Listener, error)) ([]runningProvider, error) {
	var out []runningProvider
	for _, x := range p {
		if x.backends != nil {
			if _, available := x.backends.activeBackend(); !available {
				continue
			}
		}
		listener, err := listen("tcp", x.address)
		if err != nil {
			closeListeners(out)
			return nil, fmt.Errorf("listen for %s on %s: %w", x.name, x.address, err)
		}
		setProviderListening(x, true)
		out = append(out, runningProvider{x, listener, &http.Server{
			Addr:              x.address,
			Handler:           x.handler,
			ReadTimeout:       requestReadTimeout,
			ReadHeaderTimeout: 10 * time.Second,
			IdleTimeout:       90 * time.Second,
		}})
	}
	return out, nil
}

func closeListeners(running []runningProvider) {
	for _, instance := range running {
		setProviderListening(instance.provider, false)
		_ = instance.listener.Close()
	}
}

func setProviderListening(p provider, listening bool) {
	if p.backends != nil {
		p.backends.setListening(listening)
	}
	for _, rule := range p.rules {
		rule.backends.setListening(listening)
	}
}

// newUpstreamProxy builds the credential-injecting reverse proxy for a backend.
// A backend serving several hosts selects among them by request host, which the
// egress proxy has already matched against the CONNECT authority.
func newUpstreamProxy(backend config.Backend, key string) (http.Handler, error) {
	hosts := make(map[string]http.Handler, len(backend.Upstreams))
	var single http.Handler
	for _, value := range backend.Upstreams {
		upstream, err := url.Parse(value)
		if err != nil {
			return nil, err
		}
		handler := proxy.New(proxy.Backend{
			Upstream:              upstream,
			Allowed:               routeMatcher(backend.Routes),
			RemoveHeaders:         backend.RemoveHeaders,
			RemoveQueryParameters: backend.RemoveQueryParameters,
			CredentialHeader:      backend.Credential.Header,
			CredentialValue:       credentialValue(backend.Credential, key),
		})
		hosts[strings.ToLower(upstream.Hostname())] = handler
		single = handler
	}
	if len(hosts) == 1 {
		return single, nil
	}
	return http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		handler := hosts[strings.ToLower(requestHostname(request))]
		if handler == nil {
			http.Error(w, "upstream not allowed", http.StatusForbidden)
			return
		}
		handler.ServeHTTP(w, request)
	}), nil
}

func requestHostname(request *http.Request) string {
	host, _, err := net.SplitHostPort(request.Host)
	if err != nil {
		host = request.Host
	}
	return strings.TrimSuffix(host, ".")
}

func routeMatcher(routes []config.Route) proxy.Route {
	return func(method, path string) bool {
		for _, route := range routes {
			if route.Method == method && route.Pattern.Matches(path) {
				return true
			}
		}
		return false
	}
}

func credentialValue(credential *config.Credential, key string) string {
	if credential.BasicUsername != "" {
		value := base64.StdEncoding.EncodeToString([]byte(credential.BasicUsername + ":" + key))
		return "Basic " + value
	}
	return credential.Prefix + key
}
