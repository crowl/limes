package app

import (
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/crowl/limes/internal/ca"
	"github.com/crowl/limes/internal/config"
	"github.com/crowl/limes/internal/httpsproxy"
	"github.com/crowl/limes/internal/openai"
	"github.com/crowl/limes/internal/proxy"
	"github.com/crowl/limes/internal/xai"
)

type provider struct {
	name     string
	address  string
	authMode string
	handler  http.Handler
	backends *backendSelector
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

// selectProviders retains the original startup-only selection path for focused
// compatibility tests. The application runtime uses configureRuntimeProviders.
func selectProviders(cfg config.File, getenv func(string) string, logger *slog.Logger) ([]provider, error) {
	configured := configureRuntimeProviders(cfg, getenv, logger)
	out := make([]provider, 0, len(configured))
	for _, candidate := range configured {
		active, available := candidate.backends.activeBackend()
		if !available {
			continue
		}
		candidate.authMode = active.typ
		candidate.handler = active.handler
		candidate.backends = nil
		out = append(out, candidate)
	}
	if len(out) == 0 {
		return nil, errors.New("no configured listener has an available backend")
	}
	return out, nil
}

func configureRuntimeProviders(cfg config.File, getenv func(string) string, logger *slog.Logger) []provider {
	providers := make([]provider, 0, len(cfg.Listeners))
	var authority *ca.Authority
	for _, listenerConfig := range cfg.Listeners {
		backends := make([]runtimeBackend, 0, len(listenerConfig.Backends))
		for i, backendConfig := range listenerConfig.Backends {
			backend, err := prepareBackend(i, backendConfig, getenv, &authority)
			if err != nil {
				logger.Warn("backend initialization failed",
					"listener", listenerConfig.Name,
					"backend", backend.typ,
					"error", err,
				)
			}
			backends = append(backends, backend)
		}
		selector := newBackendSelector(backends)
		active, ok := selector.activeBackend()
		if !ok {
			logger.Info("listener disabled", "listener", listenerConfig.Name, "reason", "no backend credentials available")
		} else {
			logger.Info("backend selected", "listener", listenerConfig.Name, "backend", active.typ)
		}
		providers = append(providers, provider{
			name:     listenerConfig.Name,
			address:  listenerConfig.Address,
			handler:  selector,
			backends: selector,
		})
	}
	return providers
}

func prepareBackend(index int, backend config.Backend, getenv func(string) string, authority **ca.Authority) (runtimeBackend, error) {
	result := runtimeBackend{index: index, typ: backend.Type, target: backendTarget(backend)}
	switch backend.Type {
	case "http":
		key := getenv(backend.Credential.Environment)
		if key == "" {
			result.unavailable = "environment credential is not set"
			return result, nil
		}
		handler, err := newHTTPProxy(backend, key)
		if err != nil {
			result.unavailable = "backend could not be initialized"
			return result, err
		}
		result.handler = handler
	case "https":
		key := getenv(backend.Credential.Environment)
		if key == "" {
			result.unavailable = "environment credential is not set"
			return result, nil
		}
		if *authority == nil {
			loaded, err := ca.Load(getenv)
			if err != nil {
				result.unavailable = "local certificate authority is unavailable"
				return result, fmt.Errorf("load Limes CA: %w", err)
			}
			*authority = loaded
		}
		handler, err := newHTTPSProxy(backend, key, *authority)
		if err != nil {
			result.unavailable = "backend could not be initialized"
			return result, err
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
	case "openai_subscription":
		return "OpenAI subscription"
	case "xai_subscription":
		return "xAI subscription"
	case "http":
		upstream, err := url.Parse(backend.Upstream)
		if err == nil {
			return upstream.Host
		}
	case "https":
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

func availableProviders(providers []provider) []provider {
	available := make([]provider, 0, len(providers))
	for _, provider := range providers {
		if provider.backends == nil {
			available = append(available, provider)
			continue
		}
		if active, ok := provider.backends.activeBackend(); ok {
			provider.authMode = active.typ
			available = append(available, provider)
		}
	}
	return available
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
		if x.backends != nil {
			x.backends.setListening(true)
		}
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
		if instance.provider.backends != nil {
			instance.provider.backends.setListening(false)
		}
		_ = instance.listener.Close()
	}
}

func newHTTPSProxy(backend config.Backend, key string, authority *ca.Authority) (http.Handler, error) {
	upstreams := make(map[string]*url.URL, len(backend.Upstreams))
	for _, value := range backend.Upstreams {
		upstream, err := url.Parse(value)
		if err != nil {
			return nil, err
		}
		host := strings.ToLower(upstream.Hostname())
		authorityName := net.JoinHostPort(host, "443")
		upstreams[authorityName] = upstream
	}
	allowed := func(method, path string) bool {
		for _, route := range backend.Routes {
			if route.Method == method && route.Pattern.Matches(path) {
				return true
			}
		}
		return false
	}
	return httpsproxy.New(httpsproxy.Backend{
		Upstreams:             upstreams,
		Allowed:               allowed,
		RemoveHeaders:         backend.RemoveHeaders,
		RemoveQueryParameters: backend.RemoveQueryParameters,
		CredentialHeader:      backend.Credential.Header,
		CredentialValue:       credentialValue(backend.Credential, key),
		Authority:             authority,
	}), nil
}

func newHTTPProxy(backend config.Backend, key string) (http.Handler, error) {
	target, err := url.Parse(backend.Upstream)
	if err != nil {
		return nil, err
	}
	allowed := func(method, path string) bool {
		for _, route := range backend.Routes {
			if route.Method == method && route.Pattern.Matches(path) {
				return true
			}
		}
		return false
	}
	return proxy.New(proxy.Backend{
		Upstream:              target,
		Allowed:               allowed,
		RemoveHeaders:         backend.RemoveHeaders,
		RemoveQueryParameters: backend.RemoveQueryParameters,
		CredentialHeader:      backend.Credential.Header,
		CredentialValue:       credentialValue(backend.Credential, key),
	}), nil
}

func credentialValue(credential *config.Credential, key string) string {
	if credential.BasicUsername != "" {
		value := base64.StdEncoding.EncodeToString([]byte(credential.BasicUsername + ":" + key))
		return "Basic " + value
	}
	return credential.Prefix + key
}
