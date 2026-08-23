package app

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/crowl/limes/internal/config"
	"github.com/crowl/limes/internal/openai"
	"github.com/crowl/limes/internal/proxy"
)

type provider struct {
	name     string
	address  string
	authMode string
	handler  http.Handler
}

type runningProvider struct {
	provider provider
	listener net.Listener
	server   *http.Server
}

func configuredProviders(cfg config.Options, getenv func(string) string, logger *slog.Logger) ([]provider, error) {
	fc, err := config.Load(cfg.Path)
	if err != nil {
		return nil, err
	}
	return selectProviders(fc, getenv, logger)
}

func selectProviders(cfg config.File, getenv func(string) string, logger *slog.Logger) ([]provider, error) {
	var out []provider
	for _, listenerConfig := range cfg.Listeners {
		var chosen *provider
		for _, backendConfig := range listenerConfig.Backends {
			switch backendConfig.Type {
			case "http":
				if key := getenv(backendConfig.Credential.Environment); key != "" {
					handler, err := newHTTPProxy(backendConfig, key)
					if err != nil {
						return nil, err
					}
					chosen = &provider{name: listenerConfig.Name, address: listenerConfig.Address, authMode: "http", handler: handler}
				}
			case "openai_subscription":
				if handler, available, err := openai.Available(getenv); err != nil {
					return nil, err
				} else if available {
					chosen = &provider{name: listenerConfig.Name, address: listenerConfig.Address, authMode: "openai_subscription", handler: handler}
				}
			}
			if chosen != nil {
				break
			}
		}
		if chosen == nil {
			logger.Info("listener disabled", "listener", listenerConfig.Name, "reason", "no backend credentials available")
			continue
		}
		logger.Info("backend selected", "listener", listenerConfig.Name, "backend", chosen.authMode)
		out = append(out, *chosen)
	}
	if len(out) == 0 {
		return nil, errors.New("no configured listener has an available backend")
	}
	return out, nil
}

func bindProviders(p []provider) ([]runningProvider, error) {
	return bindProvidersWithListener(p, net.Listen)
}

func bindProvidersWithListener(p []provider, listen func(string, string) (net.Listener, error)) ([]runningProvider, error) {
	var out []runningProvider
	for _, x := range p {
		listener, err := listen("tcp", x.address)
		if err != nil {
			closeListeners(out)
			return nil, fmt.Errorf("listen for %s on %s: %w", x.name, x.address, err)
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
		_ = instance.listener.Close()
	}
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
		CredentialValue:       backend.Credential.Prefix + key,
	}), nil
}
