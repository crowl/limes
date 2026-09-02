package app

import (
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/crowl/limes/internal/anthropic"
	"github.com/crowl/limes/internal/ca"
	"github.com/crowl/limes/internal/config"
	"github.com/crowl/limes/internal/egress"
	"github.com/crowl/limes/internal/openai"
	"github.com/crowl/limes/internal/xai"
)

const proxyProviderName = "proxy"

// configureProxy builds the shared proxy listener. Its rules claim the hosts
// Limes intercepts to replace caller credentials; every other destination is
// relayed to its real origin without inspection.
func configureProxy(cfg config.Proxy, getenv func(string) string, logger *slog.Logger, requests *requestLog) (provider, error) {
	authority, err := ca.Load(getenv)
	if err != nil {
		return provider{}, fmt.Errorf("load Limes CA: %w", err)
	}

	rules := make([]provider, 0, len(cfg.Rules))
	claims := make(map[string]*backendSelector)
	for _, ruleConfig := range cfg.Rules {
		hosts := make([]string, 0, len(ruleConfig.Backends))
		backends := make([]runtimeBackend, 0, len(ruleConfig.Backends))
		for i, backendConfig := range ruleConfig.Backends {
			claimed, err := claimedHosts(backendConfig)
			if err != nil {
				return provider{}, fmt.Errorf("proxy rule %q backend %d: %w", ruleConfig.Name, i, err)
			}
			hosts = appendMissing(hosts, claimed)

			backend, err := prepareBackend(i, backendConfig, getenv)
			if err != nil {
				logger.Warn("backend initialization failed",
					"rule", ruleConfig.Name,
					"backend", backend.typ,
					"error", err,
				)
			}
			if requests != nil && backend.handler != nil {
				backend.handler = requests.wrap(ruleConfig.Name, backend.typ, backend.handler)
			}
			backends = append(backends, backend)
		}

		selector := newBackendSelector(backends)
		for _, host := range hosts {
			if _, claimed := claims[host]; claimed {
				return provider{}, fmt.Errorf("proxy rule %q claims host %q, which another rule already claims", ruleConfig.Name, host)
			}
			claims[host] = selector
		}
		if active, ok := selector.activeBackend(); ok {
			logger.Info("proxy rule ready", "rule", ruleConfig.Name, "backend", active.typ, "hosts", strings.Join(hosts, ", "))
		} else {
			logger.Info("proxy rule disabled", "rule", ruleConfig.Name, "reason", "no backend credentials available")
		}
		rules = append(rules, provider{
			name:     ruleConfig.Name,
			hosts:    strings.Join(hosts, ", "),
			backends: selector,
		})
	}

	unclaimed := egress.Relay
	if cfg.Unclaimed == config.Deny {
		unclaimed = egress.Deny
	}
	interceptor := egress.Proxy{
		Claim: func(host string) http.Handler {
			selector, claimed := claims[host]
			if !claimed {
				return nil
			}
			return selector
		},
		Unclaimed: unclaimed,
		Authority: authority,
	}
	if requests != nil {
		interceptor.Observe = func(authority string, status int, started time.Time) {
			requests.observe(proxyProviderName, "relay", http.MethodConnect, authority, status, started)
		}
	}
	return provider{
		name:     proxyProviderName,
		address:  cfg.Address,
		authMode: proxyProviderName,
		handler:  egress.New(interceptor),
		rules:    rules,
	}, nil
}

// claimedHosts reports the hosts a backend answers for when it is reached
// through the proxy. A subscription backend claims the provider's public API
// host even though it serves the request from other credentials.
func claimedHosts(backend config.Backend) ([]string, error) {
	switch backend.Type {
	case "anthropic_subscription":
		return []string{anthropic.InterceptedHost}, nil
	case "openai_subscription":
		return []string{openai.InterceptedHost}, nil
	case "xai_subscription":
		return []string{xai.InterceptedHost}, nil
	case "http":
		hosts := make([]string, 0, len(backend.Upstreams))
		for _, upstream := range backend.Upstreams {
			host, err := upstreamHostname(upstream)
			if err != nil {
				return nil, err
			}
			hosts = append(hosts, host)
		}
		return hosts, nil
	default:
		return nil, fmt.Errorf("unknown backend type %q", backend.Type)
	}
}

func upstreamHostname(value string) (string, error) {
	upstream, err := url.Parse(value)
	if err != nil {
		return "", fmt.Errorf("parse upstream %q: %w", value, err)
	}
	host := strings.ToLower(upstream.Hostname())
	if host == "" {
		return "", fmt.Errorf("upstream %q has no host", value)
	}
	return host, nil
}

func appendMissing(existing, candidates []string) []string {
	for _, candidate := range candidates {
		found := false
		for _, host := range existing {
			if host == candidate {
				found = true
				break
			}
		}
		if !found {
			existing = append(existing, candidate)
		}
	}
	return existing
}
