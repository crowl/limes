package config

import (
	"strings"
	"testing"
)

func TestLoadAcceptsProxy(t *testing.T) {
	file, err := Load(writeConfig(t, `{"proxy":{"address":"0.0.0.0:8800","rules":[`+validRule("openai")+`]}}`))
	if err != nil {
		t.Fatal(err)
	}
	if file.Proxy == nil || file.Proxy.Address != "0.0.0.0:8800" || len(file.Proxy.Rules) != 1 {
		t.Fatalf("proxy = %#v", file.Proxy)
	}
	rule := file.Proxy.Rules[0]
	if rule.Name != "openai" || len(rule.Backends) != 1 || !rule.Backends[0].Routes[0].Pattern.Matches("/v1/responses") {
		t.Fatalf("rule = %#v", rule)
	}
}

func TestLoadDefaultsUnclaimedToRelay(t *testing.T) {
	for _, testCase := range []struct{ name, field, want string }{
		{"omitted", "", Relay},
		{"relay", `"unclaimed":"relay",`, Relay},
		{"deny", `"unclaimed":"deny",`, Deny},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			body := `{"proxy":{"address":"0.0.0.0:8800",` + testCase.field + `"rules":[` + validRule("openai") + `]}}`
			file, err := Load(writeConfig(t, body))
			if err != nil {
				t.Fatal(err)
			}
			if file.Proxy.Unclaimed != testCase.want {
				t.Fatalf("unclaimed = %q, want %q", file.Proxy.Unclaimed, testCase.want)
			}
		})
	}
}

func TestLoadRejectsInvalidProxy(t *testing.T) {
	for _, testCase := range []struct{ name, body, want string }{
		{"missing address", `{"proxy":{"rules":[` + validRule("openai") + `]}}`, "proxy address is required"},
		{"malformed address", `{"proxy":{"address":"bad","rules":[` + validRule("openai") + `]}}`, "proxy address"},
		{"zero port", `{"proxy":{"address":"0.0.0.0:0","rules":[` + validRule("openai") + `]}}`, "invalid port"},
		{"no rules", `{"proxy":{"address":"0.0.0.0:8800","rules":[]}}`, "proxy rules must not be empty"},
		{"unknown unclaimed policy", `{"proxy":{"address":"0.0.0.0:8800","unclaimed":"drop","rules":[` + validRule("openai") + `]}}`, "proxy unclaimed must be"},
		{"empty rule name", `{"proxy":{"address":"0.0.0.0:8800","rules":[` + validRule("") + `]}}`, "proxy rule name"},
		{"duplicate rule name", `{"proxy":{"address":"0.0.0.0:8800","rules":[` + validRule("openai") + `,` + validRule("openai") + `]}}`, "duplicate proxy rule name"},
		{"no backends", `{"proxy":{"address":"0.0.0.0:8800","rules":[{"name":"openai","backends":[]}]}}`, `proxy rule "openai" has no backends`},
		{"invalid backend", `{"proxy":{"address":"0.0.0.0:8800","rules":[{"name":"openai","backends":[{"type":"other"}]}]}}`, "unknown backend type"},
		{"foreign backend field", `{"proxy":{"address":"0.0.0.0:8800","rules":[{"name":"openai","backends":[{"type":"openai_subscription","upstreams":["https://x"]}]}]}}`, "does not belong"},
		{"unknown rule field", `{"proxy":{"address":"0.0.0.0:8800","rules":[{"name":"openai","unknown":true,"backends":[]}]}}`, "unknown field"},
		{"collides with admin", `{"admin":{"address":"127.0.0.1:8799"},"proxy":{"address":"127.0.0.1:8799","rules":[` + validRule("openai") + `]}}`, "conflicts with admin"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			_, err := Load(writeConfig(t, testCase.body))
			if err == nil || !strings.Contains(err.Error(), testCase.want) {
				t.Fatalf("Load() error = %v, want containing %q", err, testCase.want)
			}
		})
	}
}

func validRule(name string) string {
	return `{"name":"` + name + `","backends":[{"type":"http","upstreams":["https://api.openai.com"],"routes":[{"method":"POST","path":"/v1/responses"}],"credential":{"environment":"OPENAI_API_KEY","header":"Authorization","prefix":"Bearer "}}]}`
}
