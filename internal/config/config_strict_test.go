package config

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadRejectsStrictFileBoundaries(t *testing.T) {
	valid := validConfigJSON()
	cases := []struct {
		name, body, want string
	}{
		{"empty", "", "configuration is empty"},
		{"malformed", "{", "parse configuration"},
		{"multiple values", valid + " {}", "multiple top-level values"},
		{"trailing content", valid + " garbage", "trailing configuration content"},
		{"unknown top-level", `{"unknown":true,` + valid[1:], "unknown field"},
		{"unknown listener", strings.Replace(valid, `"name":"one"`, `"name":"one","unknown":true`, 1), "unknown field"},
		{"unknown route", strings.Replace(valid, `"path":"/x"`, `"path":"/x","unknown":true`, 1), "unknown field"},
		{"unknown credential", strings.Replace(valid, `"header":"Authorization"`, `"header":"Authorization","unknown":true`, 1), "unknown field"},
		{"duplicate key", `{"listeners":[],"listeners":[]}`, "duplicate JSON object key"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			_, err := Load(writeConfig(t, testCase.body))
			if err == nil || !strings.Contains(err.Error(), testCase.want) {
				t.Fatalf("Load() error = %v, want containing %q", err, testCase.want)
			}
		})
	}
	if _, err := Load(writeConfig(t, strings.Repeat("x", MaxSize+1))); err == nil || !strings.Contains(err.Error(), "exceeds 1 MiB") {
		t.Fatalf("oversized Load() error = %v", err)
	}
	if _, err := Load(filepath.Join(t.TempDir(), "missing.json")); err == nil || !strings.Contains(err.Error(), "read configuration") {
		t.Fatalf("missing Load() error = %v", err)
	}
}

func TestLoadRejectsListenerAndBackendValidation(t *testing.T) {
	valid := validConfigJSON()
	cases := []struct{ name, body, want string }{
		{"empty listeners", `{"listeners":[]}`, "listeners must not be empty"},
		{"empty listener name", strings.Replace(valid, `"name":"one"`, `"name":""`, 1), "listener name"},
		{"empty address", strings.Replace(valid, `"address":"127.0.0.1:1"`, `"address":""`, 1), "address is required"},
		{"malformed address", strings.Replace(valid, `"address":"127.0.0.1:1"`, `"address":"bad"`, 1), "listener \"one\" address"},
		{"invalid listener port", strings.Replace(valid, `"address":"127.0.0.1:1"`, `"address":"127.0.0.1:0"`, 1), "invalid port"},
		{"duplicate listener name", `{"listeners":[` + validListener("one", "127.0.0.1:1") + `,` + validListener("one", "127.0.0.1:2") + `]}`, "duplicate listener name"},
		{"duplicate listener address", `{"listeners":[` + validListener("one", "127.0.0.1:1") + `,` + validListener("two", "127.0.0.1:1") + `]}`, "duplicate listener address"},
		{"empty backends", strings.Replace(valid, `"backends":[{"type":"http","upstreams":["https://example.test"],"routes":[{"method":"POST","path":"/x"}],"credential":{"environment":"KEY","header":"Authorization"}}]`, `"backends":[]`, 1), "has no backends"},
		{"missing type", strings.Replace(valid, `"type":"http",`, "", 1), "unknown backend type"},
		{"unknown type", strings.Replace(valid, `"type":"http"`, `"type":"other"`, 1), "unknown backend type"},
		{"anthropic subscription upstream", subscriptionWith("anthropic_subscription", `"upstreams":["https://x"]`), "does not belong"},
		{"subscription upstream", subscriptionWith("openai_subscription", `"upstreams":["https://x"]`), "does not belong"},
		{"subscription routes", subscriptionWith("openai_subscription", `"routes":[]`), "does not belong"},
		{"subscription headers", subscriptionWith("openai_subscription", `"remove_headers":["X"]`), "does not belong"},
		{"subscription query", subscriptionWith("openai_subscription", `"remove_query_parameters":["x"]`), "does not belong"},
		{"subscription credential", subscriptionWith("openai_subscription", `"credential":{"environment":"X","header":"X"}`), "does not belong"},
		{"xAI subscription upstream", subscriptionWith("xai_subscription", `"upstreams":["https://x"]`), "does not belong"},
		{"missing upstream", strings.Replace(valid, `"upstreams":["https://example.test"],`, "", 1), "upstreams must not be empty"},
		{"missing routes", strings.Replace(valid, `"routes":[{"method":"POST","path":"/x"}],`, "", 1), "routes must not be empty"},
		{"missing credential", strings.Replace(valid, `,"credential":{"environment":"KEY","header":"Authorization"}`, "", 1), "credential environment"},
		{"invalid environment", strings.Replace(valid, `"environment":"KEY"`, `"environment":"BAD-NAME"`, 1), "credential environment"},
		{"invalid header", strings.Replace(valid, `"header":"Authorization"`, `"header":"bad header"`, 1), "credential environment"},
		{"basic username colon", strings.Replace(valid, `"header":"Authorization"`, `"header":"Authorization","basic_username":"bad:name"`, 1), "basic_username"},
		{"basic and prefix", strings.Replace(valid, `"header":"Authorization"`, `"header":"Authorization","basic_username":"user","prefix":"Bearer "`, 1), "mutually exclusive"},
		{"empty query name", strings.Replace(valid, `"credential"`, `"remove_query_parameters":[""],"credential"`, 1), "query parameter"},
		{"duplicate query name", strings.Replace(valid, `"credential"`, `"remove_query_parameters":["x","x"],"credential"`, 1), "query parameter"},
		{"duplicate headers", strings.Replace(valid, `"credential"`, `"remove_headers":["X-Test","x-test"],"credential"`, 1), "duplicate header"},
		{"duplicate routes", strings.Replace(valid, `] ,`, `] ,`, 1), ""},
	}
	// The duplicate route case needs a second route in the same backend.
	cases[len(cases)-1].body = strings.Replace(valid, `[{"method":"POST","path":"/x"}]`, `[{"method":"POST","path":"/x"},{"method":"POST","path":"/x"}]`, 1)
	cases[len(cases)-1].want = "duplicate route"
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			_, err := Load(writeConfig(t, testCase.body))
			if err == nil || !strings.Contains(err.Error(), testCase.want) {
				t.Fatalf("Load() error = %v, want containing %q", err, testCase.want)
			}
		})
	}
}

func TestLoadAcceptsLoopbackAdmin(t *testing.T) {
	body := strings.Replace(validConfigJSON(), `{"listeners"`, `{"admin":{"address":"127.0.0.1:8799"},"listeners"`, 1)
	file, err := Load(writeConfig(t, body))
	if err != nil {
		t.Fatal(err)
	}
	if file.Admin == nil || file.Admin.Address != "127.0.0.1:8799" {
		t.Fatalf("admin = %#v", file.Admin)
	}
}

func TestLoadRejectsInvalidAdmin(t *testing.T) {
	for name, address := range map[string]string{
		"empty":            "",
		"malformed":        "bad",
		"zero port":        "127.0.0.1:0",
		"unspecified IPv4": "0.0.0.0:8799",
		"public":           "192.0.2.1:8799",
	} {
		t.Run(name, func(t *testing.T) {
			body := strings.Replace(validConfigJSON(), `{"listeners"`, `{"admin":{"address":"`+address+`"},"listeners"`, 1)
			if _, err := Load(writeConfig(t, body)); err == nil {
				t.Fatal("Load() accepted invalid admin address")
			}
		})
	}
}

func TestLoadRejectsAdminAndProxyAddressCollision(t *testing.T) {
	body := strings.Replace(validConfigJSON(), `{"listeners"`, `{"admin":{"address":"127.0.0.1:1"},"listeners"`, 1)
	if _, err := Load(writeConfig(t, body)); err == nil || !strings.Contains(err.Error(), "duplicate listener address") {
		t.Fatalf("Load() error = %v", err)
	}
}

func TestLoadAcceptsSeveralUpstreamsInAProxyRule(t *testing.T) {
	body := `{"proxy":{"address":"0.0.0.0:8800","rules":[{"name":"github","backends":[{"type":"http","upstreams":["https://github.com","https://api.github.com"],"routes":[{"method":"GET","path":"/{path...}"}],"remove_headers":["Authorization"],"credential":{"environment":"GITHUB_PAT","header":"Authorization","basic_username":"x-access-token"}}]}]}}`
	file, err := Load(writeConfig(t, body))
	if err != nil {
		t.Fatal(err)
	}
	backend := file.Proxy.Rules[0].Backends[0]
	if backend.Type != "http" || len(backend.Upstreams) != 2 || !backend.Routes[0].Pattern.Matches("/owner/repository") {
		t.Fatalf("backend = %#v", backend)
	}
}

func TestLoadRejectsInvalidUpstreams(t *testing.T) {
	claimed := `{"proxy":{"address":"0.0.0.0:8800","rules":[{"name":"github","backends":[{"type":"http","upstreams":["https://github.com"],"routes":[{"method":"GET","path":"/{path...}"}],"credential":{"environment":"GITHUB_PAT","header":"Authorization","prefix":"Bearer "}}]}]}}`
	for _, testCase := range []struct{ name, body, want string }{
		{"empty upstreams", strings.Replace(claimed, `"https://github.com"`, "", 1), "upstreams must not be empty"},
		{"claimed IP upstream", strings.Replace(claimed, "https://github.com", "https://127.0.0.1", 1), "must use a DNS hostname"},
		{"duplicate host", strings.Replace(claimed, `"https://github.com"`, `"https://github.com","https://github.com:443"`, 1), "duplicate upstream host"},
		{"relative upstream", strings.Replace(claimed, "https://github.com", "github.com", 1), "absolute http or https"},
		{"several upstreams on a listener", strings.Replace(validConfigJSON(), `"upstreams":["https://example.test"]`, `"upstreams":["https://example.test","https://other.test"]`, 1), "exactly one upstream"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			_, err := Load(writeConfig(t, testCase.body))
			if err == nil || !strings.Contains(err.Error(), testCase.want) {
				t.Fatalf("Load() error = %v, want containing %q", err, testCase.want)
			}
		})
	}
}

// A listener reaches its upstream directly, so it may address hosts the proxy
// could never claim a certificate for.
func TestLoadAcceptsIPAndPathUpstreamsOnAListener(t *testing.T) {
	for _, upstream := range []string{"http://127.0.0.1:9000", "https://example.test/api/v1", "https://example.test:8443"} {
		t.Run(upstream, func(t *testing.T) {
			body := strings.Replace(validConfigJSON(), "https://example.test", upstream, 1)
			if _, err := Load(writeConfig(t, body)); err != nil {
				t.Fatalf("Load() error = %v", err)
			}
		})
	}
}

func TestLoadAcceptsValidUpstreamsAndCredentialHeaderAlsoRemoved(t *testing.T) {
	for _, upstream := range []string{"http://example.test", "http://example.test/api/v1", "https://example.test", "https://[::1]", "https://[::1]:443"} {
		body := strings.Replace(validConfigJSON(), "https://example.test", upstream, 1)
		body = strings.Replace(body, `"credential"`, `"remove_headers":["Authorization"],"credential"`, 1)
		if _, err := Load(writeConfig(t, body)); err != nil {
			t.Fatalf("Load(%q): %v", upstream, err)
		}
	}
}

func TestRouteGrammarAndMatching(t *testing.T) {
	for _, path := range []string{"x", "/x{", "/x}", "/{a}{b}", "/{}", "/{1bad}"} {
		if _, err := CompileRoute(path); err == nil || !strings.Contains(err.Error(), "route") && !strings.Contains(err.Error(), "placeholder") {
			t.Errorf("CompileRoute(%q) error = %v", path, err)
		}
	}
	pattern, err := CompileRoute("/v1/{model}:run")
	if err != nil {
		t.Fatal(err)
	}
	for path, want := range map[string]bool{"/v1/a:run": true, "/v1/:run": false, "/v1/a/b:run": false, "/V1/a:run": false} {
		if pattern.Matches(path) != want {
			t.Errorf("Matches(%q) = %v, want %v", path, pattern.Matches(path), want)
		}
	}
	request := httptest.NewRequest("POST", "http://proxy/v1/a:run?ignored=query", nil)
	if !pattern.Matches(request.URL.Path) {
		t.Fatal("route did not match URL.Path independently of query")
	}
	file, err := Load(writeConfig(t, strings.Replace(validConfigJSON(), `"method":"POST"`, `"method":"post"`, 1)))
	if err != nil || file.Listeners[0].Backends[0].Routes[0].Method != "POST" {
		t.Fatalf("method normalization = %#v, %v", file, err)
	}
	_, err = Load(writeConfig(t, strings.Replace(validConfigJSON(), `"method":"POST"`, `"method":"bad method"`, 1)))
	if err == nil || !strings.Contains(err.Error(), "invalid route method") {
		t.Fatalf("invalid method error = %v", err)
	}
}

func writeConfig(t *testing.T, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func validConfigJSON() string {
	return `{"listeners":[{"name":"one","address":"127.0.0.1:1","backends":[{"type":"http","upstreams":["https://example.test"],"routes":[{"method":"POST","path":"/x"}],"credential":{"environment":"KEY","header":"Authorization"}}]}]}`
}

func validListener(name, address string) string {
	return `{"name":"` + name + `","address":"` + address + `","backends":[{"type":"http","upstreams":["https://example.test"],"routes":[{"method":"POST","path":"/x"}],"credential":{"environment":"KEY","header":"Authorization"}}]}`
}
func subscriptionWith(typ, field string) string {
	return `{"listeners":[{"name":"one","address":"127.0.0.1:1","backends":[{"type":"` + typ + `",` + field + `}]}]}`
}
