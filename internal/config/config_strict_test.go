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
		{"legacy listeners", `{"listeners":[]}`, "unknown field"},
		{"unknown rule", strings.Replace(valid, `"name":"one"`, `"name":"one","unknown":true`, 1), "unknown field"},
		{"unknown route", strings.Replace(valid, `"path":"/x"`, `"path":"/x","unknown":true`, 1), "unknown field"},
		{"unknown credential", strings.Replace(valid, `"header":"Authorization"`, `"header":"Authorization","unknown":true`, 1), "unknown field"},
		{"duplicate key", `{"proxy":null,"proxy":null}`, "duplicate JSON object key"},
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

func TestLoadRejectsProxyAndBackendValidation(t *testing.T) {
	valid := validConfigJSON()
	cases := []struct{ name, body, want string }{
		{"missing proxy", `{}`, "proxy is required"},
		{"empty rule name", strings.Replace(valid, `"name":"one"`, `"name":""`, 1), "proxy rule name"},
		{"empty address", strings.Replace(valid, `"address":"127.0.0.1:1"`, `"address":""`, 1), "address is required"},
		{"malformed address", strings.Replace(valid, `"address":"127.0.0.1:1"`, `"address":"bad"`, 1), "proxy address"},
		{"invalid proxy port", strings.Replace(valid, `"address":"127.0.0.1:1"`, `"address":"127.0.0.1:0"`, 1), "invalid port"},
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
		{"duplicate routes", strings.Replace(valid, `[{"method":"POST","path":"/x"}]`, `[{"method":"POST","path":"/x"},{"method":"POST","path":"/x"}]`, 1), "duplicate route"},
	}
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
	body := strings.Replace(validConfigJSON(), `{"proxy"`, `{"admin":{"address":"127.0.0.1:8799"},"proxy"`, 1)
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
		"empty": "", "malformed": "bad", "zero port": "127.0.0.1:0",
		"unspecified IPv4": "0.0.0.0:8799", "public": "192.0.2.1:8799",
	} {
		t.Run(name, func(t *testing.T) {
			body := strings.Replace(validConfigJSON(), `{"proxy"`, `{"admin":{"address":"`+address+`"},"proxy"`, 1)
			if _, err := Load(writeConfig(t, body)); err == nil {
				t.Fatal("Load() accepted invalid admin address")
			}
		})
	}
}

func TestLoadRejectsAdminAndProxyAddressCollision(t *testing.T) {
	body := strings.Replace(validConfigJSON(), `{"proxy"`, `{"admin":{"address":"127.0.0.1:1"},"proxy"`, 1)
	if _, err := Load(writeConfig(t, body)); err == nil || !strings.Contains(err.Error(), "conflicts with admin") {
		t.Fatalf("Load() error = %v", err)
	}
}

func TestLoadAcceptsSeveralUpstreamsInRule(t *testing.T) {
	body := strings.Replace(validConfigJSON(), `"https://example.test"`, `"https://example.test","https://other.test"`, 1)
	file, err := Load(writeConfig(t, body))
	if err != nil {
		t.Fatal(err)
	}
	backend := file.Proxy.Rules[0].Backends[0]
	if len(backend.Upstreams) != 2 || !backend.Routes[0].Pattern.Matches("/x") {
		t.Fatalf("backend = %#v", backend)
	}
}

func TestLoadRejectsInvalidUpstreams(t *testing.T) {
	for _, testCase := range []struct{ name, upstream, want string }{
		{"IP upstream", "https://127.0.0.1", "DNS hostname"},
		{"relative upstream", "example.test", "absolute http or https"},
		{"userinfo", "https://key@example.test", "absolute http or https"},
		{"query", "https://example.test?key=value", "absolute http or https"},
		{"fragment", "https://example.test/#fragment", "absolute http or https"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			body := strings.Replace(validConfigJSON(), "https://example.test", testCase.upstream, 1)
			_, err := Load(writeConfig(t, body))
			if err == nil || !strings.Contains(err.Error(), testCase.want) {
				t.Fatalf("Load() error = %v, want containing %q", err, testCase.want)
			}
		})
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
	if err != nil || file.Proxy.Rules[0].Backends[0].Routes[0].Method != "POST" {
		t.Fatalf("method normalization = %#v, %v", file, err)
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
	return `{"proxy":{"address":"127.0.0.1:1","rules":[{"name":"one","backends":[{"type":"http","upstreams":["https://example.test"],"routes":[{"method":"POST","path":"/x"}],"credential":{"environment":"KEY","header":"Authorization"}}]}]}}`
}

func subscriptionWith(typ, field string) string {
	return `{"proxy":{"address":"127.0.0.1:1","rules":[{"name":"one","backends":[{"type":"` + typ + `",` + field + `}]}]}}`
}
