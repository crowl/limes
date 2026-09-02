package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadUnreadableFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	contents := validConfigJSON()
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0); err != nil {
		t.Skipf("cannot make configuration file unreadable: %v", err)
	}
	t.Cleanup(func() {
		if err := os.Chmod(path, 0o600); err != nil {
			t.Errorf("restore configuration file permissions: %v", err)
		}
	})

	_, err := Load(path)
	if err == nil {
		t.Skip("current user can read a mode 0000 configuration file")
	}
	if !strings.Contains(err.Error(), "read configuration") {
		t.Fatalf("Load() error = %v, want read configuration context", err)
	}
}

func TestResolvePath(t *testing.T) {
	path, err := ResolvePath("/explicit/config.json", func(string) string { return "" })
	if err != nil || path != "/explicit/config.json" {
		t.Fatalf("ResolvePath() = %q, %v", path, err)
	}
	path, err = ResolvePath("", func(name string) string {
		if name == "XDG_CONFIG_HOME" {
			return "/xdg"
		}
		return ""
	})
	if err != nil || path != "/xdg/limes/config.json" {
		t.Fatalf("XDG path = %q, %v", path, err)
	}
	path, err = ResolvePath("", func(name string) string {
		if name == "HOME" {
			return "/home/test"
		}
		return ""
	})
	if err != nil || path != "/home/test/.config/limes/config.json" {
		t.Fatalf("HOME path = %q, %v", path, err)
	}
	if _, err := ResolvePath("", func(string) string { return "" }); err == nil {
		t.Fatal("ResolvePath() succeeded without a path")
	}
}

func TestLoadRejectsInvalidMethodsAddressesAndUpstreams(t *testing.T) {
	valid := func(upstream, method, address string) string {
		return `{"proxy":{"address":"` + address + `","rules":[{"name":"one","backends":[{"type":"http","upstreams":["` + upstream + `"],"routes":[{"method":"` + method + `","path":"/x"}],"credential":{"environment":"KEY","header":"Authorization"}}]}]}}`
	}
	for name, document := range map[string]string{
		"non_ascii_method": valid("https://example.test", "ſ", "127.0.0.1:1"),
		"text_port":        valid("https://example.test", "POST", "127.0.0.1:abc"),
		"large_port":       valid("https://example.test", "POST", "[::1]:99999"),
		"userinfo":         valid("https://key@example.test", "POST", "127.0.0.1:1"),
		"ftp":              valid("ftp://example.test", "POST", "127.0.0.1:1"),
		"query":            valid("https://example.test?key=value", "POST", "127.0.0.1:1"),
		"fragment":         valid("https://example.test/#fragment", "POST", "127.0.0.1:1"),
		"hostless":         valid("https:/path", "POST", "127.0.0.1:1"),
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.json")
			if err := os.WriteFile(path, []byte(document), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := Load(path); err == nil {
				t.Fatal("Load() succeeded")
			}
		})
	}
}

func TestCompileRouteMatchesExactAndPlaceholder(t *testing.T) {
	exact, err := CompileRoute("/v1/responses")
	if err != nil {
		t.Fatal(err)
	}
	if !exact.Matches("/v1/responses") || exact.Matches("/v1/Responses") {
		t.Fatal("exact matching is incorrect")
	}
	pattern, err := CompileRoute("/v1/models/{model}:countTokens")
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/v1/models/gemini:countTokens", "/v1/models/a/b:countTokens", "/v1/models/:countTokens"} {
		if pattern.Matches(path) != (path == "/v1/models/gemini:countTokens") {
			t.Errorf("Matches(%q) incorrect", path)
		}
	}
	multi, err := CompileRoute("/{path...}")
	if err != nil {
		t.Fatal(err)
	}
	for path, want := range map[string]bool{"/owner/repository/git-upload-pack": true, "/graphql": true, "/": false} {
		if multi.Matches(path) != want {
			t.Errorf("multi-segment Matches(%q) = %v, want %v", path, multi.Matches(path), want)
		}
	}
}

func TestExampleConfiguration(t *testing.T) {
	if _, err := Load(filepath.Join("..", "..", "config.example.json")); err != nil {
		t.Fatal(err)
	}
}
