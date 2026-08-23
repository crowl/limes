package config

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadValidatesExplicitUpstreamPortsAndIPv6(t *testing.T) {
	valid := func(upstream string) string {
		return `{"listeners":[{"name":"one","address":"127.0.0.1:1","backends":[{"type":"http","upstream":"` + upstream + `","routes":[{"method":"POST","path":"/x"}],"credential":{"environment":"KEY","header":"Authorization"}}]}]}`
	}
	cases := []struct {
		name     string
		upstream string
		wantErr  bool
	}{
		{"no port", "https://example.test", false},
		{"lower bound", "https://example.test:1", false},
		{"upper bound", "https://example.test:65535", false},
		{"out of range", "https://example.test:99999", true},
		{"zero", "https://example.test:0", true},
		{"negative", "https://example.test:-1", true},
		{"malformed", "https://example.test:abc", true},
		{"empty", "https://example.test:", true},
		{"IPv6 no port", "https://[::1]", false},
		{"IPv6 port", "https://[::1]:443", false},
		{"invalid IPv6 authority", "https://::1", true},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.json")
			if err := os.WriteFile(path, []byte(valid(testCase.upstream)), 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := Load(path)
			if (err != nil) != testCase.wantErr {
				t.Fatalf("Load() error = %v, want error %v", err, testCase.wantErr)
			}
		})
	}
}

func TestParseRejectsUnknownFlagsAndPositionalArguments(t *testing.T) {
	for _, args := range [][]string{{"--unknown"}, {"config.json"}} {
		_, err := Parse(args, io.Discard)
		if err == nil {
			t.Fatalf("Parse(%q) succeeded", args)
		}
	}
}

func TestResolvePathErrorUsesConfigFlagName(t *testing.T) {
	_, err := ResolvePath("", func(string) string { return "" })
	if err == nil || !strings.Contains(err.Error(), "--config-path") {
		t.Fatalf("ResolvePath() error = %v", err)
	}
}
