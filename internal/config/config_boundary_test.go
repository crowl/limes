package config

import (
	"errors"
	"flag"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseExplicitConfigPathAndHelp(t *testing.T) {
	var output strings.Builder
	options, err := Parse([]string{"--config-path", "/tmp/config.json"}, &output)
	if err != nil {
		t.Fatal(err)
	}
	if options.Path != "/tmp/config.json" {
		t.Fatalf("path = %q", options.Path)
	}
	_, err = Parse([]string{"--help"}, &output)
	if !errors.Is(err, flag.ErrHelp) || !IsHelp(err) || !strings.Contains(output.String(), "config-path") {
		t.Fatalf("help error = %v, output = %q", err, output.String())
	}
}

func TestParseResolvesEnvironmentPathsWithoutProcessEnvironment(t *testing.T) {
	tests := []struct {
		name string
		env  map[string]string
		want string
	}{
		{"XDG", map[string]string{"XDG_CONFIG_HOME": "/xdg", "HOME": "/home"}, "/xdg/limes/config.json"},
		{"HOME fallback", map[string]string{"HOME": "/home"}, "/home/.config/limes/config.json"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			options, err := parseWithGetenv(nil, io.Discard, func(name string) string { return test.env[name] })
			if err != nil || options.Path != test.want {
				t.Fatalf("Parse() = %#v, %v", options, err)
			}
		})
	}
	_, err := parseWithGetenv(nil, io.Discard, func(string) string { return "" })
	if err == nil || !strings.Contains(err.Error(), "cannot resolve configuration path") {
		t.Fatalf("Parse() error = %v", err)
	}
	_, err = parseWithGetenv([]string{"--unknown"}, io.Discard, func(string) string { return "" })
	if err == nil {
		t.Fatal("Parse() accepted unknown flag")
	}
	_, err = parseWithGetenv([]string{"config.json"}, io.Discard, func(string) string { return "" })
	if err == nil || !strings.Contains(err.Error(), "positional") {
		t.Fatalf("Parse() error = %v", err)
	}
}

func TestLoadRejectsRoutePatternAndZeroListenerPort(t *testing.T) {
	for _, testCase := range []struct {
		name     string
		document string
		want     string
	}{
		{
			name: "route pattern is not configuration", want: "unknown field",
			document: `{"listeners":[{"name":"one","address":"127.0.0.1:1","backends":[{"type":"http","upstream":"https://example.test","routes":[{"method":"POST","path":"/x","Pattern":{}}],"credential":{"environment":"KEY","header":"Authorization"}}]}]}`,
		},
		{
			name: "zero listener port", want: "invalid port",
			document: `{"listeners":[{"name":"one","address":"127.0.0.1:0","backends":[{"type":"http","upstream":"https://example.test","routes":[{"method":"POST","path":"/x"}],"credential":{"environment":"KEY","header":"Authorization"}}]}]}`,
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.json")
			if err := os.WriteFile(path, []byte(testCase.document), 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := Load(path)
			if err == nil || !strings.Contains(err.Error(), testCase.want) {
				t.Fatalf("Load() error = %v, want containing %q", err, testCase.want)
			}
		})
	}
}
