package openai

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestAvailableDistinguishesMissingAndMalformedCredentials(t *testing.T) {
	missing := t.TempDir()
	if handler, available, err := Available(func(name string) string {
		if name == "CODEX_HOME" {
			return missing
		}
		return ""
	}); err != nil || available || handler != nil {
		t.Fatalf("missing Available() = %v, %v, %v", handler, available, err)
	}

	malformed := t.TempDir()
	if err := os.WriteFile(filepath.Join(malformed, "auth.json"), []byte(`not json`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, available, err := Available(func(name string) string {
		if name == "CODEX_HOME" {
			return malformed
		}
		return ""
	}); err == nil || available {
		t.Fatalf("malformed Available() = available %v, error %v", available, err)
	}
}

func TestFindSubscriptionCredentialsUsesFirstValidCandidate(t *testing.T) {
	root := t.TempDir()
	codex := filepath.Join(root, "codex")
	local := filepath.Join(root, "local")
	home := filepath.Join(root, "home")
	for _, path := range []string{filepath.Join(codex, "auth.json"), filepath.Join(local, "auth.json"), filepath.Join(home, ".codex", "auth.json"), filepath.Join(home, ".chatgpt-local", "auth.json")} {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(codex, "auth.json"), []byte(`{"tokens":{"api_key":"not a subscription"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	valid := `{"tokens":{"access_token":"` + testJWT(t, "second") + `","refresh_token":"refresh"},"last_refresh":"` + time.Now().UTC().Format(time.RFC3339) + `"}`
	if err := os.WriteFile(filepath.Join(local, "auth.json"), []byte(valid), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".codex", "auth.json"), []byte(`not json`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".chatgpt-local", "auth.json"), []byte(valid), 0o600); err != nil {
		t.Fatal(err)
	}
	path, file, err := findSubscriptionCredentialsAt(func(name string) string {
		switch name {
		case "CODEX_HOME":
			return codex
		case "CHATGPT_LOCAL_HOME":
			return local
		case "HOME":
			return home
		}
		return ""
	}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if path != filepath.Join(local, "auth.json") || accountID(file.Tokens) != "second" {
		t.Fatalf("selected %q with account %q", path, accountID(file.Tokens))
	}
}

func TestFindSubscriptionCredentialsPrefersCodexHome(t *testing.T) {
	root := t.TempDir()
	for _, directory := range []string{"codex", "local"} {
		if err := os.Mkdir(filepath.Join(root, directory), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for directory, account := range map[string]string{"codex": "first", "local": "second"} {
		contents := `{"tokens":{"access_token":"` + testJWT(t, account) + `"},"last_refresh":"` + time.Now().UTC().Format(time.RFC3339) + `"}`
		if err := os.WriteFile(filepath.Join(root, directory, "auth.json"), []byte(contents), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	path, _, err := findSubscriptionCredentialsAt(func(name string) string {
		if name == "CODEX_HOME" {
			return filepath.Join(root, "codex")
		}
		if name == "CHATGPT_LOCAL_HOME" {
			return filepath.Join(root, "local")
		}
		return ""
	}, time.Now())
	if err != nil || path != filepath.Join(root, "codex", "auth.json") {
		t.Fatalf("path = %q, err = %v", path, err)
	}
}

func testJWT(t *testing.T, account string) string {
	t.Helper()
	payload := `{"exp":4102444800,"https://api.openai.com/auth":{"chatgpt_account_id":"` + account + `"}}`
	return "x." + base64.RawURLEncoding.EncodeToString([]byte(payload)) + ".x"
}
