package anthropic

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const maxCredentialSize = 1 << 20

var errNoSubscriptionCredentials = errors.New("no valid Claude subscription credentials found")

type oauthCredential struct {
	AccessToken  string
	RefreshToken string
	ExpiresAt    int64
	Scopes       []string
	fields       map[string]json.RawMessage
}

type credentialFile struct {
	OAuth  oauthCredential
	fields map[string]json.RawMessage
}

type credentialStore interface {
	read() (*credentialFile, error)
	write(*credentialFile) error
	description() string
}

type plaintextStore struct {
	path   string
	rename func(oldPath, newPath string) error
}

type keychainStore struct {
	service string
	account string
	run     func(args []string, input string) ([]byte, error)
}

func findSubscriptionCredentials(getenv func(string) string) (credentialStore, *credentialFile, error) {
	return findSubscriptionCredentialsAt(getenv, runtime.GOOS, defaultKeychainRunner)
}

func findSubscriptionCredentialsAt(getenv func(string) string, operatingSystem string, keychainRunner func([]string, string) ([]byte, error)) (credentialStore, *credentialFile, error) {
	stores := credentialStores(getenv, operatingSystem, keychainRunner)
	var candidateErr error
	for _, store := range stores {
		file, err := store.read()
		if err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				candidateErr = fmt.Errorf("%s: %w", store.description(), err)
			}
			continue
		}
		if err := validateCredentialFileAt(file, nowTime()); err != nil {
			candidateErr = fmt.Errorf("%s: %w", store.description(), err)
			continue
		}
		return store, file, nil
	}
	if candidateErr != nil {
		return nil, nil, fmt.Errorf("load subscription credentials: %w", candidateErr)
	}
	return nil, nil, errNoSubscriptionCredentials
}

func credentialStores(getenv func(string) string, operatingSystem string, keychainRunner func([]string, string) ([]byte, error)) []credentialStore {
	configDirectory := getenv("CLAUDE_CONFIG_DIR")
	stores := make([]credentialStore, 0, 2)
	if operatingSystem == "darwin" {
		service := "Claude Code-credentials"
		if configDirectory != "" {
			digest := sha256.Sum256([]byte(configDirectory))
			service += "-" + hex.EncodeToString(digest[:])[:8]
		}
		account := getenv("USER")
		if account == "" {
			if current, err := user.Current(); err == nil {
				account = current.Username
			}
		}
		if account == "" {
			account = "claude-code-user"
		}
		stores = append(stores, &keychainStore{service: service, account: account, run: keychainRunner})
	}
	if configDirectory != "" {
		stores = append(stores, newPlaintextStore(filepath.Join(configDirectory, ".credentials.json")))
	} else if home := getenv("HOME"); home != "" {
		stores = append(stores, newPlaintextStore(filepath.Join(home, ".claude", ".credentials.json")))
	}
	return stores
}

func newPlaintextStore(path string) *plaintextStore {
	return &plaintextStore{path: path, rename: os.Rename}
}

func (store *plaintextStore) description() string { return store.path }

func (store *plaintextStore) read() (*credentialFile, error) {
	file, err := os.Open(store.path)
	if err != nil {
		return nil, fmt.Errorf("read credential file: %w", err)
	}
	defer func() { _ = file.Close() }()
	contents, err := io.ReadAll(io.LimitReader(file, maxCredentialSize+1))
	if err != nil {
		return nil, fmt.Errorf("read credential file: %w", err)
	}
	if len(contents) > maxCredentialSize {
		return nil, errors.New("credential file exceeds 1 MiB")
	}
	return parseCredentialFile(contents)
}

func (store *plaintextStore) write(file *credentialFile) error {
	contents, err := marshalCredentialFile(file)
	if err != nil {
		return err
	}
	directory := filepath.Dir(store.path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return fmt.Errorf("create credential directory: %w", err)
	}
	temporary, err := os.CreateTemp(directory, ".credentials.json.tmp-*")
	if err != nil {
		return fmt.Errorf("create temporary credential file: %w", err)
	}
	temporaryPath := temporary.Name()
	keepTemporary := true
	defer func() {
		if keepTemporary {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("secure temporary credential file: %w", err)
	}
	if _, err := temporary.Write(contents); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("write temporary credential file: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("sync temporary credential file: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close temporary credential file: %w", err)
	}
	if err := store.rename(temporaryPath, store.path); err != nil {
		return fmt.Errorf("replace credential file: %w", err)
	}
	keepTemporary = false
	return nil
}

func (store *keychainStore) description() string { return "macOS Keychain service " + store.service }

func (store *keychainStore) read() (*credentialFile, error) {
	contents, err := store.run([]string{"find-generic-password", "-a", store.account, "-s", store.service, "-w"}, "")
	if err != nil || len(bytes.TrimSpace(contents)) == 0 {
		return nil, fmt.Errorf("read Keychain credential: %w", os.ErrNotExist)
	}
	if len(contents) > maxCredentialSize {
		return nil, errors.New("Keychain credential exceeds 1 MiB")
	}
	return parseCredentialFile(bytes.TrimSpace(contents))
}

func (store *keychainStore) write(file *credentialFile) error {
	contents, err := marshalCredentialFile(file)
	if err != nil {
		return err
	}
	encoded := hex.EncodeToString(bytes.TrimSpace(contents))
	command := fmt.Sprintf("add-generic-password -U -a \"%s\" -s \"%s\" -X \"%s\"\n", keychainQuote(store.account), keychainQuote(store.service), encoded)
	if _, err := store.run([]string{"-i"}, command); err != nil {
		return fmt.Errorf("update Keychain credential: %w", err)
	}
	return nil
}

func keychainQuote(value string) string {
	value = strings.ReplaceAll(value, `\`, `\\`)
	return strings.ReplaceAll(value, `"`, `\"`)
}

func defaultKeychainRunner(args []string, input string) ([]byte, error) {
	command := exec.Command("security", args...)
	if input != "" {
		command.Stdin = strings.NewReader(input)
	}
	return command.Output()
}

func parseCredentialFile(contents []byte) (*credentialFile, error) {
	var fields map[string]json.RawMessage
	decoder := json.NewDecoder(bytes.NewReader(contents))
	if err := decoder.Decode(&fields); err != nil {
		return nil, fmt.Errorf("parse credential store: %w", err)
	}
	if fields == nil {
		return nil, errors.New("parse credential store: expected a JSON object")
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		if err == nil {
			return nil, errors.New("parse credential store: multiple JSON values")
		}
		return nil, fmt.Errorf("parse credential store: trailing content: %w", err)
	}
	var oauthFields map[string]json.RawMessage
	if raw := fields["claudeAiOauth"]; len(raw) == 0 {
		return nil, errNoSubscriptionCredentials
	} else if err := json.Unmarshal(raw, &oauthFields); err != nil || oauthFields == nil {
		if err == nil {
			err = errors.New("expected a JSON object")
		}
		return nil, fmt.Errorf("parse claudeAiOauth credential: %w", err)
	}
	oauth := oauthCredential{fields: oauthFields}
	if err := decodeField(oauthFields, "accessToken", &oauth.AccessToken); err != nil {
		return nil, err
	}
	if err := decodeField(oauthFields, "refreshToken", &oauth.RefreshToken); err != nil {
		return nil, err
	}
	if err := decodeField(oauthFields, "expiresAt", &oauth.ExpiresAt); err != nil {
		return nil, err
	}
	if err := decodeField(oauthFields, "scopes", &oauth.Scopes); err != nil {
		return nil, err
	}
	return &credentialFile{OAuth: oauth, fields: fields}, nil
}

func decodeField(fields map[string]json.RawMessage, name string, target any) error {
	raw := fields[name]
	if len(raw) == 0 {
		return nil
	}
	if err := json.Unmarshal(raw, target); err != nil {
		return fmt.Errorf("parse claudeAiOauth %s: %w", name, err)
	}
	return nil
}

func validateCredentialFileAt(file *credentialFile, now time.Time) error {
	if file == nil || file.OAuth.AccessToken == "" {
		return errors.New("access token is missing")
	}
	if !hasScope(file.OAuth.Scopes, inferenceScope) {
		return errors.New("user:inference scope is missing")
	}
	if file.OAuth.ExpiresAt <= 0 {
		return errors.New("access token expiry is missing")
	}
	if tokenNeedsRefresh(file.OAuth, now) && file.OAuth.RefreshToken == "" {
		return errors.New("refresh token is missing")
	}
	return nil
}

func marshalCredentialFile(file *credentialFile) ([]byte, error) {
	oauthFields := cloneFields(file.OAuth.fields)
	setJSONField(oauthFields, "accessToken", file.OAuth.AccessToken)
	setJSONField(oauthFields, "refreshToken", file.OAuth.RefreshToken)
	setJSONField(oauthFields, "expiresAt", file.OAuth.ExpiresAt)
	setJSONField(oauthFields, "scopes", file.OAuth.Scopes)
	encodedOAuth, err := json.Marshal(oauthFields)
	if err != nil {
		return nil, fmt.Errorf("marshal claudeAiOauth credential: %w", err)
	}
	fields := cloneFields(file.fields)
	fields["claudeAiOauth"] = encodedOAuth
	contents, err := json.MarshalIndent(fields, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal credential store: %w", err)
	}
	return append(contents, '\n'), nil
}

func cloneFields(fields map[string]json.RawMessage) map[string]json.RawMessage {
	cloned := make(map[string]json.RawMessage, len(fields))
	for name, value := range fields {
		cloned[name] = append(json.RawMessage(nil), value...)
	}
	return cloned
}

func setJSONField(fields map[string]json.RawMessage, name string, value any) {
	encoded, _ := json.Marshal(value)
	fields[name] = encoded
}
