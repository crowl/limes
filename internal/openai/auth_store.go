package openai

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

const maxAuthFileSize = 1 << 20

type authStore struct {
	rename func(oldPath, newPath string) error
}

func newAuthStore() authStore {
	return authStore{rename: os.Rename}
}

func (store authStore) read(path string) (*authFile, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("read auth file: %w", err)
	}
	defer func() { _ = file.Close() }()

	contents, err := io.ReadAll(io.LimitReader(file, maxAuthFileSize+1))
	if err != nil {
		return nil, fmt.Errorf("read auth file: %w", err)
	}
	if len(contents) > maxAuthFileSize {
		return nil, errors.New("auth file exceeds 1 MiB")
	}

	var fields map[string]json.RawMessage
	if err := json.Unmarshal(contents, &fields); err != nil {
		return nil, fmt.Errorf("parse auth file: %w", err)
	}

	var tokens storedTokens
	if err := json.Unmarshal(fields["tokens"], &tokens); err != nil {
		return nil, fmt.Errorf("parse auth tokens: %w", err)
	}

	var lastRefresh string
	if value := fields["last_refresh"]; len(value) != 0 {
		if err := json.Unmarshal(value, &lastRefresh); err != nil {
			return nil, fmt.Errorf("parse last refresh: %w", err)
		}
	}

	return &authFile{
		Tokens:      tokens,
		LastRefresh: lastRefresh,
		fields:      fields,
	}, nil
}

func (store authStore) write(path string, file *authFile) error {
	fields := make(map[string]json.RawMessage, len(file.fields)+2)
	for name, value := range file.fields {
		fields[name] = value
	}

	tokens, err := json.Marshal(file.Tokens)
	if err != nil {
		return fmt.Errorf("marshal auth tokens: %w", err)
	}
	lastRefresh, err := json.Marshal(file.LastRefresh)
	if err != nil {
		return fmt.Errorf("marshal last refresh: %w", err)
	}
	fields["tokens"] = tokens
	fields["last_refresh"] = lastRefresh

	contents, err := json.MarshalIndent(fields, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal auth file: %w", err)
	}
	contents = append(contents, '\n')

	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, ".auth.json.tmp-*")
	if err != nil {
		return fmt.Errorf("create temporary auth file: %w", err)
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
		return fmt.Errorf("secure temporary auth file: %w", err)
	}
	if _, err := temporary.Write(contents); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("write temporary auth file: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("sync temporary auth file: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close temporary auth file: %w", err)
	}
	if err := store.rename(temporaryPath, path); err != nil {
		return fmt.Errorf("replace auth file: %w", err)
	}
	keepTemporary = false
	return nil
}

var errNoSubscriptionCredentials = errors.New("no valid Codex subscription credentials found")
