package xai

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const maxAuthFileSize = 1 << 20

var errNoSubscriptionCredentials = errors.New("no valid Grok subscription credentials found")

type authEntry struct {
	AccessToken   string
	RefreshToken  string
	UserID        string
	PrincipalType string
	PrincipalID   string
	ExpiresAt     time.Time
	fields        map[string]json.RawMessage
}

type authFile struct {
	EntryKey string
	Entry    authEntry
	fields   map[string]json.RawMessage
}

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
	decoder := json.NewDecoder(bytes.NewReader(contents))
	if err := decoder.Decode(&fields); err != nil {
		return nil, fmt.Errorf("parse auth file: %w", err)
	}
	if fields == nil {
		return nil, errors.New("parse auth file: expected a JSON object")
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		if err == nil {
			return nil, errors.New("parse auth file: multiple JSON values")
		}
		return nil, fmt.Errorf("parse auth file: trailing content: %w", err)
	}

	entryKey, entryFields, err := findAuthEntry(fields)
	if err != nil {
		return nil, err
	}
	entry, err := parseAuthEntry(entryFields)
	if err != nil {
		return nil, err
	}
	return &authFile{EntryKey: entryKey, Entry: entry, fields: fields}, nil
}

func findAuthEntry(fields map[string]json.RawMessage) (string, map[string]json.RawMessage, error) {
	keys := []string{xaiAuthEntryKey}
	for key := range fields {
		if key != xaiAuthEntryKey && strings.HasSuffix(key, "::"+grokClientID) {
			keys = append(keys, key)
		}
	}
	for _, key := range keys {
		raw, ok := fields[key]
		if !ok {
			continue
		}
		var entry map[string]json.RawMessage
		if err := json.Unmarshal(raw, &entry); err == nil && entry != nil {
			return key, entry, nil
		}
	}
	return "", nil, errNoSubscriptionCredentials
}

func parseAuthEntry(fields map[string]json.RawMessage) (authEntry, error) {
	entry := authEntry{
		AccessToken:   firstString(fields, "key", "access_token"),
		RefreshToken:  firstString(fields, "refresh_token", "refresh"),
		UserID:        firstString(fields, "user_id", "userId"),
		PrincipalType: firstString(fields, "principal_type", "principalType"),
		PrincipalID:   firstString(fields, "principal_id", "principalId"),
		fields:        fields,
	}
	if mode := firstString(fields, "auth_mode", "authMode"); mode != "" && !strings.EqualFold(mode, "oidc") {
		return authEntry{}, errors.New("Grok credential is not an OIDC subscription login")
	}
	if issuer := strings.TrimRight(firstString(fields, "oidc_issuer", "oidcIssuer", "issuer"), "/"); issuer != "" && issuer != xaiIssuer {
		return authEntry{}, errors.New("Grok credential was issued by an unsupported provider")
	}
	if clientID := firstString(fields, "oidc_client_id", "oidcClientId", "client_id", "clientId"); clientID != "" && clientID != grokClientID {
		return authEntry{}, errors.New("Grok credential belongs to an unsupported OAuth client")
	}
	entry.ExpiresAt = entryExpiry(fields, entry.AccessToken)
	return entry, nil
}

func firstString(fields map[string]json.RawMessage, names ...string) string {
	for _, name := range names {
		var value string
		if raw := fields[name]; len(raw) != 0 && json.Unmarshal(raw, &value) == nil && strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func entryExpiry(fields map[string]json.RawMessage, accessToken string) time.Time {
	for _, name := range []string{"expires_at", "expires"} {
		raw := fields[name]
		if len(raw) == 0 {
			continue
		}
		var text string
		if json.Unmarshal(raw, &text) == nil {
			if expiration, err := time.Parse(time.RFC3339Nano, text); err == nil {
				return expiration
			}
		}
		var milliseconds int64
		if json.Unmarshal(raw, &milliseconds) == nil && milliseconds > 0 {
			if milliseconds > 10_000_000_000 {
				return time.UnixMilli(milliseconds)
			}
			return time.Unix(milliseconds, 0)
		}
	}
	if expiration := jwtExpiry(accessToken); !expiration.IsZero() {
		return expiration
	}
	if created := firstString(fields, "create_time", "createTime"); created != "" {
		if createdAt, err := time.Parse(time.RFC3339Nano, created); err == nil {
			return createdAt.Add(30 * 24 * time.Hour)
		}
	}
	return time.Time{}
}

func (store authStore) write(path string, file *authFile) error {
	contents, err := json.MarshalIndent(file.fields, "", "  ")
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

func refreshedAuthFile(file *authFile, reply tokenReply, now time.Time) (*authFile, error) {
	entryFields := cloneFields(file.Entry.fields)
	setStringAlias(entryFields, "key", "access_token", reply.AccessToken)
	if reply.RefreshToken != "" {
		setStringAlias(entryFields, "refresh_token", "refresh", reply.RefreshToken)
	}
	if reply.IDToken != "" {
		setJSONField(entryFields, "id_token", reply.IDToken)
	}
	expiresIn := reply.ExpiresIn
	if expiresIn <= 0 {
		expiresIn = 3600
	}
	expiresAt := now.Add(time.Duration(expiresIn) * time.Second).UTC()
	if _, legacy := entryFields["expires"]; legacy {
		var numeric int64
		if json.Unmarshal(entryFields["expires"], &numeric) == nil {
			setJSONField(entryFields, "expires", expiresAt.UnixMilli())
		} else {
			setJSONField(entryFields, "expires", expiresAt.Format(time.RFC3339Nano))
		}
	} else {
		setJSONField(entryFields, "expires_at", expiresAt.Format(time.RFC3339Nano))
	}
	setJSONField(entryFields, "create_time", now.UTC().Format(time.RFC3339Nano))

	fields := cloneFields(file.fields)
	encodedEntry, err := json.Marshal(entryFields)
	if err != nil {
		return nil, fmt.Errorf("marshal auth entry: %w", err)
	}
	fields[file.EntryKey] = encodedEntry
	entry, err := parseAuthEntry(entryFields)
	if err != nil {
		return nil, err
	}
	return &authFile{EntryKey: file.EntryKey, Entry: entry, fields: fields}, nil
}

func setStringAlias(fields map[string]json.RawMessage, current, legacy, value string) {
	if _, currentExists := fields[current]; currentExists {
		setJSONField(fields, current, value)
	}
	if _, legacyExists := fields[legacy]; legacyExists {
		setJSONField(fields, legacy, value)
	}
	if _, currentExists := fields[current]; !currentExists {
		if _, legacyExists := fields[legacy]; !legacyExists {
			setJSONField(fields, current, value)
		}
	}
}

func setJSONField(fields map[string]json.RawMessage, name string, value any) {
	encoded, _ := json.Marshal(value)
	fields[name] = encoded
}

func cloneFields(fields map[string]json.RawMessage) map[string]json.RawMessage {
	cloned := make(map[string]json.RawMessage, len(fields))
	for name, value := range fields {
		cloned[name] = append(json.RawMessage(nil), value...)
	}
	return cloned
}
