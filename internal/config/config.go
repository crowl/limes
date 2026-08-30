package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

const MaxSize = 1 << 20

type Options struct {
	Path        string
	ShowVersion bool
}

type File struct {
	Listeners []Listener `json:"listeners"`
}

type Listener struct {
	Name     string    `json:"name"`
	Address  string    `json:"address"`
	Backends []Backend `json:"backends"`
}

type Backend struct {
	Type                  string      `json:"type"`
	Upstream              string      `json:"upstream,omitempty"`
	Upstreams             []string    `json:"upstreams,omitempty"`
	Routes                []Route     `json:"routes,omitempty"`
	RemoveHeaders         []string    `json:"remove_headers,omitempty"`
	RemoveQueryParameters []string    `json:"remove_query_parameters,omitempty"`
	Credential            *Credential `json:"credential,omitempty"`
}

type Route struct {
	Method  string  `json:"method"`
	Path    string  `json:"path"`
	Pattern Pattern `json:"-"`
}

type Credential struct {
	Environment   string `json:"environment"`
	Header        string `json:"header"`
	Prefix        string `json:"prefix"`
	BasicUsername string `json:"basic_username,omitempty"`
}

type Pattern struct {
	prefix, suffix string
	placeholder    bool
	multiSegment   bool
}

func Parse(args []string, output io.Writer) (Options, error) {
	return parseWithGetenv(args, output, os.Getenv)
}

func parseWithGetenv(args []string, output io.Writer, getenv func(string) string) (Options, error) {
	var cfg Options
	flags := flag.NewFlagSet("limes", flag.ContinueOnError)
	flags.SetOutput(output)
	flags.StringVar(&cfg.Path, "config-path", "", "path to config.json (default: $XDG_CONFIG_HOME/limes/config.json or $HOME/.config/limes/config.json)")
	flags.BoolVar(&cfg.ShowVersion, "version", false, "print version and exit")
	if err := flags.Parse(args); err != nil {
		return Options{}, err
	}
	if flags.NArg() != 0 {
		return Options{}, fmt.Errorf("unexpected positional argument %q", flags.Arg(0))
	}
	if cfg.ShowVersion {
		return cfg, nil
	}
	path, err := ResolvePath(cfg.Path, getenv)
	if err != nil {
		return Options{}, err
	}
	cfg.Path = path
	return cfg, nil
}

func IsHelp(err error) bool { return errors.Is(err, flag.ErrHelp) }

func ResolvePath(explicit string, getenv func(string) string) (string, error) {
	if explicit != "" {
		return explicit, nil
	}
	if xdg := getenv("XDG_CONFIG_HOME"); xdg != "" {
		return filepath.Join(xdg, "limes", "config.json"), nil
	}
	if home := getenv("HOME"); home != "" {
		return filepath.Join(home, ".config", "limes", "config.json"), nil
	}
	return "", errors.New("cannot resolve configuration path: set --config-path, XDG_CONFIG_HOME, or HOME")
}

func Load(path string) (File, error) {
	file, err := os.Open(path)
	if err != nil {
		return File{}, fmt.Errorf("read configuration: %w", err)
	}
	defer func() { _ = file.Close() }()
	contents, err := io.ReadAll(io.LimitReader(file, MaxSize+1))
	if err != nil {
		return File{}, fmt.Errorf("read configuration: %w", err)
	}
	if len(contents) == 0 {
		return File{}, errors.New("configuration is empty")
	}
	if len(contents) > MaxSize {
		return File{}, errors.New("configuration exceeds 1 MiB")
	}
	if err := rejectDuplicateJSONKeys(contents); err != nil {
		return File{}, fmt.Errorf("parse configuration: %w", err)
	}
	var raw struct {
		Listeners []struct {
			Backends []map[string]json.RawMessage `json:"backends"`
		} `json:"listeners"`
	}
	rawDecoder := json.NewDecoder(bytes.NewReader(contents))
	if err := rawDecoder.Decode(&raw); err != nil {
		return File{}, fmt.Errorf("parse configuration: %w", err)
	}
	if err := rawDecoder.Decode(&struct{}{}); err != io.EOF {
		if err == nil {
			return File{}, errors.New("configuration contains multiple top-level values")
		}
		return File{}, fmt.Errorf("trailing configuration content: %w", err)
	}
	for _, listener := range raw.Listeners {
		for _, backend := range listener.Backends {
			allowed := map[string]bool{"type": true}
			typeValue, hasType := backend["type"]
			var typ string
			if hasType {
				_ = json.Unmarshal(typeValue, &typ)
			}
			if typ == "http" {
				for _, key := range []string{"upstream", "routes", "remove_headers", "remove_query_parameters", "credential"} {
					allowed[key] = true
				}
			} else if typ == "https" {
				for _, key := range []string{"upstreams", "routes", "remove_headers", "remove_query_parameters", "credential"} {
					allowed[key] = true
				}
			} else if typ != "openai_subscription" && typ != "xai_subscription" {
				for _, key := range []string{"upstream", "upstreams", "routes", "remove_headers", "remove_query_parameters", "credential"} {
					allowed[key] = true
				}
			}
			for key := range backend {
				if !allowed[key] {
					return File{}, fmt.Errorf("backend field %q does not belong to its type", key)
				}
			}
		}
	}
	var cfg File
	dec := json.NewDecoder(bytes.NewReader(contents))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return File{}, fmt.Errorf("parse configuration: %w", err)
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		if err == nil {
			return File{}, errors.New("configuration contains multiple top-level values")
		}
		return File{}, fmt.Errorf("trailing configuration content: %w", err)
	}
	return cfg, validateFile(&cfg)
}

func rejectDuplicateJSONKeys(contents []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(contents))
	if err := scanJSONValue(decoder); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		if err == nil {
			return errors.New("configuration contains multiple top-level values")
		}
		return fmt.Errorf("trailing configuration content: %w", err)
	}
	return nil
}

func scanJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	switch token := token.(type) {
	case json.Delim:
		switch token {
		case '{':
			keys := make(map[string]struct{})
			for decoder.More() {
				key, err := decoder.Token()
				if err != nil {
					return err
				}
				name, ok := key.(string)
				if !ok {
					return errors.New("object key is not a string")
				}
				if _, exists := keys[name]; exists {
					return fmt.Errorf("duplicate JSON object key %q", name)
				}
				keys[name] = struct{}{}
				if err := scanJSONValue(decoder); err != nil {
					return err
				}
			}
			_, err := decoder.Token()
			return err
		case '[':
			for decoder.More() {
				if err := scanJSONValue(decoder); err != nil {
					return err
				}
			}
			_, err := decoder.Token()
			return err
		}
	}
	return nil
}

var envName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
var tokenName = regexp.MustCompile(`^[!#$%&'*+\-.^_` + "`" + `|~0-9A-Za-z]+$`)

func validateFile(cfg *File) error {
	if len(cfg.Listeners) == 0 {
		return errors.New("listeners must not be empty")
	}
	names := map[string]bool{}
	addresses := map[string]bool{}
	for i := range cfg.Listeners {
		l := &cfg.Listeners[i]
		if l.Name == "" || names[l.Name] {
			return fmt.Errorf("invalid or duplicate listener name %q", l.Name)
		}
		names[l.Name] = true
		if l.Address == "" {
			return fmt.Errorf("listener %q address is required", l.Name)
		}
		_, port, err := net.SplitHostPort(l.Address)
		if err != nil {
			return fmt.Errorf("listener %q address: %w", l.Name, err)
		}
		portNumber, err := strconv.ParseUint(port, 10, 16)
		if err != nil || portNumber == 0 {
			return fmt.Errorf("listener %q address has invalid port %q", l.Name, port)
		}
		if addresses[l.Address] {
			return fmt.Errorf("duplicate listener address %q", l.Address)
		}
		addresses[l.Address] = true
		if len(l.Backends) == 0 {
			return fmt.Errorf("listener %q has no backends", l.Name)
		}
		for j := range l.Backends {
			if err := validateBackend(&l.Backends[j]); err != nil {
				return fmt.Errorf("listener %q backend %d: %w", l.Name, j, err)
			}
		}
	}
	return nil
}

func validateBackend(b *Backend) error {
	if b.Type == "openai_subscription" || b.Type == "xai_subscription" {
		if b.Upstream != "" || len(b.Upstreams) > 0 || len(b.Routes) > 0 || len(b.RemoveHeaders) > 0 || len(b.RemoveQueryParameters) > 0 || b.Credential != nil {
			return fmt.Errorf("%s does not accept additional fields", b.Type)
		}
		return nil
	}
	if b.Type != "http" && b.Type != "https" {
		return fmt.Errorf("unknown backend type %q", b.Type)
	}
	if b.Type == "http" {
		if err := validateUpstream(b.Upstream, false); err != nil {
			return err
		}
	} else {
		if len(b.Upstreams) == 0 {
			return errors.New("upstreams must not be empty")
		}
		seen := make(map[string]bool)
		for _, upstream := range b.Upstreams {
			if err := validateUpstream(upstream, true); err != nil {
				return err
			}
			u, _ := url.Parse(upstream)
			authority := strings.ToLower(u.Host)
			if u.Port() == "" {
				authority = net.JoinHostPort(strings.ToLower(u.Hostname()), "443")
			}
			if seen[authority] {
				return fmt.Errorf("duplicate upstream authority %q", authority)
			}
			seen[authority] = true
		}
	}
	if len(b.Routes) == 0 {
		return errors.New("routes must not be empty")
	}
	seen := map[string]bool{}
	for i := range b.Routes {
		r := &b.Routes[i]
		if !tokenName.MatchString(r.Method) {
			return fmt.Errorf("invalid route method %q", r.Method)
		}
		r.Method = asciiUpper(r.Method)
		if !tokenName.MatchString(r.Method) {
			return fmt.Errorf("invalid route method %q", r.Method)
		}
		p, err := CompileRoute(r.Path)
		if err != nil {
			return err
		}
		r.Pattern = p
		k := r.Method + "\000" + r.Path
		if seen[k] {
			return fmt.Errorf("duplicate route %s %s", r.Method, r.Path)
		}
		seen[k] = true
	}
	headers := map[string]bool{}
	for _, h := range b.RemoveHeaders {
		h = http.CanonicalHeaderKey(h)
		if !tokenName.MatchString(h) || headers[strings.ToLower(h)] {
			return fmt.Errorf("invalid or duplicate header %q", h)
		}
		headers[strings.ToLower(h)] = true
	}
	q := map[string]bool{}
	for _, n := range b.RemoveQueryParameters {
		if n == "" || q[n] {
			return fmt.Errorf("invalid or duplicate query parameter %q", n)
		}
		q[n] = true
	}
	if b.Credential == nil || !envName.MatchString(b.Credential.Environment) || !tokenName.MatchString(b.Credential.Header) {
		return errors.New("credential environment and header are required and must be valid")
	}
	if b.Credential.BasicUsername != "" {
		if b.Credential.Prefix != "" {
			return errors.New("credential prefix and basic_username are mutually exclusive")
		}
		if strings.ContainsAny(b.Credential.BasicUsername, ":\r\n") {
			return errors.New("credential basic_username must not contain a colon or line break")
		}
	}
	return nil
}

func validateUpstream(value string, httpsOnly bool) error {
	u, err := url.Parse(value)
	if err != nil {
		if httpsOnly {
			return errors.New("upstreams must contain absolute https URLs without userinfo, query, or fragment")
		}
		return errors.New("upstream must be an absolute http or https URL without userinfo, query, or fragment")
	}
	validScheme := u.Scheme == "http" || u.Scheme == "https"
	if httpsOnly {
		validScheme = u.Scheme == "https"
	}
	if u.Scheme == "" || u.Host == "" || u.Hostname() == "" || !validScheme || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		if httpsOnly {
			return errors.New("upstreams must contain absolute https URLs without userinfo, query, or fragment")
		}
		return errors.New("upstream must be an absolute http or https URL without userinfo, query, or fragment")
	}
	if httpsOnly && u.Path != "" && u.Path != "/" {
		return errors.New("HTTPS upstreams must not contain paths")
	}
	if httpsOnly && net.ParseIP(u.Hostname()) != nil {
		return errors.New("HTTPS upstreams must use DNS hostnames")
	}
	if hasExplicitPort(u) {
		port := u.Port()
		portNumber, portErr := strconv.ParseUint(port, 10, 16)
		if port == "" || portErr != nil || portNumber == 0 {
			return fmt.Errorf("upstream has invalid explicit port %q", port)
		}
		if httpsOnly && port != "443" {
			return fmt.Errorf("HTTPS upstream explicit port must be 443, got %q", port)
		}
	}
	return nil
}

func hasExplicitPort(upstream *url.URL) bool {
	host := upstream.Host
	if strings.HasPrefix(host, "[") {
		closingBracket := strings.LastIndexByte(host, ']')
		return closingBracket >= 0 && len(host) > closingBracket+1
	}
	return strings.Contains(host, ":")
}

func CompileRoute(path string) (Pattern, error) {
	if !strings.HasPrefix(path, "/") {
		return Pattern{}, errors.New("route path must begin with /")
	}
	first := strings.IndexByte(path, '{')
	last := strings.IndexByte(path, '}')
	if first < 0 && last < 0 {
		return Pattern{prefix: path}, nil
	}
	if first < 0 || last < first || strings.Count(path, "{") != 1 || strings.Count(path, "}") != 1 {
		return Pattern{}, fmt.Errorf("malformed route pattern %q", path)
	}
	name := path[first+1 : last]
	multiSegment := strings.HasSuffix(name, "...")
	if multiSegment {
		name = strings.TrimSuffix(name, "...")
	}
	if !regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]*$`).MatchString(name) {
		return Pattern{}, fmt.Errorf("invalid placeholder in %q", path)
	}
	return Pattern{prefix: path[:first], suffix: path[last+1:], placeholder: true, multiSegment: multiSegment}, nil
}

func (p Pattern) Matches(path string) bool {
	if !p.placeholder {
		return path == p.prefix
	}
	if len(path) < len(p.prefix)+len(p.suffix) || !strings.HasPrefix(path, p.prefix) || !strings.HasSuffix(path, p.suffix) {
		return false
	}
	middle := path[len(p.prefix) : len(path)-len(p.suffix)]
	return middle != "" && (p.multiSegment || !strings.Contains(middle, "/"))
}

func asciiUpper(value string) string {
	return strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' {
			return r - ('a' - 'A')
		}
		return r
	}, value)
}
