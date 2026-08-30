package app

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"html/template"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type adminPanel struct {
	address   string
	csrfToken string
	providers map[string]provider
	ordered   []provider
	logger    *slog.Logger
	template  *template.Template
}

type adminPage struct {
	CSRFToken string
	Listeners []adminListener
}

type adminListener struct {
	Name      string
	Address   string
	Listening bool
	Backends  []backendSnapshot
}

func newAdminPanel(address string, providers []provider, logger *slog.Logger) (*adminPanel, error) {
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return nil, fmt.Errorf("generate admin form token: %w", err)
	}
	panel := &adminPanel{
		address:   address,
		csrfToken: base64.RawURLEncoding.EncodeToString(tokenBytes),
		providers: make(map[string]provider, len(providers)),
		ordered:   providers,
		logger:    logger,
	}
	for _, provider := range providers {
		panel.providers[provider.name] = provider
	}
	parsed, err := template.New("admin").Parse(adminHTML)
	if err != nil {
		return nil, fmt.Errorf("parse admin template: %w", err)
	}
	panel.template = parsed
	return panel, nil
}

func (panel *adminPanel) ServeHTTP(w http.ResponseWriter, request *http.Request) {
	setAdminSecurityHeaders(w.Header())
	if !panel.validHost(request.Host) {
		http.Error(w, "invalid host", http.StatusForbidden)
		return
	}
	if request.URL.Path == "/" {
		if request.Method != http.MethodGet && request.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		panel.index(w, request)
		return
	}
	if request.URL.Path == "/switch" {
		if request.Method != http.MethodPost {
			w.Header().Set("Allow", "POST")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		panel.switchBackend(w, request)
		return
	}
	http.NotFound(w, request)
}

func (panel *adminPanel) index(w http.ResponseWriter, _ *http.Request) {
	listeners := make([]adminListener, 0, len(panel.ordered))
	for _, provider := range panel.ordered {
		backends, listening := provider.backends.snapshots()
		listeners = append(listeners, adminListener{
			Name:      provider.name,
			Address:   provider.address,
			Listening: listening,
			Backends:  backends,
		})
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := panel.template.Execute(w, adminPage{CSRFToken: panel.csrfToken, Listeners: listeners}); err != nil {
		panel.logger.Error("render admin panel", "error", err)
	}
}

func (panel *adminPanel) switchBackend(w http.ResponseWriter, request *http.Request) {
	if !panel.validOrigin(request) {
		panel.logger.Warn("backend switch rejected", "reason", "invalid origin")
		http.Error(w, "invalid origin", http.StatusForbidden)
		return
	}
	request.Body = http.MaxBytesReader(w, request.Body, 16<<10)
	if err := request.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	if subtle.ConstantTimeCompare([]byte(request.PostForm.Get("csrf_token")), []byte(panel.csrfToken)) != 1 {
		panel.logger.Warn("backend switch rejected", "reason", "invalid form token")
		http.Error(w, "invalid form token", http.StatusForbidden)
		return
	}
	provider, ok := panel.providers[request.PostForm.Get("listener")]
	if !ok || provider.backends == nil {
		http.Error(w, "listener does not exist", http.StatusNotFound)
		return
	}
	index, err := strconv.Atoi(request.PostForm.Get("backend"))
	if err != nil {
		http.Error(w, "invalid backend", http.StatusBadRequest)
		return
	}
	selected, err := provider.backends.switchTo(index)
	if err != nil {
		panel.logger.Warn("backend switch rejected", "listener", provider.name, "reason", err)
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	panel.logger.Info("backend switched", "listener", provider.name, "backend", selected.Type)
	http.Redirect(w, request, "/", http.StatusSeeOther)
}

func (panel *adminPanel) validHost(value string) bool {
	host, port, err := net.SplitHostPort(value)
	if err != nil {
		return false
	}
	_, configuredPort, err := net.SplitHostPort(panel.address)
	if err != nil || port != configuredPort {
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func (panel *adminPanel) validOrigin(request *http.Request) bool {
	if request.Header.Get("Sec-Fetch-Site") == "cross-site" {
		return false
	}
	origin := request.Header.Get("Origin")
	if origin == "" || origin == "null" {
		return true
	}
	parsed, err := url.Parse(origin)
	return err == nil && parsed.Scheme == "http" && (parsed.Path == "" || parsed.Path == "/") && parsed.RawQuery == "" && parsed.Fragment == "" && panel.validHost(parsed.Host)
}

func setAdminSecurityHeaders(header http.Header) {
	header.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
	header.Set("Referrer-Policy", "no-referrer")
	header.Set("X-Content-Type-Options", "nosniff")
	header.Set("X-Frame-Options", "DENY")
	header.Set("Cache-Control", "no-store")
}

func bindAdmin(panel *adminPanel) (runningProvider, error) {
	listener, err := net.Listen("tcp", panel.address)
	if err != nil {
		return runningProvider{}, fmt.Errorf("listen for admin on %s: %w", panel.address, err)
	}
	return runningProvider{
		provider: provider{name: "admin", address: panel.address, authMode: "admin", handler: panel},
		listener: listener,
		server: &http.Server{
			Addr:              panel.address,
			Handler:           panel,
			ReadTimeout:       15 * time.Second,
			ReadHeaderTimeout: 10 * time.Second,
			IdleTimeout:       90 * time.Second,
		},
	}, nil
}

const adminHTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Limes admin</title>
<style>
:root { color-scheme: light dark; font-family: system-ui, sans-serif; }
body { max-width: 72rem; margin: 2rem auto; padding: 0 1rem; }
h1 { margin-bottom: .25rem; }
.listener { border: 1px solid #8888; border-radius: .6rem; margin: 1rem 0; padding: 1rem; }
.listener h2 { margin: 0; }
.meta { color: #777; margin: .25rem 0 1rem; }
table { border-collapse: collapse; width: 100%; }
th, td { border-top: 1px solid #8888; padding: .7rem .4rem; text-align: left; }
.status { font-weight: 600; }
button { padding: .4rem .75rem; }
</style>
</head>
<body>
<h1>Limes</h1>
<p>Runtime backend selection</p>
{{$csrf := .CSRFToken}}
{{range .Listeners}}
{{$listener := .Name}}
<section class="listener">
<h2>{{.Name}}</h2>
<p class="meta">{{.Address}} · {{if .Listening}}listening{{else}}not listening{{end}}</p>
<table>
<thead><tr><th>Backend</th><th>Target</th><th>Status</th><th>Action</th></tr></thead>
<tbody>
{{range .Backends}}
<tr>
<td><code>{{.Type}}</code></td>
<td>{{.Target}}</td>
<td class="status">{{if .Active}}active{{else if .Available}}available{{else}}{{.Unavailable}}{{end}}</td>
<td>{{if and .Available (not .Active)}}
<form method="post" action="/switch">
<input type="hidden" name="csrf_token" value="{{$csrf}}">
<input type="hidden" name="listener" value="{{$listener}}">
<input type="hidden" name="backend" value="{{.Index}}">
<button type="submit">Switch</button>
</form>
{{end}}</td>
</tr>
{{end}}
</tbody>
</table>
</section>
{{end}}
</body>
</html>`
