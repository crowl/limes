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
	requests  *requestLog
}

type adminPage struct {
	CSRFToken    string
	Listeners    []adminListener
	Requests     []adminRequest
	RequestsPage bool
}

type adminRequest struct {
	Time     string
	Listener string
	Backend  string
	Method   string
	Path     string
	Status   int
	Duration string
}

type adminListener struct {
	Name      string
	Address   string
	Listening bool
	Backends  []backendSnapshot
}

func newAdminPanel(address string, providers []provider, requests *requestLog, logger *slog.Logger) (*adminPanel, error) {
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
		requests:  requests,
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
	switch request.URL.Path {
	case "/", "/requests":
		if request.Method != http.MethodGet && request.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if request.URL.Path == "/requests" {
			panel.requestsPage(w)
			return
		}
		panel.listenersPage(w)
		return
	case "/switch":
		if request.Method != http.MethodPost {
			w.Header().Set("Allow", "POST")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		panel.switchBackend(w, request)
		return
	default:
		http.NotFound(w, request)
	}
}

func (panel *adminPanel) listenersPage(w http.ResponseWriter) {
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
	panel.render(w, adminPage{CSRFToken: panel.csrfToken, Listeners: listeners})
}

func (panel *adminPanel) requestsPage(w http.ResponseWriter) {
	requests := []adminRequest(nil)
	if panel.requests != nil {
		entries := panel.requests.snapshots()
		requests = make([]adminRequest, len(entries))
		for i, entry := range entries {
			requests[i] = adminRequest{
				Time:     entry.CompletedAt.Local().Format("2006-01-02 15:04:05"),
				Listener: entry.Listener,
				Backend:  entry.Backend,
				Method:   entry.Method,
				Path:     entry.Path,
				Status:   entry.Status,
				Duration: formatRequestDuration(entry.Duration),
			}
		}
	}
	panel.render(w, adminPage{Requests: requests, RequestsPage: true})
}

func (panel *adminPanel) render(w http.ResponseWriter, page adminPage) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := panel.template.Execute(w, page); err != nil {
		panel.logger.Error("render admin panel", "error", err)
	}
}

func formatRequestDuration(duration time.Duration) string {
	if duration < time.Millisecond {
		return "<1 ms"
	}
	if duration < time.Second {
		return strconv.FormatInt(duration.Milliseconds(), 10) + " ms"
	}
	return strconv.FormatFloat(duration.Seconds(), 'f', 2, 64) + " s"
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
<title>{{if .RequestsPage}}Request log{{else}}Listeners{{end}} · Limes admin</title>
<style>
:root {
  color-scheme: light dark;
  font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
  font-synthesis: none;
  --background: #f7f7f5;
  --surface: #ffffff;
  --foreground: #151515;
  --muted: #686868;
  --faint: #969696;
  --border: #dededb;
  --border-strong: #b8b8b4;
  --accent: #151515;
  --accent-foreground: #ffffff;
}
* { box-sizing: border-box; }
html { background: var(--background); }
body {
  min-width: 20rem;
  margin: 0;
  background: var(--background);
  color: var(--foreground);
  font-size: .9375rem;
  line-height: 1.5;
  text-rendering: optimizeLegibility;
}
.shell {
  width: min(100% - 2rem, 68rem);
  margin: 0 auto;
  padding: 4rem 0 6rem;
}
.masthead {
  display: flex;
  align-items: flex-end;
  justify-content: space-between;
  gap: 2rem;
  margin-bottom: 3rem;
}
.eyebrow {
  margin: 0 0 .5rem;
  color: var(--muted);
  font-size: .6875rem;
  font-weight: 700;
  letter-spacing: .14em;
  text-transform: uppercase;
}
h1 {
  margin: 0;
  font-size: clamp(2rem, 5vw, 3rem);
  font-weight: 600;
  letter-spacing: -.045em;
  line-height: 1;
}
.intro {
  max-width: 28rem;
  margin: 0 0 .15rem;
  color: var(--muted);
  text-align: right;
}
.page-nav {
  display: flex;
  gap: 1.5rem;
  margin-bottom: 3rem;
  border-bottom: 1px solid var(--border);
}
.page-nav a {
  margin-bottom: -1px;
  padding: .65rem 0;
  border-bottom: 2px solid transparent;
  color: var(--muted);
  font-size: .8125rem;
  font-weight: 650;
  text-decoration: none;
}
.page-nav a:hover { color: var(--foreground); }
.page-nav a[aria-current="page"] {
  border-bottom-color: var(--foreground);
  color: var(--foreground);
}
.page-nav a:focus-visible {
  outline: 2px solid var(--foreground);
  outline-offset: 3px;
}
.listeners { display: grid; gap: 1.25rem; }
.request-log { margin: 0; }
.section-heading {
  display: flex;
  align-items: baseline;
  justify-content: space-between;
  gap: 1rem;
  margin-bottom: 1rem;
}
.section-heading h2 {
  margin: 0;
  font-size: 1.25rem;
  font-weight: 600;
  letter-spacing: -.025em;
}
.section-heading p {
  margin: 0;
  color: var(--muted);
  font-size: .75rem;
}
.request-table { min-width: 58rem; }
.request-table th:nth-child(1) { width: 12rem; }
.request-table th:nth-child(2) { width: 13%; }
.request-table th:nth-child(3) { width: 13rem; }
.request-table th:nth-child(4) { width: 9%; }
.request-table th:nth-child(5) { width: auto; }
.request-table th:nth-child(6) { width: 8%; }
.request-table th:nth-child(7) { width: 9%; }
.request-table td:last-child { text-align: left; }
.request-table time { white-space: nowrap; }
.empty-state {
  margin: 0;
  padding: 2.5rem 1.5rem;
  color: var(--muted);
  text-align: center;
}
.listener {
  overflow: hidden;
  border: 1px solid var(--border);
  border-radius: .75rem;
  background: var(--surface);
}
.listener-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 1.5rem;
  padding: 1.25rem 1.5rem;
  border-bottom: 1px solid var(--border);
}
.listener h2 {
  margin: 0 0 .2rem;
  font-size: 1.0625rem;
  font-weight: 600;
  letter-spacing: -.015em;
}
.address {
  margin: 0;
  color: var(--muted);
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  font-size: .75rem;
}
.listener-state {
  display: inline-flex;
  flex: none;
  align-items: center;
  gap: .5rem;
  color: var(--muted);
  font-size: .75rem;
  font-weight: 600;
  letter-spacing: .02em;
}
.listener-state::before {
  width: .45rem;
  height: .45rem;
  border: 1px solid currentColor;
  border-radius: 50%;
  content: "";
}
.listener-state.is-listening { color: var(--foreground); }
.listener-state.is-listening::before { background: currentColor; }
.table-wrap { overflow-x: auto; }
table {
  width: 100%;
  border-collapse: collapse;
  table-layout: fixed;
}
th {
  padding: .7rem 1rem;
  color: var(--faint);
  font-size: .625rem;
  font-weight: 700;
  letter-spacing: .1em;
  text-align: left;
  text-transform: uppercase;
}
th:first-child, td:first-child { padding-left: 1.5rem; }
th:last-child, td:last-child { padding-right: 1.5rem; }
th:nth-child(1) { width: 24%; }
th:nth-child(2) { width: 34%; }
th:nth-child(3) { width: 27%; }
th:nth-child(4) { width: 15%; text-align: right; }
td {
  padding: 1rem;
  border-top: 1px solid var(--border);
  text-align: left;
  vertical-align: middle;
  overflow-wrap: anywhere;
}
td:last-child { text-align: right; }
code {
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  font-size: .8125rem;
}
.target { color: var(--muted); }
.status {
  display: inline-flex;
  align-items: center;
  min-height: 1.65rem;
  padding: .2rem .55rem;
  border: 1px solid var(--border-strong);
  border-radius: 999px;
  color: var(--muted);
  font-size: .6875rem;
  font-weight: 650;
  line-height: 1.2;
}
.status.active {
  border-color: var(--accent);
  background: var(--accent);
  color: var(--accent-foreground);
}
.status.unavailable {
  border-color: transparent;
  padding-left: 0;
  color: var(--faint);
}
form { margin: 0; }
button {
  min-height: 2rem;
  padding: .35rem .7rem;
  border: 1px solid var(--border-strong);
  border-radius: .4rem;
  background: transparent;
  color: var(--foreground);
  font: inherit;
  font-size: .75rem;
  font-weight: 650;
  cursor: pointer;
}
button:hover {
  border-color: var(--accent);
  background: var(--accent);
  color: var(--accent-foreground);
}
button:focus-visible {
  outline: 2px solid var(--foreground);
  outline-offset: 3px;
}
@media (prefers-color-scheme: dark) {
  :root {
    --background: #111111;
    --surface: #171717;
    --foreground: #eeeeec;
    --muted: #a1a19c;
    --faint: #777772;
    --border: #30302e;
    --border-strong: #555550;
    --accent: #eeeeec;
    --accent-foreground: #151515;
  }
}
@media (max-width: 42rem) {
  .shell { padding: 2.5rem 0 4rem; }
  .masthead { display: block; margin-bottom: 1.5rem; }
  .intro { margin-top: 1rem; text-align: left; }
  .page-nav { margin-bottom: 2rem; }
  .listener-header { align-items: flex-start; padding: 1rem; }
  .section-heading { display: block; }
  .section-heading p { margin-top: .35rem; }
  thead { display: none; }
  table, tbody, tr, td { display: block; width: 100%; }
  tr {
    display: grid;
    grid-template-columns: minmax(0, 1fr) auto;
    gap: .75rem 1rem;
    padding: 1rem;
    border-top: 1px solid var(--border);
  }
  td, th:first-child, td:first-child, th:last-child, td:last-child {
    padding: 0;
    border: 0;
    text-align: left;
  }
  td::before {
    display: block;
    margin-bottom: .15rem;
    color: var(--faint);
    content: attr(data-label);
    font-size: .5625rem;
    font-weight: 700;
    letter-spacing: .1em;
    text-transform: uppercase;
  }
  td:nth-child(2) { grid-column: 1 / -1; }
  td:nth-child(3), td:nth-child(4) { align-self: end; }
  td:nth-child(4):empty { display: none; }
  td:nth-child(4) { justify-self: end; }
  .request-table { min-width: 0; }
  .request-table tr { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  .request-table td:nth-child(1), .request-table td:nth-child(2), .request-table td:nth-child(3), .request-table td:nth-child(5) { grid-column: 1 / -1; }
  .request-table td:nth-child(4), .request-table td:nth-child(6), .request-table td:nth-child(7) { grid-column: auto; justify-self: auto; }
  .request-table td:empty { display: block; }
}
</style>
</head>
<body>
<main class="shell">
<header class="masthead">
<div>
<p class="eyebrow">Admin console</p>
<h1>Limes</h1>
</div>
{{if not .RequestsPage}}<p class="intro">Inspect listeners and select the backend used for new requests.</p>{{end}}
</header>
<nav class="page-nav" aria-label="Admin pages">
<a href="/"{{if not .RequestsPage}} aria-current="page"{{end}}>Listeners</a>
<a href="/requests"{{if .RequestsPage}} aria-current="page"{{end}}>Request log</a>
</nav>
{{if .RequestsPage}}
<section class="request-log" aria-labelledby="request-log-heading">
<header class="section-heading">
<h2 id="request-log-heading">Recent requests</h2>
<p>Latest 200 completed requests · newest first</p>
</header>
<div class="listener">
{{if .Requests}}
<div class="table-wrap">
<table class="request-table">
<thead><tr><th>Time</th><th>Listener</th><th>Backend</th><th>Method</th><th>Path</th><th>Status</th><th>Duration</th></tr></thead>
<tbody>
{{range .Requests}}
<tr>
<td data-label="Time"><time>{{.Time}}</time></td>
<td data-label="Listener">{{.Listener}}</td>
<td data-label="Backend"><code>{{.Backend}}</code></td>
<td data-label="Method"><code>{{.Method}}</code></td>
<td data-label="Path"><code>{{.Path}}</code></td>
<td data-label="Status"><span class="status">{{.Status}}</span></td>
<td data-label="Duration">{{.Duration}}</td>
</tr>
{{end}}
</tbody>
</table>
</div>
{{else}}
<p class="empty-state">No requests recorded yet.</p>
{{end}}
</div>
</section>
{{else}}
<div class="listeners">
{{$csrf := .CSRFToken}}
{{range .Listeners}}
{{$listener := .Name}}
<section class="listener">
<header class="listener-header">
<div>
<h2>{{.Name}}</h2>
<p class="address">{{.Address}}</p>
</div>
<span class="listener-state {{if .Listening}}is-listening{{end}}">{{if .Listening}}listening{{else}}not listening{{end}}</span>
</header>
<div class="table-wrap">
<table>
<thead><tr><th>Backend</th><th>Target</th><th>Status</th><th>Action</th></tr></thead>
<tbody>
{{range .Backends}}
<tr>
<td data-label="Backend"><code>{{.Type}}</code></td>
<td class="target" data-label="Target">{{.Target}}</td>
<td data-label="Status">{{if .Active}}<span class="status active">Active</span>{{else if .Available}}<span class="status">Available</span>{{else}}<span class="status unavailable">{{.Unavailable}}</span>{{end}}</td>
<td data-label="Action">{{if and .Available (not .Active)}}
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
</div>
</section>
{{end}}
</div>
{{end}}
</main>
</body>
</html>`
