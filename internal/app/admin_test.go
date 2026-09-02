package app

import (
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/crowl/limes/internal/config"
)

func TestBackendSelectorSwitchesNewRequestsWithoutInterruptingInflightRequest(t *testing.T) {
	firstStarted := make(chan struct{})
	releaseFirst := make(chan struct{})
	first := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		close(firstStarted)
		<-releaseFirst
		_, _ = io.WriteString(w, "first")
	})
	second := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "second")
	})
	selector := newBackendSelector([]runtimeBackend{
		{index: 0, typ: "openai_subscription", handler: first},
		{index: 1, typ: "http", handler: second},
	})

	firstResponse := make(chan string, 1)
	go func() {
		response := httptest.NewRecorder()
		selector.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/", nil))
		firstResponse <- response.Body.String()
	}()
	select {
	case <-firstStarted:
	case <-time.After(time.Second):
		t.Fatal("first request did not start")
	}

	selected, err := selector.switchTo(1)
	if err != nil || selected.Type != "http" {
		t.Fatalf("switchTo() = %#v, %v", selected, err)
	}
	response := httptest.NewRecorder()
	selector.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/", nil))
	if response.Body.String() != "second" {
		t.Fatalf("new request response = %q", response.Body.String())
	}

	close(releaseFirst)
	select {
	case body := <-firstResponse:
		if body != "first" {
			t.Fatalf("in-flight request response = %q", body)
		}
	case <-time.After(time.Second):
		t.Fatal("in-flight request did not finish")
	}
}

func TestBackendSelectorRejectsUnavailableAndUnknownBackends(t *testing.T) {
	selector := newBackendSelector([]runtimeBackend{
		{index: 0, typ: "http", handler: http.NotFoundHandler()},
		{index: 1, typ: "openai_subscription", unavailable: "subscription credentials are unavailable"},
	})
	if _, err := selector.switchTo(1); err == nil || err.Error() != "backend is unavailable" {
		t.Fatalf("unavailable switch error = %v", err)
	}
	if _, err := selector.switchTo(9); err == nil || err.Error() != "backend does not exist" {
		t.Fatalf("unknown switch error = %v", err)
	}
	active, ok := selector.activeBackend()
	if !ok || active.index != 0 {
		t.Fatalf("active backend = %#v, %v", active, ok)
	}
}

func TestAdminPanelDisplaysStatusAndSwitchesBackend(t *testing.T) {
	selector := newBackendSelector([]runtimeBackend{
		{index: 0, typ: "openai_subscription", target: "OpenAI subscription", handler: http.NotFoundHandler()},
		{index: 1, typ: "http", target: "api.openai.com", handler: http.NotFoundHandler()},
		{index: 2, typ: "http", target: "other.test", unavailable: "environment credential is not set"},
	})
	selector.setListening(true)
	panel, err := newAdminPanel("127.0.0.1:8799", []provider{{
		name: "openai", address: "127.0.0.1:8787", backends: selector,
	}}, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}

	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8799/", nil)
	panel.ServeHTTP(response, request)
	body := response.Body.String()
	if response.Code != http.StatusOK || !strings.Contains(body, "OpenAI subscription") || !strings.Contains(body, "api.openai.com") || !strings.Contains(body, "environment credential is not set") || !strings.Contains(body, "listening") {
		t.Fatalf("admin index = %d, %q", response.Code, body)
	}
	if response.Header().Get("Content-Security-Policy") == "" || response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("security headers = %#v", response.Header())
	}
	for _, expected := range []string{
		"color-scheme: light dark",
		"@media (prefers-color-scheme: dark)",
		"@media (max-width: 42rem)",
		`href="/" aria-current="page"`,
		`href="/requests"`,
		`class="status active"`,
		`class="status unavailable"`,
	} {
		if !strings.Contains(body, expected) {
			t.Errorf("admin index does not contain %q", expected)
		}
	}

	form := url.Values{
		"csrf_token": {panel.csrfToken},
		"rule":       {"openai"},
		"backend":    {"1"},
	}
	response = httptest.NewRecorder()
	request = httptest.NewRequest(http.MethodPost, "http://127.0.0.1:8799/switch", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Origin", "http://127.0.0.1:8799")
	panel.ServeHTTP(response, request)
	if response.Code != http.StatusSeeOther {
		t.Fatalf("switch status = %d, body = %q", response.Code, response.Body.String())
	}
	active, ok := selector.activeBackend()
	if !ok || active.index != 1 {
		t.Fatalf("active backend = %#v, %v", active, ok)
	}
}

func TestAdminPanelDisplaysRequestLog(t *testing.T) {
	selector := newBackendSelector([]runtimeBackend{{index: 0, typ: "http", handler: http.NotFoundHandler()}})
	requests := newRequestLog()
	requests.record(requestEntry{
		CompletedAt: time.Date(2026, 1, 2, 3, 4, 5, 0, time.Local),
		Rule:        "one",
		Backend:     "http",
		Method:      http.MethodGet,
		Path:        "/safe/path",
		Status:      http.StatusNoContent,
		Duration:    12 * time.Millisecond,
	})
	panel, err := newAdminPanel("127.0.0.1:8799", []provider{{name: "one", backends: selector}}, requests, testLogger())
	if err != nil {
		t.Fatal(err)
	}

	response := httptest.NewRecorder()
	panel.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8799/", nil))
	if strings.Contains(response.Body.String(), "/safe/path") || strings.Contains(response.Body.String(), "Recent requests") {
		t.Fatalf("rules page contains request log: %q", response.Body.String())
	}

	response = httptest.NewRecorder()
	panel.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8799/requests", nil))
	body := response.Body.String()
	for _, expected := range []string{
		"Recent requests",
		`href="/requests" aria-current="page"`,
		"one",
		"http",
		"GET",
		"/safe/path",
		"204",
		"12 ms",
		`.request-table th:nth-child(1) { width: 12rem; }`,
		`.request-table time { white-space: nowrap; }`,
	} {
		if !strings.Contains(body, expected) {
			t.Errorf("admin request log does not contain %q", expected)
		}
	}
}

func TestAdminPanelRequestRoutes(t *testing.T) {
	selector := newBackendSelector([]runtimeBackend{{index: 0, typ: "http", handler: http.NotFoundHandler()}})
	panel, err := newAdminPanel("127.0.0.1:8799", []provider{{name: "one", backends: selector}}, newRequestLog(), testLogger())
	if err != nil {
		t.Fatal(err)
	}

	for _, path := range []string{"/", "/requests"} {
		for _, method := range []string{http.MethodGet, http.MethodHead} {
			response := httptest.NewRecorder()
			panel.ServeHTTP(response, httptest.NewRequest(method, "http://127.0.0.1:8799"+path, nil))
			if response.Code != http.StatusOK {
				t.Errorf("%s %s status = %d", method, path, response.Code)
			}
		}
	}

	response := httptest.NewRecorder()
	panel.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "http://127.0.0.1:8799/requests", nil))
	if response.Code != http.StatusMethodNotAllowed || response.Header().Get("Allow") != "GET, HEAD" {
		t.Errorf("POST /requests = %d, Allow %q", response.Code, response.Header().Get("Allow"))
	}

	response = httptest.NewRecorder()
	panel.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8799/unknown", nil))
	if response.Code != http.StatusNotFound {
		t.Errorf("GET /unknown status = %d", response.Code)
	}
}

func TestAdminPanelServesIPv6LoopbackAddress(t *testing.T) {
	listener, err := net.Listen("tcp", "[::1]:0")
	if err != nil {
		t.Skipf("IPv6 loopback unavailable: %v", err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	selector := newBackendSelector([]runtimeBackend{{index: 0, typ: "http", handler: http.NotFoundHandler()}})
	panel, err := newAdminPanel(address, []provider{{name: "one", backends: selector}}, nil, testLogger())
	if err != nil {
		t.Fatal(err)
	}
	running, err := bindAdmin(panel)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = running.listener.Close() }()

	result := make(chan error, 1)
	go func() { result <- running.server.Serve(running.listener) }()
	response, err := http.Get("http://" + running.listener.Addr().String() + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", response.StatusCode)
	}
	if err := running.server.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-result; err != nil && err != http.ErrServerClosed {
		t.Fatal(err)
	}
}

func TestAdminPanelAcceptsSameOriginWithRootPath(t *testing.T) {
	selector := newBackendSelector([]runtimeBackend{{index: 0, typ: "http", handler: http.NotFoundHandler()}})
	panel, err := newAdminPanel("127.0.0.1:8799", []provider{{name: "one", backends: selector}}, nil, testLogger())
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:8799/switch", nil)
	request.Header.Set("Origin", "http://127.0.0.1:8799/")
	if !panel.validOrigin(request) {
		t.Fatal("same origin with root path was rejected")
	}
}

func TestAdminPanelAcceptsOpaqueOriginWithValidToken(t *testing.T) {
	selector := newBackendSelector([]runtimeBackend{{index: 0, typ: "http", handler: http.NotFoundHandler()}})
	panel, err := newAdminPanel("127.0.0.1:8799", []provider{{name: "one", backends: selector}}, nil, testLogger())
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:8799/switch", nil)
	request.Header.Set("Origin", "null")
	if !panel.validOrigin(request) {
		t.Fatal("opaque origin was rejected")
	}
	request.Header.Set("Sec-Fetch-Site", "cross-site")
	if panel.validOrigin(request) {
		t.Fatal("cross-site request was accepted")
	}
}

func TestAdminPanelRejectsInvalidHostOriginAndToken(t *testing.T) {
	selector := newBackendSelector([]runtimeBackend{{index: 0, typ: "http", handler: http.NotFoundHandler()}})
	panel, err := newAdminPanel("127.0.0.1:8799", []provider{{name: "one", backends: selector}}, nil, testLogger())
	if err != nil {
		t.Fatal(err)
	}

	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "http://evil.test:8799/", nil)
	panel.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("invalid host status = %d", response.Code)
	}

	for name, testCase := range map[string]struct{ origin, token string }{
		"origin": {origin: "https://evil.test", token: panel.csrfToken},
		"token":  {origin: "http://localhost:8799", token: "wrong"},
	} {
		t.Run(name, func(t *testing.T) {
			form := url.Values{"csrf_token": {testCase.token}, "rule": {"one"}, "backend": {"0"}}
			response := httptest.NewRecorder()
			request := httptest.NewRequest(http.MethodPost, "http://localhost:8799/switch", strings.NewReader(form.Encode()))
			request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			request.Header.Set("Origin", testCase.origin)
			panel.ServeHTTP(response, request)
			if response.Code != http.StatusForbidden {
				t.Fatalf("status = %d", response.Code)
			}
		})
	}
}

func TestConfigureProxyRetainsUnavailableBackends(t *testing.T) {
	getenv, _ := proxyEnvironment(t, map[string]string{"AVAILABLE": "secret"})
	configured, err := configureProxy(config.Proxy{
		Address: "127.0.0.1:0",
		Rules: []config.Rule{{
			Name: "one",
			Backends: []config.Backend{
				httpBackend("MISSING"),
				httpBackend("AVAILABLE"),
			},
		}},
	}, getenv, testLogger(), nil)
	if err != nil {
		t.Fatal(err)
	}
	backends, _ := configured.rules[0].backends.snapshots()
	if len(backends) != 2 || backends[0].Available || backends[0].Unavailable != "environment credential is not set" || !backends[1].Available || !backends[1].Active {
		t.Fatalf("backends = %#v", backends)
	}
}
