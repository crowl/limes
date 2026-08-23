package proxy

import (
	"bufio"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestConfiguredBackendSanitizesAndPreservesExchange(t *testing.T) {
	var got *http.Request
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		got = request.Clone(request.Context())
		body, err := io.ReadAll(request.Body)
		if err != nil {
			t.Error(err)
			return
		}
		if string(body) != "body" {
			t.Errorf("body = %q", body)
		}
		w.Header().Set("X-Upstream", "present")
		w.WriteHeader(http.StatusCreated)
		if _, err := io.WriteString(w, "response"); err != nil {
			t.Error(err)
		}
	}))
	defer upstream.Close()
	target, err := url.Parse(upstream.URL + "/prefix")
	if err != nil {
		t.Fatal(err)
	}
	handler := New(Backend{
		Upstream:              target,
		Allowed:               func(method, path string) bool { return method == http.MethodPost && path == "/allowed" },
		RemoveHeaders:         []string{"Authorization", "X-Remove"},
		RemoveQueryParameters: []string{"key"},
		CredentialHeader:      "X-Key", CredentialValue: "token secret",
	})
	request := httptest.NewRequest(http.MethodPost, "http://untrusted/allowed?key=one&safe=yes&key=two", strings.NewReader("body"))
	request.Header.Set("Authorization", "caller")
	request.Header.Set("X-Remove", "caller")
	request.Header.Set("X-Key", "caller")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusCreated || response.Body.String() != "response" || response.Header().Get("X-Upstream") != "present" {
		t.Fatalf("response = %d %q", response.Code, response.Body.String())
	}
	if got == nil {
		t.Fatal("upstream was not called")
	}
	if got.URL.Path != "/prefix/allowed" || got.URL.Query().Has("key") || got.URL.Query().Get("safe") != "yes" {
		t.Errorf("upstream URL = %s", got.URL)
	}
	if got.Header.Get("Authorization") != "" || got.Header.Get("X-Remove") != "" || got.Header.Get("X-Key") != "token secret" {
		t.Errorf("upstream headers = %#v", got.Header)
	}
}

func TestConfiguredBackendStreamsFlushedResponse(t *testing.T) {
	firstFlushed := make(chan struct{})
	releaseSecond := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		if _, err := io.WriteString(w, "first\n"); err != nil {
			t.Error(err)
			return
		}
		w.(http.Flusher).Flush()
		close(firstFlushed)
		select {
		case <-releaseSecond:
		case <-t.Context().Done():
			return
		}
		if _, err := io.WriteString(w, "second\n"); err != nil {
			t.Error(err)
			return
		}
		w.(http.Flusher).Flush()
	}))
	defer upstream.Close()
	target, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(newHandler(Backend{Upstream: target, Allowed: func(method, path string) bool {
		return method == http.MethodPost && path == "/events"
	}, CredentialHeader: "Authorization"}, roundTripper(func(request *http.Request) (*http.Response, error) {
		response, err := (&http.Transport{}).RoundTrip(request)
		if err != nil {
			t.Logf("upstream transport error: %v", err)
		}
		return response, err
	})))
	defer server.Close()
	request, err := http.NewRequestWithContext(context.Background(), http.MethodPost, server.URL+"/events", nil)
	if err != nil {
		t.Fatal(err)
	}
	responseResult := make(chan struct {
		response *http.Response
		err      error
	}, 1)
	go func() {
		response, err := server.Client().Do(request)
		responseResult <- struct {
			response *http.Response
			err      error
		}{response, err}
	}()
	select {
	case <-firstFlushed:
	case result := <-responseResult:
		t.Fatalf("client completed before first event: response=%v error=%v", result.response, result.err)
	case <-time.After(time.Second):
		t.Fatal("upstream did not flush the first event")
	}
	result := <-responseResult
	if result.err != nil {
		t.Fatal(result.err)
	}
	response := result.response
	defer response.Body.Close()
	reader := bufio.NewReader(response.Body)
	first, err := reader.ReadString('\n')
	if err != nil || first != "first\n" {
		t.Fatalf("first event = %q, %v", first, err)
	}
	close(releaseSecond)
	second, err := reader.ReadString('\n')
	if err != nil || second != "second\n" {
		t.Fatalf("second event = %q, %v", second, err)
	}
}

func TestConfiguredBackendRejectsUnsupportedMethodBeforeUpstream(t *testing.T) {
	called := false
	upstream := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }))
	defer upstream.Close()
	target, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	handler := New(Backend{Upstream: target, Allowed: func(method, path string) bool { return method == http.MethodPost && path == "/allowed" }, CredentialHeader: "Authorization"})
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "http://proxy/allowed", nil))
	if response.Code != http.StatusForbidden || called {
		t.Fatalf("status = %d, called = %v", response.Code, called)
	}
}

type roundTripper func(*http.Request) (*http.Response, error)

func (fn roundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	return fn(request)
}
