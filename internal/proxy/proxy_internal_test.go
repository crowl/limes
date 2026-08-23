package proxy

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestTransportFailureIsGenericAndNotRetried(t *testing.T) {
	target, err := url.Parse("https://upstream.test")
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	secret := "credential=super-secret"
	handler := newHandler(Backend{
		Upstream: target,
		Allowed:  func(string, string) bool { return true },
	}, roundTripFunc(func(*http.Request) (*http.Response, error) {
		calls++
		return nil, errors.New(secret)
	}))

	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "http://proxy/allowed", nil))
	if response.Code != http.StatusBadGateway {
		t.Fatalf("status = %d", response.Code)
	}
	if body := response.Body.String(); !strings.Contains(body, "upstream request failed") || strings.Contains(body, secret) {
		t.Fatalf("body leaked transport failure: %q", body)
	}
	if calls != 1 {
		t.Fatalf("transport calls = %d, want 1", calls)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return fn(request)
}
