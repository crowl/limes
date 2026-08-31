package app

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"
)

func TestRequestLogRetainsLatestEntriesNewestFirst(t *testing.T) {
	requests := newRequestLog()
	for i := range requestLogCapacity + 5 {
		requests.record(requestEntry{Status: i})
	}

	entries := requests.snapshots()
	if len(entries) != requestLogCapacity {
		t.Fatalf("entries = %d, want %d", len(entries), requestLogCapacity)
	}
	if entries[0].Status != requestLogCapacity+4 || entries[len(entries)-1].Status != 5 {
		t.Fatalf("entry range = %d through %d", entries[0].Status, entries[len(entries)-1].Status)
	}
}

func TestRequestLogCapturesSafeCompletedRequestMetadata(t *testing.T) {
	requests := newRequestLog()
	times := []time.Time{
		time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
		time.Date(2026, 1, 2, 3, 4, 5, 25_000_000, time.UTC),
	}
	requests.now = func() time.Time {
		now := times[0]
		times = times[1:]
		return now
	}
	handler := requests.wrap("api", "http", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusCreated)
	}))

	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "http://proxy/v1/items?token=secret", nil))
	entries := requests.snapshots()
	if len(entries) != 1 {
		t.Fatalf("entries = %#v", entries)
	}
	got := entries[0]
	if got.Listener != "api" || got.Backend != "http" || got.Method != http.MethodPost || got.Path != "/v1/items" || got.Status != http.StatusCreated || got.Duration != 25*time.Millisecond {
		t.Fatalf("entry = %#v", got)
	}

	longPath := "/" + strings.Repeat("é", maxLoggedPathLength)
	completedAt := time.Date(2026, 1, 2, 3, 5, 0, 0, time.UTC)
	requests.now = func() time.Time { return completedAt }
	requests.observe("api", "http", http.MethodGet, longPath, http.StatusOK, completedAt.Add(-time.Millisecond))
	got = requests.snapshots()[0]
	if len(got.Path) > maxLoggedPathLength || !strings.HasSuffix(got.Path, truncatedPathSuffix) || !utf8.ValidString(got.Path) {
		t.Fatalf("truncated path length = %d, path suffix = %q", len(got.Path), got.Path[len(got.Path)-4:])
	}
}

func TestRequestLogCapturesBackendSelectedForEachRequest(t *testing.T) {
	requests := newRequestLog()
	selector := newBackendSelector([]runtimeBackend{
		{index: 0, typ: "first", handler: requests.wrap("api", "first", http.NotFoundHandler())},
		{index: 1, typ: "second", handler: requests.wrap("api", "second", http.NotFoundHandler())},
	})
	selector.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/first", nil))
	if _, err := selector.switchTo(1); err != nil {
		t.Fatal(err)
	}
	selector.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/second", nil))

	entries := requests.snapshots()
	if len(entries) != 2 || entries[0].Backend != "second" || entries[1].Backend != "first" {
		t.Fatalf("entries = %#v", entries)
	}
}

func TestRequestLogCapturesFinalStatusAfterInformationalResponse(t *testing.T) {
	requests := newRequestLog()
	handler := requests.wrap("api", "http", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusEarlyHints)
		w.WriteHeader(http.StatusNoContent)
	}))

	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "http://proxy/x", nil))
	entries := requests.snapshots()
	if len(entries) != 1 || entries[0].Status != http.StatusNoContent {
		t.Fatalf("entries = %#v", entries)
	}
}

func TestRequestLogSupportsConcurrentRecordingAndSnapshots(t *testing.T) {
	requests := newRequestLog()
	var writers sync.WaitGroup
	for range 20 {
		writers.Go(func() {
			for status := range 100 {
				requests.record(requestEntry{Status: status})
				_ = requests.snapshots()
			}
		})
	}
	writers.Wait()
	if got := len(requests.snapshots()); got != requestLogCapacity {
		t.Fatalf("entries = %d, want %d", got, requestLogCapacity)
	}
}
