package app

import (
	"bufio"
	"net"
	"net/http"
	"sync"
	"time"
	"unicode/utf8"
)

const (
	requestLogCapacity  = 200
	maxLoggedPathLength = 2048
	truncatedPathSuffix = "…"
)

type requestEntry struct {
	CompletedAt time.Time
	Listener    string
	Backend     string
	Method      string
	Path        string
	Status      int
	Duration    time.Duration
}

type requestLog struct {
	mu      sync.RWMutex
	entries []requestEntry
	next    int
	full    bool
	now     func() time.Time
}

func newRequestLog() *requestLog {
	return &requestLog{
		entries: make([]requestEntry, requestLogCapacity),
		now:     time.Now,
	}
}

func (log *requestLog) record(entry requestEntry) {
	log.mu.Lock()
	log.entries[log.next] = entry
	log.next = (log.next + 1) % len(log.entries)
	if log.next == 0 {
		log.full = true
	}
	log.mu.Unlock()
}

func (log *requestLog) snapshots() []requestEntry {
	log.mu.RLock()
	defer log.mu.RUnlock()

	count := log.next
	if log.full {
		count = len(log.entries)
	}
	entries := make([]requestEntry, 0, count)
	for offset := range count {
		index := log.next - 1 - offset
		if index < 0 {
			index += len(log.entries)
		}
		entries = append(entries, log.entries[index])
	}
	return entries
}

func (log *requestLog) observe(listener, backend, method, path string, status int, started time.Time) {
	completedAt := log.now()
	log.record(requestEntry{
		CompletedAt: completedAt,
		Listener:    listener,
		Backend:     backend,
		Method:      method,
		Path:        truncateRequestPath(path),
		Status:      status,
		Duration:    completedAt.Sub(started),
	})
}

func truncateRequestPath(path string) string {
	if len(path) <= maxLoggedPathLength {
		return path
	}
	end := maxLoggedPathLength - len(truncatedPathSuffix)
	for end > 0 && !utf8.RuneStart(path[end]) {
		end--
	}
	return path[:end] + truncatedPathSuffix
}

func (log *requestLog) wrap(listener, backend string, handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		started := log.now()
		response := &statusResponseWriter{ResponseWriter: w}
		handler.ServeHTTP(response, request)
		log.observe(listener, backend, request.Method, request.URL.Path, response.statusCode(), started)
	})
}

type statusResponseWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusResponseWriter) WriteHeader(status int) {
	if status >= 100 && status < 200 {
		w.ResponseWriter.WriteHeader(status)
		return
	}
	if w.status != 0 {
		return
	}
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

func (w *statusResponseWriter) Write(body []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.ResponseWriter.Write(body)
}

func (w *statusResponseWriter) FlushError() error {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return http.NewResponseController(w.ResponseWriter).Flush()
}

func (w *statusResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return http.NewResponseController(w.ResponseWriter).Hijack()
}

func (w *statusResponseWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

func (w *statusResponseWriter) statusCode() int {
	if w.status == 0 {
		return http.StatusOK
	}
	return w.status
}
