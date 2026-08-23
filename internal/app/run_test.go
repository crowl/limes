package app

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestServeRunningStopsAllListenersOnParentCancellation(t *testing.T) {
	listeners := []net.Listener{mustListen(t), mustListen(t)}
	started := make(chan string, len(listeners))
	running := make([]runningProvider, 0, len(listeners))
	for index, listener := range listeners {
		name := "listener-" + strconv.Itoa(index)
		handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			started <- name
			w.WriteHeader(http.StatusNoContent)
		})
		running = append(running, runningProvider{provider: provider{name: name, address: listener.Addr().String(), authMode: "http", handler: handler}, listener: listener, server: &http.Server{Handler: handler}})
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	result := make(chan error, 1)
	go func() { result <- serveRunning(ctx, running, testLogger()) }()
	for _, listener := range listeners {
		response, err := http.Get("http://" + listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		if err := response.Body.Close(); err != nil {
			t.Fatal(err)
		}
	}
	for range listeners {
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatal("server did not begin serving")
		}
	}
	cancel()
	select {
	case err := <-result:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("serveRunning did not return after cancellation")
	}
	for _, listener := range listeners {
		if _, err := net.Dial("tcp", listener.Addr().String()); err == nil {
			t.Fatal("listener remains active after shutdown")
		}
	}
}

func TestServeRunningPropagatesFailureAndStopsOtherListeners(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	sentinel := errors.New("accept failed")
	failing := &failingListener{address: listener.Addr(), err: sentinel}
	running := []runningProvider{
		{provider: provider{name: "failing", address: "127.0.0.1:1", handler: http.NotFoundHandler()}, listener: failing, server: &http.Server{Handler: http.NotFoundHandler()}},
		{provider: provider{name: "other", address: listener.Addr().String(), handler: http.NotFoundHandler()}, listener: listener, server: &http.Server{Handler: http.NotFoundHandler()}},
	}
	result := make(chan error, 1)
	go func() { result <- serveRunning(t.Context(), running, testLogger()) }()
	select {
	case err := <-result:
		if !errors.Is(err, sentinel) || !strings.Contains(err.Error(), "serve failing") {
			t.Fatalf("serveRunning error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("serveRunning did not return")
	}
	if _, err := net.Dial("tcp", listener.Addr().String()); err == nil {
		t.Fatal("other listener remains active")
	}
}

func TestShutdownServersStartsAllShutdownsConcurrently(t *testing.T) {
	firstRequestStarted := make(chan struct{})
	releaseFirstRequest := make(chan struct{})
	secondShutdownStarted := make(chan struct{})

	first := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		close(firstRequestStarted)
		<-releaseFirstRequest
		w.WriteHeader(http.StatusNoContent)
	})}
	second := &http.Server{Handler: http.NotFoundHandler()}
	second.RegisterOnShutdown(func() { close(secondShutdownStarted) })

	firstListener := mustListen(t)
	secondListener := mustListen(t)
	firstServeResult := make(chan error, 1)
	secondServeResult := make(chan error, 1)
	go func() { firstServeResult <- first.Serve(firstListener) }()
	go func() { secondServeResult <- second.Serve(secondListener) }()

	requestResult := make(chan error, 1)
	go func() {
		response, err := http.Get("http://" + firstListener.Addr().String())
		if err == nil {
			err = response.Body.Close()
		}
		requestResult <- err
	}()
	select {
	case <-firstRequestStarted:
	case <-time.After(time.Second):
		t.Fatal("first server did not receive request")
	}

	result := make(chan error, 1)
	go func() {
		result <- shutdownServers([]runningProvider{
			{provider: provider{name: "first"}, listener: firstListener, server: first},
			{provider: provider{name: "second"}, listener: secondListener, server: second},
		}, 5*time.Second, testLogger())
	}()

	select {
	case <-secondShutdownStarted:
		close(releaseFirstRequest)
	case <-time.After(time.Second):
		close(releaseFirstRequest)
		t.Fatal("second shutdown did not start while first was draining")
	}
	if err := <-requestResult; err != nil {
		t.Fatal(err)
	}
	if err := <-result; err != nil {
		t.Fatal(err)
	}
	for _, serveResult := range []<-chan error{firstServeResult, secondServeResult} {
		if err := <-serveResult; !errors.Is(err, http.ErrServerClosed) {
			t.Fatalf("Serve() error = %v", err)
		}
	}
}

type failingListener struct {
	address net.Addr
	err     error
}

func (listener *failingListener) Accept() (net.Conn, error) { return nil, listener.err }
func (listener *failingListener) Close() error              { return nil }
func (listener *failingListener) Addr() net.Addr            { return listener.address }
