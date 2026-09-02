package egress

import (
	"errors"
	"net"
	"net/http"
	"sync"
	"time"
)

const (
	relayIdleTimeout = 5 * time.Minute
	relayBufferSize  = 32 << 10
)

// relay forwards an unclaimed destination as an opaque byte stream. Limes does
// not inspect, modify, or authenticate relayed traffic.
func relay(w http.ResponseWriter, request *http.Request, authority string, dialer *net.Dialer, proxy Proxy, started time.Time) {
	upstream, err := dialer.DialContext(request.Context(), "tcp", authority)
	if err != nil {
		status := http.StatusBadGateway
		message := "relay destination is unreachable"
		if errors.Is(err, errPrivateDestination) {
			status = http.StatusForbidden
			message = "relay destination is not a public address"
		}
		reject(w, proxy, authority, status, message, started)
		return
	}
	defer upstream.Close()

	client, err := establishTunnel(w)
	if err != nil {
		return
	}
	defer client.Close()

	copyBothDirections(client, upstream)
	if proxy.Observe != nil {
		proxy.Observe(authority, http.StatusOK, started)
	}
}

func copyBothDirections(client, upstream net.Conn) {
	var wait sync.WaitGroup
	for _, direction := range [][2]net.Conn{{upstream, client}, {client, upstream}} {
		wait.Go(func() {
			destination, source := direction[0], direction[1]
			copyUntilIdle(destination, source)
			// Closing both ends releases the opposite copy, which is
			// otherwise blocked reading from a half-open connection.
			destination.Close()
			source.Close()
		})
	}
	wait.Wait()
}

func copyUntilIdle(destination, source net.Conn) {
	buffer := make([]byte, relayBufferSize)
	for {
		if err := source.SetReadDeadline(time.Now().Add(relayIdleTimeout)); err != nil {
			return
		}
		read, readErr := source.Read(buffer)
		if read > 0 {
			if err := destination.SetWriteDeadline(time.Now().Add(relayIdleTimeout)); err != nil {
				return
			}
			if _, writeErr := destination.Write(buffer[:read]); writeErr != nil {
				return
			}
		}
		if readErr != nil {
			return
		}
	}
}
