package egress

import (
	"net"
	"sync"
)

// tunnelListener serves one already-established connection to an http.Server.
// Accept yields the connection once and then blocks until it closes, so Serve
// returns only after the connection is finished.
type tunnelListener struct {
	connection *closeNotifyConn
	accepted   bool
}

func newTunnelListener(connection net.Conn) *tunnelListener {
	return &tunnelListener{connection: &closeNotifyConn{Conn: connection, closed: make(chan struct{})}}
}

func (listener *tunnelListener) Accept() (net.Conn, error) {
	if !listener.accepted {
		listener.accepted = true
		return listener.connection, nil
	}
	<-listener.connection.closed
	return nil, net.ErrClosed
}

func (listener *tunnelListener) Close() error { return nil }

func (listener *tunnelListener) Addr() net.Addr { return listener.connection.LocalAddr() }

type closeNotifyConn struct {
	net.Conn
	closed chan struct{}
	once   sync.Once
}

func (connection *closeNotifyConn) Close() error {
	err := connection.Conn.Close()
	connection.once.Do(func() { close(connection.closed) })
	return err
}
