package egress

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"syscall"
	"time"
)

const relayDialTimeout = 30 * time.Second

// errPrivateDestination reports a destination the proxy refuses to reach on a
// client's behalf. Relayed traffic is chosen by the client, so limiting it to
// public addresses keeps clients from using Limes to reach the host loopback
// or the surrounding private network.
var errPrivateDestination = errors.New("destination is not a public address")

// publicDialer rejects non-public addresses in Control, which runs after
// resolution and before connect for every candidate address. Checking there
// leaves no window between the decision and the connection, so a hostname
// resolving to a private address cannot slip through.
func publicDialer() *net.Dialer {
	return &net.Dialer{
		Timeout:   relayDialTimeout,
		KeepAlive: 30 * time.Second,
		Control: func(_, address string, _ syscall.RawConn) error {
			return requirePublicAddress(address)
		},
	}
}

func requirePublicAddress(address string) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("parse destination %q: %w", address, err)
	}
	parsed, err := netip.ParseAddr(host)
	if err != nil {
		return fmt.Errorf("parse destination address %q: %w", host, err)
	}
	if !publicAddress(parsed) {
		return fmt.Errorf("%w: %s", errPrivateDestination, parsed)
	}
	return nil
}

func publicAddress(address netip.Addr) bool {
	address = address.Unmap()
	switch {
	case !address.IsValid(),
		address.IsUnspecified(),
		address.IsLoopback(),
		address.IsPrivate(),
		address.IsLinkLocalUnicast(),
		address.IsLinkLocalMulticast(),
		address.IsInterfaceLocalMulticast(),
		address.IsMulticast():
		return false
	}
	return true
}
