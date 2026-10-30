package scan

import (
	"context"
	"net"

	"github.com/AlexS778/test_go_tcp_scanner/internal/domain"
)

// Resolver returns a host's addresses. Implementations must honor ctx, be safe
// for concurrent calls, and not mutate addresses after returning them.
type Resolver interface {
	Resolve(ctx context.Context, host string) ([]net.IP, error)
}

// Prober attempts a connection and releases its resources before returning.
// Implementations must honor ctx, be safe for concurrent calls, and not mutate ip.
type Prober interface {
	Probe(ctx context.Context, ip net.IP, port uint16) (domain.State, error)
}
