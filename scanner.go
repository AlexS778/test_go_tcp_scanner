package portscan

import (
	"context"
	"fmt"
	"time"

	"github.com/AlexS778/test_go_tcp_scanner/internal/domain"
	"github.com/AlexS778/test_go_tcp_scanner/internal/network"
	"github.com/AlexS778/test_go_tcp_scanner/internal/scan"
)

// State describes the outcome of a TCP connection attempt.
type State = domain.State

const (
	StateOpen        = domain.StateOpen
	StateClosed      = domain.StateClosed
	StateTimeout     = domain.StateTimeout
	StateUnreachable = domain.StateUnreachable
	StateCanceled    = domain.StateCanceled
	StateError       = domain.StateError
)

// Result describes one host, resolved IP address, and port.
// IP is nil when the host could not be resolved. Err is nil only for open ports.
// Duration measures the connection attempt, or the failed DNS lookup; it does
// not include time spent waiting for a worker or the concurrency limit.
type Result = domain.Result

type config struct {
	concurrency    int
	connectTimeout time.Duration
}

// Option configures a Scanner created by New.
type Option func(*config) error

// WithConcurrency sets the shared limit on network operations across all scans
// using the same Scanner. Both DNS lookups and TCP connections use this limit.
// The default is 100.
func WithConcurrency(n int) Option {
	return func(c *config) error {
		if n < 1 {
			return fmt.Errorf("concurrency must be positive, got %d", n)
		}
		c.concurrency = n
		return nil
	}
}

// WithConnectTimeout sets the timeout for each TCP connection attempt.
// It must be positive. The default is 500 milliseconds.
// DNS lookups use the scan context, without this additional timeout.
func WithConnectTimeout(timeout time.Duration) Option {
	return func(c *config) error {
		if timeout <= 0 {
			return fmt.Errorf("connect timeout must be positive, got %s", timeout)
		}
		c.connectTimeout = timeout
		return nil
	}
}

// Scanner performs TCP connect scans. Create it with New; its zero value is not
// usable. A Scanner is safe for concurrent use.
type Scanner struct {
	service *scan.Service
}

// New creates a Scanner using the standard library DNS resolver and TCP dialer.
func New(options ...Option) (*Scanner, error) {
	c := config{concurrency: 100, connectTimeout: 500 * time.Millisecond}
	for _, option := range options {
		if option == nil {
			return nil, fmt.Errorf("scanner option must not be nil")
		}
		if err := option(&c); err != nil {
			return nil, err
		}
	}
	return &Scanner{service: scan.New(
		c.concurrency, c.connectTimeout, network.NewResolver(), network.NewProber(),
	)}, nil
}

// Scan validates its inputs and starts scanning. Validation errors are returned
// synchronously, with a nil channel. DNS and connection errors arrive in results.
// Every unique host/IP/port combination produces one result on a complete scan.
// Result order is unspecified. Cancellation stops scheduling new work and closes
// the stream after active operations finish; unsent results may be discarded.
// Always drain the stream or cancel ctx when stopping early.
func (s *Scanner) Scan(ctx context.Context, hosts []string, ports PortSet) (<-chan Result, error) {
	if s == nil || s.service == nil {
		return nil, fmt.Errorf("scanner is not initialized; use portscan.New")
	}
	if ctx == nil {
		return nil, fmt.Errorf("scan context must not be nil")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	targets, err := domain.NormalizeHosts(hosts)
	if err != nil {
		return nil, err
	}
	values, err := ports.values()
	if err != nil {
		return nil, err
	}
	return s.service.Scan(ctx, targets, values), nil
}
