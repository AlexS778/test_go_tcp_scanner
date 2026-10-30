package network

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/AlexS778/test_go_tcp_scanner/internal/domain"
)

func TestClassify(t *testing.T) {
	tests := []struct {
		name  string
		err   error
		state domain.State
	}{
		{"refused", syscall.ECONNREFUSED, domain.StateClosed},
		{"timeout errno", syscall.ETIMEDOUT, domain.StateTimeout},
		{"deadline", context.DeadlineExceeded, domain.StateTimeout},
		{"canceled", context.Canceled, domain.StateCanceled},
		{"network unreachable", syscall.ENETUNREACH, domain.StateUnreachable},
		{"host unreachable", syscall.EHOSTUNREACH, domain.StateUnreachable},
		{"network down", syscall.ENETDOWN, domain.StateUnreachable},
		{"host down", syscall.EHOSTDOWN, domain.StateUnreachable},
		{"permission", syscall.EACCES, domain.StateError},
		{"text is not an errno", errors.New("connection refused"), domain.StateError},
		{"timeout interface", &net.DNSError{IsTimeout: true}, domain.StateTimeout},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			wrapped := fmt.Errorf("probe failed: %w", &net.OpError{
				Op: "dial", Net: "tcp", Err: os.NewSyscallError("connect", test.err),
			})
			if got := classify(wrapped); got != test.state {
				t.Fatalf("state = %s, want %s", got, test.state)
			}
		})
	}
}

type dialFunc func(context.Context, string, string) (net.Conn, error)

func (f dialFunc) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return f(ctx, network, address)
}

func TestProbeClosesConnection(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	defer client.Close()
	if err := server.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	prober := &Prober{dialer: dialFunc(func(_ context.Context, network, address string) (net.Conn, error) {
		if network != "tcp" || address != "[::1]:443" {
			t.Errorf("dial arguments = %s %s", network, address)
		}
		return client, nil
	})}
	state, err := prober.Probe(context.Background(), net.ParseIP("::1"), 443)
	if err != nil || state != domain.StateOpen {
		t.Fatalf("probe = %s, %v", state, err)
	}
	var data [1]byte
	if _, err := server.Read(data[:]); !errors.Is(err, io.EOF) {
		t.Fatalf("read after probe = %v, want EOF", err)
	}
}

func TestProbePreservesError(t *testing.T) {
	want := &net.OpError{Op: "dial", Net: "tcp", Err: syscall.ECONNREFUSED}
	prober := &Prober{dialer: dialFunc(func(context.Context, string, string) (net.Conn, error) {
		return nil, want
	})}
	state, err := prober.Probe(context.Background(), net.ParseIP("127.0.0.1"), 80)
	if state != domain.StateClosed || !errors.Is(err, want) {
		t.Fatalf("probe = %s, %v", state, err)
	}
}
