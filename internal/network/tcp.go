package network

import (
	"context"
	"errors"
	"net"
	"strconv"
	"syscall"

	"github.com/AlexS778/test_go_tcp_scanner/internal/domain"
)

type dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// Prober implements an ordinary TCP connect check, without sending any payload.
type Prober struct {
	dialer dialer
}

func NewProber() *Prober {
	return &Prober{dialer: &net.Dialer{}}
}

func (p *Prober) Probe(ctx context.Context, ip net.IP, port uint16) (domain.State, error) {
	address := net.JoinHostPort(ip.String(), strconv.Itoa(int(port)))
	conn, err := p.dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return classify(err), err
	}
	// The handshake is the check. A close error does not undo a successful
	// connection, but closing immediately is essential when scanning many ports.
	_ = conn.Close()
	return domain.StateOpen, nil
}

func classify(err error) domain.State {
	switch {
	case errors.Is(err, context.Canceled):
		return domain.StateCanceled
	case errors.Is(err, context.DeadlineExceeded):
		return domain.StateTimeout
	case errors.Is(err, syscall.ECONNREFUSED):
		return domain.StateClosed
	case errors.Is(err, syscall.ENETUNREACH), errors.Is(err, syscall.EHOSTUNREACH),
		errors.Is(err, syscall.ENETDOWN), errors.Is(err, syscall.EHOSTDOWN):
		return domain.StateUnreachable
	}
	var timeout net.Error
	if errors.As(err, &timeout) && timeout.Timeout() {
		return domain.StateTimeout
	}
	return domain.StateError
}
