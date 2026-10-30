package domain

import (
	"net"
	"time"
)

// State describes the outcome of an attempt.
type State string

const (
	StateOpen        State = "open"
	StateClosed      State = "closed"
	StateTimeout     State = "timeout"
	StateUnreachable State = "unreachable"
	StateCanceled    State = "canceled"
	StateError       State = "error"
)

// Result is independent of the transport and the scan scheduler.
type Result struct {
	Host     string
	IP       net.IP
	Port     uint16
	State    State
	Duration time.Duration
	Err      error
}
