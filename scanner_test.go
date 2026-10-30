package portscan_test

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/AlexS778/test_go_tcp_scanner"
)

func TestNewRejectsInvalidOptions(t *testing.T) {
	for name, option := range map[string]portscan.Option{
		"zero concurrency":     portscan.WithConcurrency(0),
		"negative concurrency": portscan.WithConcurrency(-1),
		"zero timeout":         portscan.WithConnectTimeout(0),
		"negative timeout":     portscan.WithConnectTimeout(-time.Second),
		"nil option":           nil,
	} {
		t.Run(name, func(t *testing.T) {
			if scanner, err := portscan.New(option); scanner != nil || err == nil {
				t.Fatalf("New = %v, %v; want nil scanner and error", scanner, err)
			}
		})
	}
}

func TestScanRejectsInvalidInputs(t *testing.T) {
	scanner, err := portscan.New()
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name  string
		ctx   context.Context
		hosts []string
		ports portscan.PortSet
	}{
		{"nil context", nil, []string{"127.0.0.1"}, portscan.Ports(80)},
		{"no hosts", t.Context(), nil, portscan.Ports(80)},
		{"empty host", t.Context(), []string{""}, portscan.Ports(80)},
		{"invalid address", t.Context(), []string{"999.0.0.1"}, portscan.Ports(80)},
		{"host with port", t.Context(), []string{"localhost:80"}, portscan.Ports(80)},
		{"no ports", t.Context(), []string{"localhost"}, portscan.Ports()},
		{"invalid port", t.Context(), []string{"localhost"}, portscan.Ports(65536)},
		{"reversed range", t.Context(), []string{"localhost"}, portscan.Range(1000, 1)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results, err := scanner.Scan(test.ctx, test.hosts, test.ports)
			if results != nil || err == nil {
				t.Fatalf("Scan = %v, %v; want nil stream and error", results, err)
			}
		})
	}
}

func TestScanAlreadyCanceled(t *testing.T) {
	scanner, err := portscan.New()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	results, err := scanner.Scan(ctx, []string{"127.0.0.1"}, portscan.Ports(80))
	if results != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("Scan = %v, %v; want context.Canceled", results, err)
	}
}

func TestUninitializedScanner(t *testing.T) {
	for _, scanner := range []*portscan.Scanner{nil, {}} {
		results, err := scanner.Scan(t.Context(), []string{"127.0.0.1"}, portscan.Ports(80))
		if results != nil || err == nil {
			t.Fatalf("Scan = %v, %v; want initialization error", results, err)
		}
	}
}

func TestTCPScanOpenAndClosed(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	openPort := listener.Addr().(*net.TCPAddr).Port
	closed, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closedPort := closed.Addr().(*net.TCPAddr).Port
	if err := closed.Close(); err != nil {
		t.Fatal(err)
	}
	scanner, err := portscan.New(portscan.WithConcurrency(2), portscan.WithConnectTimeout(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	results, err := scanner.Scan(ctx, []string{"127.0.0.1", " ::ffff:127.0.0.1 "}, portscan.Ports(openPort, closedPort, openPort))
	if err != nil {
		t.Fatal(err)
	}
	seen := make(map[uint16]portscan.Result)
	for result := range results {
		if _, exists := seen[result.Port]; exists {
			t.Fatalf("duplicate result: %+v", result)
		}
		seen[result.Port] = result
		if result.Host != "127.0.0.1" || !result.IP.Equal(net.ParseIP("127.0.0.1")) || result.Duration < 0 {
			t.Fatalf("incorrect target or duration: %+v", result)
		}
	}
	if len(seen) != 2 {
		t.Fatalf("got %d results, want 2", len(seen))
	}
	if result := seen[uint16(openPort)]; result.State != portscan.StateOpen || result.Err != nil {
		t.Fatalf("open port result: %+v", result)
	}
	if result := seen[uint16(closedPort)]; result.State != portscan.StateClosed || result.Err == nil {
		t.Fatalf("closed port result: %+v", result)
	}
	assertPeerClosed(t, listener)
}

func TestTCPScanIPv6(t *testing.T) {
	listener, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skipf("IPv6 loopback unavailable: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	scanner, err := portscan.New()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	results, err := scanner.Scan(ctx, []string{"::1"}, portscan.Ports(listener.Addr().(*net.TCPAddr).Port))
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for result := range results {
		count++
		if result.State != portscan.StateOpen || result.Err != nil || !result.IP.Equal(net.ParseIP("::1")) {
			t.Fatalf("IPv6 result: %+v", result)
		}
	}
	if count != 1 {
		t.Fatalf("got %d results, want 1", count)
	}
	assertPeerClosed(t, listener)
}

func assertPeerClosed(t *testing.T, listener net.Listener) {
	t.Helper()
	if err := listener.(*net.TCPListener).SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	conn, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	var data [1]byte
	if _, err := conn.Read(data[:]); !errors.Is(err, io.EOF) {
		t.Fatalf("scanner did not close the connection: %v", err)
	}
}
