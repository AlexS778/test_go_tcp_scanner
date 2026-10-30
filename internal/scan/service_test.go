package scan

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AlexS778/test_go_tcp_scanner/internal/domain"
)

type resolveFunc func(context.Context, string) ([]net.IP, error)

func (f resolveFunc) Resolve(ctx context.Context, host string) ([]net.IP, error) {
	return f(ctx, host)
}

type probeFunc func(context.Context, net.IP, uint16) (domain.State, error)

func (f probeFunc) Probe(ctx context.Context, ip net.IP, port uint16) (domain.State, error) {
	return f(ctx, ip, port)
}

func testContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func collect(t *testing.T, results <-chan domain.Result) []domain.Result {
	t.Helper()
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	var all []domain.Result
	for {
		select {
		case result, ok := <-results:
			if !ok {
				return all
			}
			all = append(all, result)
		case <-timer.C:
			t.Fatal("result stream did not close")
			return nil
		}
	}
}

func waitSignal(t *testing.T, signal <-chan struct{}) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(5 * time.Second):
		t.Fatal("operation did not start or finish")
	}
}

func unexpectedResolver(t *testing.T) Resolver {
	t.Helper()
	return resolveFunc(func(context.Context, string) ([]net.IP, error) {
		t.Error("IP literals must not use DNS")
		return nil, errors.New("unexpected DNS lookup")
	})
}

func openProbe(context.Context, net.IP, uint16) (domain.State, error) {
	return domain.StateOpen, nil
}

func TestScanAllResolvedAddresses(t *testing.T) {
	var lookups atomic.Int32
	resolver := resolveFunc(func(_ context.Context, host string) ([]net.IP, error) {
		lookups.Add(1)
		if host != "example.test" {
			t.Errorf("unexpected lookup: %s", host)
		}
		return []net.IP{
			net.ParseIP("192.0.2.1"), net.IPv4(192, 0, 2, 1).To4(),
			net.ParseIP("2001:db8::1"),
		}, nil
	})
	s := New(4, time.Second, resolver, probeFunc(openProbe))
	results := collect(t, s.Scan(testContext(t), []string{"example.test", "127.0.0.1"}, []uint16{22, 443}))
	if len(results) != 6 || lookups.Load() != 1 {
		t.Fatalf("got %d results, %d lookups; want 6 and 1", len(results), lookups.Load())
	}
	type target struct {
		host string
		ip   string
		port uint16
	}
	seen := make(map[target]bool)
	for _, result := range results {
		key := target{result.Host, result.IP.String(), result.Port}
		if seen[key] {
			t.Fatalf("duplicate result: %+v", result)
		}
		seen[key] = true
		if result.State != domain.StateOpen || result.Err != nil || result.Duration < 0 {
			t.Fatalf("unexpected result: %+v", result)
		}
	}
	for _, ip := range []string{"192.0.2.1", "2001:db8::1"} {
		for _, port := range []uint16{22, 443} {
			if !seen[target{"example.test", ip, port}] {
				t.Fatalf("missing result for %s:%d", ip, port)
			}
		}
	}
}

func TestDNSFailureDoesNotStopOtherHosts(t *testing.T) {
	wantErr := &net.DNSError{Name: "missing.test", IsNotFound: true}
	s := New(3, time.Second, resolveFunc(func(context.Context, string) ([]net.IP, error) {
		return nil, wantErr
	}), probeFunc(openProbe))
	results := collect(t, s.Scan(testContext(t), []string{"missing.test", "127.0.0.1"}, []uint16{80, 443}))
	if len(results) != 4 {
		t.Fatalf("got %d results, want 4", len(results))
	}
	for _, result := range results {
		if result.Host == "missing.test" {
			if result.State != domain.StateError || result.IP != nil || !errors.Is(result.Err, wantErr) {
				t.Fatalf("DNS failure result: %+v", result)
			}
		} else if result.State != domain.StateOpen || result.Err != nil {
			t.Fatalf("literal IP result: %+v", result)
		}
	}
}

func TestDNSWithoutUsableAddresses(t *testing.T) {
	for name, addresses := range map[string][]net.IP{
		"empty": nil, "invalid": {nil, {1, 2, 3}},
	} {
		t.Run(name, func(t *testing.T) {
			s := New(1, time.Second, resolveFunc(func(context.Context, string) ([]net.IP, error) {
				return addresses, nil
			}), probeFunc(func(context.Context, net.IP, uint16) (domain.State, error) {
				t.Error("must not probe an invalid address")
				return domain.StateError, nil
			}))
			results := collect(t, s.Scan(testContext(t), []string{"empty.test"}, []uint16{80}))
			if len(results) != 1 || results[0].State != domain.StateError || results[0].Err == nil {
				t.Fatalf("unexpected results: %+v", results)
			}
		})
	}
}

func TestConcurrencyLimitIsSharedByScansAndDNS(t *testing.T) {
	const limit = 3
	var active, peak atomic.Int32
	started := make(chan struct{}, 100)
	release := make(chan struct{})
	operation := func(ctx context.Context) error {
		n := active.Add(1)
		defer active.Add(-1)
		for previous := peak.Load(); n > previous; previous = peak.Load() {
			if peak.CompareAndSwap(previous, n) {
				break
			}
		}
		started <- struct{}{}
		select {
		case <-release:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	s := New(limit, time.Second, resolveFunc(func(ctx context.Context, _ string) ([]net.IP, error) {
		if err := operation(ctx); err != nil {
			return nil, err
		}
		return []net.IP{net.ParseIP("192.0.2.1")}, nil
	}), probeFunc(func(ctx context.Context, _ net.IP, _ uint16) (domain.State, error) {
		err := operation(ctx)
		return domain.StateOpen, err
	}))
	ctx := testContext(t)
	hosts := []string{"a.test", "b.test", "c.test", "127.0.0.1"}
	first := s.Scan(ctx, hosts, []uint16{80, 443})
	second := s.Scan(ctx, hosts, []uint16{80, 443})
	for range limit {
		waitSignal(t, started)
	}
	select {
	case <-started:
		t.Fatal("concurrency exceeded the shared limit")
	case <-time.After(30 * time.Millisecond):
	}
	close(release)
	if got := len(collect(t, first)); got != 8 {
		t.Fatalf("first scan: %d results, want 8", got)
	}
	if got := len(collect(t, second)); got != 8 {
		t.Fatalf("second scan: %d results, want 8", got)
	}
	if peak.Load() != limit || active.Load() != 0 {
		t.Fatalf("peak = %d, active after completion = %d", peak.Load(), active.Load())
	}
}

func TestCancelActiveProbesAndReuseScanner(t *testing.T) {
	const concurrency = 3
	started := make(chan struct{}, concurrency)
	finished := make(chan struct{}, concurrency)
	var calls atomic.Int32
	s := New(concurrency, time.Minute, unexpectedResolver(t), probeFunc(func(ctx context.Context, _ net.IP, _ uint16) (domain.State, error) {
		if calls.Add(1) <= concurrency {
			started <- struct{}{}
			<-ctx.Done()
			finished <- struct{}{}
			return domain.StateCanceled, ctx.Err()
		}
		return domain.StateOpen, nil
	}))
	ctx, cancel := context.WithCancel(testContext(t))
	defer cancel()
	results := s.Scan(ctx, []string{"127.0.0.1"}, []uint16{1, 2, 3, 4, 5, 6})
	for range concurrency {
		waitSignal(t, started)
	}
	cancel()
	for range concurrency {
		waitSignal(t, finished)
	}
	canceled := collect(t, results)
	if len(canceled) != concurrency || calls.Load() != concurrency {
		t.Fatalf("got %d results and %d probes, want %d", len(canceled), calls.Load(), concurrency)
	}
	for _, result := range canceled {
		if result.State != domain.StateCanceled || !errors.Is(result.Err, context.Canceled) {
			t.Fatalf("unexpected canceled result: %+v", result)
		}
	}
	next := collect(t, s.Scan(testContext(t), []string{"127.0.0.1"}, []uint16{80}))
	if len(next) != 1 || next[0].State != domain.StateOpen {
		t.Fatalf("scanner did not recover after cancellation: %+v", next)
	}
}

func TestCancelWhileWaitingForSharedSlot(t *testing.T) {
	started := make(chan struct{}, 2)
	s := New(1, time.Minute, unexpectedResolver(t), probeFunc(func(ctx context.Context, _ net.IP, _ uint16) (domain.State, error) {
		started <- struct{}{}
		<-ctx.Done()
		return domain.StateCanceled, ctx.Err()
	}))
	firstCtx, cancelFirst := context.WithCancel(testContext(t))
	defer cancelFirst()
	first := s.Scan(firstCtx, []string{"127.0.0.1"}, []uint16{80})
	waitSignal(t, started)
	secondCtx, cancelSecond := context.WithCancel(testContext(t))
	second := s.Scan(secondCtx, []string{"127.0.0.2"}, []uint16{80})
	cancelSecond()
	if got := collect(t, second); len(got) != 0 {
		t.Fatalf("probe started without a slot: %+v", got)
	}
	cancelFirst()
	collect(t, first)
	select {
	case <-started:
		t.Fatal("a canceled scan started another probe")
	default:
	}
}

func TestCancelDNS(t *testing.T) {
	started := make(chan struct{})
	s := New(1, time.Second, resolveFunc(func(ctx context.Context, _ string) ([]net.IP, error) {
		close(started)
		<-ctx.Done()
		return nil, ctx.Err()
	}), probeFunc(openProbe))
	ctx, cancel := context.WithCancel(testContext(t))
	defer cancel()
	results := s.Scan(ctx, []string{"slow.test"}, []uint16{80, 443})
	waitSignal(t, started)
	cancel()
	all := collect(t, results)
	if len(all) != 1 || all[0].State != domain.StateCanceled || !errors.Is(all[0].Err, context.Canceled) {
		t.Fatalf("unexpected canceled DNS results: %+v", all)
	}
}

func TestConnectTimeoutDoesNotCancelScan(t *testing.T) {
	s := New(1, 10*time.Millisecond, unexpectedResolver(t), probeFunc(func(ctx context.Context, _ net.IP, port uint16) (domain.State, error) {
		if port == 80 {
			<-ctx.Done()
			return domain.StateTimeout, ctx.Err()
		}
		return domain.StateOpen, nil
	}))
	results := collect(t, s.Scan(testContext(t), []string{"127.0.0.1"}, []uint16{80, 443}))
	if len(results) != 2 {
		t.Fatalf("got %d results, want 2", len(results))
	}
	for _, result := range results {
		if result.Port == 80 {
			if result.State != domain.StateTimeout || !errors.Is(result.Err, context.DeadlineExceeded) || result.Duration <= 0 {
				t.Fatalf("unexpected timeout result: %+v", result)
			}
		} else if result.State != domain.StateOpen {
			t.Fatalf("timeout affected the next probe: %+v", result)
		}
	}
}

func TestScanDeadlineMeansCanceled(t *testing.T) {
	s := New(1, time.Minute, unexpectedResolver(t), probeFunc(func(ctx context.Context, _ net.IP, _ uint16) (domain.State, error) {
		<-ctx.Done()
		return domain.StateTimeout, ctx.Err()
	}))
	ctx, cancel := context.WithTimeout(testContext(t), 10*time.Millisecond)
	defer cancel()
	results := collect(t, s.Scan(ctx, []string{"127.0.0.1"}, []uint16{80}))
	if len(results) != 1 || results[0].State != domain.StateCanceled || !errors.Is(results[0].Err, context.DeadlineExceeded) {
		t.Fatalf("unexpected scan deadline results: %+v", results)
	}
}

func TestSlowReaderDoesNotLoseResults(t *testing.T) {
	const count = 200
	ports := make([]uint16, count)
	for i := range ports {
		ports[i] = uint16(i + 1)
	}
	probed := make(chan struct{}, count)
	s := New(2, time.Second, unexpectedResolver(t), probeFunc(func(context.Context, net.IP, uint16) (domain.State, error) {
		probed <- struct{}{}
		return domain.StateOpen, nil
	}))
	results := s.Scan(testContext(t), []string{"127.0.0.1"}, ports)
	// Two buffered results and two workers blocked on delivery must apply
	// backpressure, even though there are many more available ports.
	for range 4 {
		waitSignal(t, probed)
	}
	select {
	case <-probed:
		t.Fatal("scanner is accumulating work while the reader is stalled")
	case <-time.After(20 * time.Millisecond):
	}
	if got := len(collect(t, results)); got != count {
		t.Fatalf("got %d results, want %d", got, count)
	}
}

func TestCancelWithFullResultBuffer(t *testing.T) {
	probed := make(chan struct{}, 4)
	s := New(2, time.Second, unexpectedResolver(t), probeFunc(func(context.Context, net.IP, uint16) (domain.State, error) {
		probed <- struct{}{}
		return domain.StateOpen, nil
	}))
	ctx, cancel := context.WithCancel(testContext(t))
	defer cancel()
	results := s.Scan(ctx, []string{"127.0.0.1"}, []uint16{1, 2, 3, 4, 5, 6})
	for range 4 {
		waitSignal(t, probed)
	}
	cancel()
	all := collect(t, results)
	if len(all) < 2 || len(all) > 4 {
		t.Fatalf("got %d results; expected buffered and possibly in-flight results", len(all))
	}
}

func TestResultIPsAreIndependent(t *testing.T) {
	ctx := testContext(t)
	s := New(4, time.Second, unexpectedResolver(t), probeFunc(openProbe))
	results := s.Scan(ctx, []string{"127.0.0.1"}, []uint16{1, 2, 3, 4, 5, 6})
	for result := range results {
		if !result.IP.Equal(net.ParseIP("127.0.0.1")) {
			t.Fatalf("another result changed this IP: %s", result.IP)
		}
		for i := range result.IP {
			result.IP[i] = 0
		}
	}
}
