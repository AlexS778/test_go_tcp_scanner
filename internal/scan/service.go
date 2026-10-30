package scan

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/AlexS778/test_go_tcp_scanner/internal/domain"
)

// Service coordinates resolution and probes through outbound ports.
type Service struct {
	concurrency int
	timeout     time.Duration
	resolver    Resolver
	prober      Prober
	slots       chan struct{}
}

// New receives validated configuration from the public package.
func New(concurrency int, timeout time.Duration, resolver Resolver, prober Prober) *Service {
	return &Service{
		concurrency: concurrency,
		timeout:     timeout,
		resolver:    resolver,
		prober:      prober,
		slots:       make(chan struct{}, concurrency),
	}
}

type job struct {
	host string
	ip   net.IP
	port uint16
}

// Scan receives owned, nonempty, validated input slices.
func (s *Service) Scan(ctx context.Context, hosts []string, ports []uint16) <-chan domain.Result {
	// Avoid starting an enormous worker pool for a tiny request. Divide first
	// so the host/port product cannot overflow an int.
	workers := s.concurrency
	if len(hosts) <= workers/len(ports) {
		workers = min(workers, len(hosts)*len(ports))
	}
	results := make(chan domain.Result, workers)
	hostJobs := make(chan string)
	probeJobs := make(chan job)

	var schedulers sync.WaitGroup
	for range min(workers, len(hosts)) {
		schedulers.Go(func() {
			for host := range hostJobs {
				if ctx.Err() != nil {
					return
				}
				s.scheduleHost(ctx, host, ports, probeJobs, results)
			}
		})
	}
	schedulers.Go(func() {
		defer close(hostJobs)
		for _, host := range hosts {
			if ctx.Err() != nil {
				return
			}
			select {
			case hostJobs <- host:
			case <-ctx.Done():
				return
			}
		}
	})

	var probes sync.WaitGroup
	for range workers {
		probes.Go(func() {
			for target := range probeJobs {
				if !s.acquire(ctx) {
					return
				}
				result := s.probe(ctx, target)
				s.release()
				if !sendResult(ctx, results, result) {
					return
				}
			}
		})
	}
	go func() {
		schedulers.Wait()
		close(probeJobs)
		probes.Wait()
		close(results)
	}()
	return results
}

func (s *Service) scheduleHost(ctx context.Context, host string, ports []uint16, jobs chan<- job, results chan<- domain.Result) {
	addresses, duration, err := s.resolve(ctx, host)
	if err != nil {
		state := domain.StateError
		if ctx.Err() != nil {
			state = domain.StateCanceled
		}
		for _, port := range ports {
			if !sendResult(ctx, results, domain.Result{
				Host: host, Port: port, State: state, Duration: duration, Err: err,
			}) {
				return
			}
			if ctx.Err() != nil {
				return
			}
		}
		return
	}
	for _, ip := range addresses {
		for _, port := range ports {
			if ctx.Err() != nil {
				return
			}
			select {
			case jobs <- job{host: host, ip: ip, port: port}:
			case <-ctx.Done():
				return
			}
		}
	}
}

func (s *Service) resolve(ctx context.Context, host string) ([]net.IP, time.Duration, error) {
	if ip := net.ParseIP(host); ip != nil {
		return []net.IP{ip}, 0, nil
	}
	if !s.acquire(ctx) {
		return nil, 0, ctx.Err()
	}
	start := time.Now()
	addresses, err := s.resolver.Resolve(ctx, host)
	duration := time.Since(start)
	s.release()
	if err != nil {
		return nil, duration, fmt.Errorf("resolve %q: %w", host, err)
	}
	seen := make(map[string]bool, len(addresses))
	var unique []net.IP
	for _, ip := range addresses {
		if ipv4 := ip.To4(); ipv4 != nil {
			ip = ipv4
		} else if ip.To16() == nil {
			continue
		}
		key := ip.String()
		if !seen[key] {
			seen[key] = true
			unique = append(unique, append(net.IP(nil), ip...))
		}
	}
	if len(unique) == 0 {
		return nil, duration, fmt.Errorf("resolve %q: no IP addresses", host)
	}
	return unique, duration, nil
}

func (s *Service) probe(ctx context.Context, target job) domain.Result {
	probeCtx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()
	start := time.Now()
	state, err := s.prober.Probe(probeCtx, target.ip, target.port)
	duration := time.Since(start)
	if err != nil && ctx.Err() != nil {
		state, err = domain.StateCanceled, ctx.Err()
	}
	return domain.Result{
		Host: target.host, IP: append(net.IP(nil), target.ip...), Port: target.port,
		State: state, Duration: duration, Err: err,
	}
}

func (s *Service) acquire(ctx context.Context) bool {
	if ctx.Err() != nil {
		return false
	}
	select {
	case s.slots <- struct{}{}:
		// A ready slot and cancellation may race. Check again before I/O.
		if ctx.Err() != nil {
			s.release()
			return false
		}
		return true
	case <-ctx.Done():
		return false
	}
}

func (s *Service) release() {
	<-s.slots
}

func sendResult(ctx context.Context, results chan<- domain.Result, result domain.Result) bool {
	// Keep a completed (including canceled) attempt if the reader or buffer is
	// ready. A stalled reader must not prevent cancellation from shutting down.
	select {
	case results <- result:
		return true
	default:
	}
	select {
	case results <- result:
		return true
	case <-ctx.Done():
		return false
	}
}
