package network

import (
	"context"
	"net"
)

// Resolver adapts the standard library DNS resolver to the application port.
type Resolver struct {
	resolver *net.Resolver
}

func NewResolver() *Resolver {
	return &Resolver{resolver: &net.Resolver{}}
}

func (r *Resolver) Resolve(ctx context.Context, host string) ([]net.IP, error) {
	addresses, err := r.resolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	ips := make([]net.IP, 0, len(addresses))
	for _, address := range addresses {
		// Scoped IPv6 literals are not part of the package's target format.
		if address.Zone == "" {
			ips = append(ips, address.IP)
		}
	}
	return ips, nil
}
