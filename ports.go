package portscan

import "fmt"

type portRange struct {
	first int
	last  int
}

// PortSet is an immutable selection of ports. Use Ports, Range, and Union to
// construct it. Scan validates the selection; the zero value is an empty set.
type PortSet struct {
	ranges []portRange
}

// Ports selects individual ports. Ports outside 1..65535 are rejected by Scan.
func Ports(ports ...int) PortSet {
	ranges := make([]portRange, len(ports))
	for i, port := range ports {
		ranges[i] = portRange{first: port, last: port}
	}
	return PortSet{ranges: ranges}
}

// Range selects an inclusive range. Scan rejects invalid or reversed bounds.
func Range(first, last int) PortSet {
	return PortSet{ranges: []portRange{{first: first, last: last}}}
}

// Union combines selections. Duplicate ports are scanned once per host/IP pair.
func Union(sets ...PortSet) PortSet {
	var ranges []portRange
	for _, set := range sets {
		ranges = append(ranges, set.ranges...)
	}
	return PortSet{ranges: ranges}
}

func (p PortSet) values() ([]uint16, error) {
	if len(p.ranges) == 0 {
		return nil, fmt.Errorf("at least one port is required")
	}
	var selected [65536]bool
	for _, r := range p.ranges {
		if r.first < 1 || r.first > 65535 || r.last < 1 || r.last > 65535 {
			return nil, fmt.Errorf("ports must be in 1..65535, got %d..%d", r.first, r.last)
		}
		if r.first > r.last {
			return nil, fmt.Errorf("port range is reversed: %d..%d", r.first, r.last)
		}
		for port := r.first; port <= r.last; port++ {
			selected[port] = true
		}
	}
	var ports []uint16
	for port := 1; port <= 65535; port++ {
		if selected[port] {
			ports = append(ports, uint16(port))
		}
	}
	return ports, nil
}
