package domain

import (
	"fmt"
	"net"
	"strings"
)

// NormalizeHosts validates targets and removes duplicates while keeping their
// first occurrence. DNS names remain names so resolution happens once per scan.
func NormalizeHosts(hosts []string) ([]string, error) {
	if len(hosts) == 0 {
		return nil, fmt.Errorf("at least one host is required")
	}
	seen := make(map[string]struct{}, len(hosts))
	targets := make([]string, 0, len(hosts))
	for _, raw := range hosts {
		host := strings.ToLower(strings.TrimSpace(raw))
		if ip := net.ParseIP(host); ip != nil {
			host = ip.String()
		} else if !validHostname(host) {
			return nil, fmt.Errorf("invalid host %q: expected an IP address or DNS hostname", raw)
		}
		if _, exists := seen[host]; !exists {
			seen[host] = struct{}{}
			targets = append(targets, host)
		}
	}
	return targets, nil
}

func validHostname(host string) bool {
	name := strings.TrimSuffix(host, ".")
	if len(name) == 0 || len(name) > 253 {
		return false
	}
	// A malformed dotted IPv4 address should not silently become a DNS lookup.
	onlyDigitsAndDots := strings.Contains(name, ".")
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, ch := range label {
			if (ch < 'a' || ch > 'z') && (ch < '0' || ch > '9') && ch != '-' {
				return false
			}
			if ch < '0' || ch > '9' {
				onlyDigitsAndDots = false
			}
		}
	}
	return !onlyDigitsAndDots
}
