// Package portscan scans TCP ports with bounded concurrency.
//
// Scan returns a stream of results. Callers should either drain the stream or
// cancel its context, and may safely reuse a Scanner from multiple goroutines.
package portscan
