package portscan_test

import (
	"context"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/AlexS778/test_go_tcp_scanner"
)

func ExampleScanner_Scan() {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		log.Fatal(err)
	}
	defer listener.Close()

	scanner, err := portscan.New(
		portscan.WithConcurrency(20),
		portscan.WithConnectTimeout(500*time.Millisecond),
	)
	if err != nil {
		log.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	port := listener.Addr().(*net.TCPAddr).Port
	results, err := scanner.Scan(ctx, []string{"127.0.0.1"}, portscan.Ports(port))
	if err != nil {
		log.Fatal(err)
	}
	for result := range results {
		fmt.Println(result.Host, result.State)
	}
	// Output: 127.0.0.1 open
}
