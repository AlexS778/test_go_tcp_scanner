package domain

import (
	"reflect"
	"strings"
	"testing"
)

func TestNormalizeHosts(t *testing.T) {
	input := []string{
		" EXAMPLE.com ", "example.COM", "example.com.", "localhost",
		"127.0.0.1", "::ffff:127.0.0.1", "2001:0DB8::1", "2001:db8::1",
		"xn--e1afmkfd.xn--p1ai", "123",
	}
	want := []string{
		"example.com", "example.com.", "localhost", "127.0.0.1", "2001:db8::1",
		"xn--e1afmkfd.xn--p1ai", "123",
	}
	got, err := NormalizeHosts(input)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("hosts = %v, want %v", got, want)
	}
	if input[0] != " EXAMPLE.com " {
		t.Fatal("normalization changed the input slice")
	}
}

func TestInvalidHosts(t *testing.T) {
	invalid := []string{
		"", " ", ".", "example..com", "-host", "host-", "a.-b",
		"http://example.com", "example.com:80", "[::1]", "::invalid",
		"fe80::1%en0", "192.168.1.999", "01.2.3.4", "127.1",
		"192.168.0.0/24", "host_name", "пример.рф", "a b",
		strings.Repeat("a", 64) + ".com",
		strings.Repeat("abcd.", 51) + "a",
	}
	for _, host := range invalid {
		t.Run(host, func(t *testing.T) {
			if _, err := NormalizeHosts([]string{host}); err == nil {
				t.Fatalf("accepted invalid host %q", host)
			}
		})
	}
	if _, err := NormalizeHosts(nil); err == nil {
		t.Fatal("accepted an empty host list")
	}
}
