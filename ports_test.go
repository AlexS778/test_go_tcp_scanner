package portscan

import (
	"reflect"
	"testing"
)

func TestPortSelections(t *testing.T) {
	tests := []struct {
		name string
		set  PortSet
		want []uint16
	}{
		{"list", Ports(443, 22, 80, 22), []uint16{22, 80, 443}},
		{"range", Range(80, 82), []uint16{80, 81, 82}},
		{"single port range", Range(65535, 65535), []uint16{65535}},
		{"union", Union(Ports(22, 81), Range(80, 82), Range(81, 83)), []uint16{22, 80, 81, 82, 83}},
		{"empty member", Union(Ports(), Ports(443)), []uint16{443}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := test.set.values()
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, test.want) {
				t.Fatalf("ports = %v, want %v", got, test.want)
			}
		})
	}
}

func TestInvalidPortSelections(t *testing.T) {
	for name, set := range map[string]PortSet{
		"zero value": {}, "empty list": Ports(), "empty union": Union(),
		"zero": Ports(0), "negative": Ports(-1), "too large": Ports(65536),
		"reversed": Range(1000, 1), "range starts at zero": Range(0, 100),
		"range ends above limit": Range(1, 65536),
		"invalid union member":   Union(Ports(80), Range(10, 1)),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := set.values(); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestFullPortRange(t *testing.T) {
	ports, err := Range(1, 65535).values()
	if err != nil {
		t.Fatal(err)
	}
	if len(ports) != 65535 || ports[0] != 1 || ports[len(ports)-1] != 65535 {
		t.Fatalf("incorrect full range: length %d", len(ports))
	}
}

func TestPortSelectionOwnsItsInput(t *testing.T) {
	input := []int{22, 80}
	set := Ports(input...)
	combined := Union(set, Ports(443))
	input[0] = 0
	got, err := combined.values()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, []uint16{22, 80, 443}) {
		t.Fatalf("ports changed after input mutation: %v", got)
	}
}
