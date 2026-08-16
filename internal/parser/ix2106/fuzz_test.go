package ix2106

import (
	"bytes"
	"os"
	"testing"
)

func FuzzParseLease(f *testing.F) {
	addFixtureSeed(f, "normal-lease.txt")
	addFixtureSeed(f, "empty-lease.txt")
	addFixtureSeed(f, "truncated-lease.txt")
	f.Fuzz(func(t *testing.T, data []byte) {
		table, err := ParseLease(bytes.NewReader(data))
		if err == nil {
			if validateErr := table.Validate(); validateErr != nil {
				t.Fatalf("successful parse returned invalid table: %v", validateErr)
			}
		}
	})
}

func FuzzParseARP(f *testing.F) {
	addFixtureSeed(f, "normal-arp.txt")
	addFixtureSeed(f, "empty-arp.txt")
	addFixtureSeed(f, "truncated-arp.txt")
	f.Fuzz(func(t *testing.T, data []byte) {
		table, err := ParseARP(bytes.NewReader(data))
		if err == nil {
			if validateErr := table.Validate(); validateErr != nil {
				t.Fatalf("successful parse returned invalid table: %v", validateErr)
			}
		}
	})
}

func addFixtureSeed(f *testing.F, name string) {
	f.Helper()
	data, err := os.ReadFile(fixturePath(name))
	if err != nil {
		f.Fatalf("read fuzz seed %s: %v", name, err)
	}
	f.Add(data)
}
