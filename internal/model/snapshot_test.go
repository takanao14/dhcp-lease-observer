package model

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestNormalGoldenSnapshotRoundTrip(t *testing.T) {
	data := readGolden(t, "normal.json")
	var snapshot LeaseSnapshot
	if err := json.Unmarshal(data, &snapshot); err != nil {
		t.Fatalf("unmarshal golden snapshot: %v", err)
	}
	if err := snapshot.Validate(); err != nil {
		t.Fatalf("validate golden snapshot: %v", err)
	}
	if snapshot.Leases.ReportedCount != 24 {
		t.Fatalf("lease count = %d, want 24", snapshot.Leases.ReportedCount)
	}
	if snapshot.ARP.ReportedDynamic != 40 {
		t.Fatalf("ARP dynamic count = %d, want 40", snapshot.ARP.ReportedDynamic)
	}

	encoded, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatalf("marshal snapshot: %v", err)
	}
	var roundTrip LeaseSnapshot
	if err := json.Unmarshal(encoded, &roundTrip); err != nil {
		t.Fatalf("unmarshal round trip: %v", err)
	}
	if !reflect.DeepEqual(snapshot, roundTrip) {
		t.Fatal("snapshot changed during JSON round trip")
	}
}

func TestMultipleProfileGoldenLeaseTable(t *testing.T) {
	data := readGolden(t, "multi-profile-lease.json")
	var table LeaseTable
	if err := json.Unmarshal(data, &table); err != nil {
		t.Fatalf("unmarshal golden lease table: %v", err)
	}
	if err := table.Validate(); err != nil {
		t.Fatalf("validate golden lease table: %v", err)
	}
	if table.Records[0].Profile == table.Records[1].Profile {
		t.Fatal("profile names were not preserved")
	}
	if got := table.Records[0].HardwareAddress.String(); got != "02:00:00:00:00:30" {
		t.Fatalf("canonical MAC = %q", got)
	}
}

func TestEmptyTablesAreValid(t *testing.T) {
	snapshot := LeaseSnapshot{
		SchemaVersion: SchemaVersion,
		Leases:        LeaseTable{Records: []LeaseRecord{}},
		ARP:           ARPTable{Neighbors: []ARPNeighbor{}},
	}
	if err := snapshot.Validate(); err != nil {
		t.Fatalf("validate empty snapshot: %v", err)
	}
}

func TestLeaseValidationRejectsConflicts(t *testing.T) {
	data := readGolden(t, "normal.json")
	var snapshot LeaseSnapshot
	if err := json.Unmarshal(data, &snapshot); err != nil {
		t.Fatalf("unmarshal golden snapshot: %v", err)
	}

	tests := map[string]func(*LeaseSnapshot){
		"reported count": func(value *LeaseSnapshot) {
			value.Leases.ReportedCount++
		},
		"duplicate IP": func(value *LeaseSnapshot) {
			value.Leases.Records[1].IP = value.Leases.Records[0].IP
		},
		"duplicate MAC": func(value *LeaseSnapshot) {
			value.Leases.Records[1].HardwareAddress = value.Leases.Records[0].HardwareAddress
		},
		"unknown state": func(value *LeaseSnapshot) {
			value.Leases.Records[0].State = LeaseState("fixture-unknown")
		},
	}

	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			candidate := cloneSnapshot(t, snapshot)
			mutate(&candidate)
			if err := candidate.Validate(); err == nil {
				t.Fatal("validation unexpectedly succeeded")
			}
		})
	}
}

func TestMACAddressRejectsNonCanonicalWidth(t *testing.T) {
	for _, value := range []string{"", "02:00:00:00:00", "02:00:00:00:00:01:02"} {
		if _, err := ParseMACAddress(value); err == nil {
			t.Fatalf("ParseMACAddress(%q) unexpectedly succeeded", value)
		}
	}
}

func readGolden(t *testing.T, name string) []byte {
	t.Helper()
	path := filepath.Join("..", "..", "testdata", "expected", name)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return data
}

func cloneSnapshot(t *testing.T, source LeaseSnapshot) LeaseSnapshot {
	t.Helper()
	data, err := json.Marshal(source)
	if err != nil {
		t.Fatalf("marshal clone: %v", err)
	}
	var clone LeaseSnapshot
	if err := json.Unmarshal(data, &clone); err != nil {
		t.Fatalf("unmarshal clone: %v", err)
	}
	return clone
}
