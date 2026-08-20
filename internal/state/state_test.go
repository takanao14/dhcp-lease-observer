package state

import (
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/takanao14/dhcp-lease-observer/internal/identity"
	"github.com/takanao14/dhcp-lease-observer/internal/model"
)

func TestNormalizeGoldenSnapshotIsPrivateAndDeterministic(t *testing.T) {
	source := readGoldenSnapshot(t)
	generator := testGenerator(t, 'a')
	observedAt := time.Date(2026, 8, 16, 1, 2, 3, 0, time.UTC)
	snapshot, err := Normalize(source, observedAt, generator)
	if err != nil {
		t.Fatalf("normalize snapshot: %v", err)
	}
	if len(snapshot.Leases) != 24 {
		t.Fatalf("lease count = %d, want 24", len(snapshot.Leases))
	}
	for index := 1; index < len(snapshot.Leases); index++ {
		if snapshot.Leases[index-1].DeviceID >= snapshot.Leases[index].DeviceID {
			t.Fatal("normalized leases are not sorted by device ID")
		}
	}

	encoded, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatalf("marshal state: %v", err)
	}
	text := string(encoded)
	if strings.Contains(text, "hardware_address") || strings.Contains(text, "02:00:00") {
		t.Fatal("last-good state retained a plain MAC address")
	}
	firstSource := source.Leases.Records[0]
	firstID, err := generator.DeviceID(firstSource.HardwareAddress)
	if err != nil {
		t.Fatalf("derive first ID: %v", err)
	}
	lease := findLease(t, snapshot, firstID)
	wantBound := observedAt.Add(-time.Duration(firstSource.BoundTimeSeconds) * time.Second)
	wantExpiry := wantBound.Add(time.Duration(firstSource.LeaseTimeSeconds) * time.Second)
	if !lease.BoundAt.Equal(wantBound) || !lease.ExpiresAt.Equal(wantExpiry) {
		t.Fatalf("lease times = %s/%s, want %s/%s", lease.BoundAt, lease.ExpiresAt, wantBound, wantExpiry)
	}
}

func TestDiffClassifiesAllLeaseTransitions(t *testing.T) {
	generator := testGenerator(t, 'a')
	previousTime := time.Date(2026, 8, 16, 1, 0, 0, 0, time.UTC)
	currentTime := previousTime.Add(time.Minute)
	previous := normalizeRecords(t, generator, previousTime, []model.LeaseRecord{
		testRecord(t, "192.0.2.10", "02:00:00:00:00:01", 100),
		testRecord(t, "192.0.2.11", "02:00:00:00:00:02", 100),
		testRecord(t, "192.0.2.12", "02:00:00:00:00:03", 100),
		testRecord(t, "192.0.2.13", "02:00:00:00:00:04", 100),
	})
	current := normalizeRecords(t, generator, currentTime, []model.LeaseRecord{
		testRecord(t, "192.0.2.10", "02:00:00:00:00:01", 160),
		testRecord(t, "192.0.2.21", "02:00:00:00:00:02", 160),
		testRecord(t, "192.0.2.13", "02:00:00:00:00:04", 10),
		testRecord(t, "192.0.2.14", "02:00:00:00:00:05", 10),
	})

	events, err := Diff(&previous, current)
	if err != nil {
		t.Fatalf("diff snapshots: %v", err)
	}
	if len(events) != 4 {
		t.Fatalf("event count = %d, want 4: %#v", len(events), events)
	}
	byType := make(map[EventType]Event, len(events))
	for _, event := range events {
		byType[event.Type] = event
	}
	for _, eventType := range []EventType{EventLeaseBound, EventLeaseRenewed, EventLeaseMoved, EventLeaseRemoved} {
		if _, exists := byType[eventType]; !exists {
			t.Fatalf("missing %s event", eventType)
		}
	}
	moved := byType[EventLeaseMoved]
	if moved.PreviousIP == nil || moved.PreviousIP.String() != "192.0.2.11" || moved.IP.String() != "192.0.2.21" {
		t.Fatalf("moved event IPs = %#v", moved)
	}
}

func TestDiffInitialSnapshotBindsAllLeases(t *testing.T) {
	generator := testGenerator(t, 'a')
	snapshot := normalizeRecords(t, generator, time.Now().UTC(), []model.LeaseRecord{
		testRecord(t, "192.0.2.10", "02:00:00:00:00:01", 10),
		testRecord(t, "192.0.2.11", "02:00:00:00:00:02", 10),
	})
	events, err := Diff(nil, snapshot)
	if err != nil {
		t.Fatalf("diff initial snapshot: %v", err)
	}
	if len(events) != 2 || events[0].Type != EventLeaseBound || events[1].Type != EventLeaseBound {
		t.Fatalf("initial events = %#v", events)
	}
}

func TestDiffRejectsIdentityRotationAndTimeRegression(t *testing.T) {
	observedAt := time.Date(2026, 8, 16, 1, 0, 0, 0, time.UTC)
	first := normalizeRecords(t, testGenerator(t, 'a'), observedAt, []model.LeaseRecord{
		testRecord(t, "192.0.2.10", "02:00:00:00:00:01", 10),
	})
	rotated := normalizeRecords(t, testGenerator(t, 'b'), observedAt.Add(time.Minute), []model.LeaseRecord{
		testRecord(t, "192.0.2.10", "02:00:00:00:00:01", 70),
	})
	if _, err := Diff(&first, rotated); !errors.Is(err, ErrIdentityKeyChanged) {
		t.Fatalf("rotation error = %v, want ErrIdentityKeyChanged", err)
	}

	regressed := first
	regressed.ObservedAt = observedAt.Add(-time.Second)
	if _, err := Diff(&first, regressed); err == nil || !strings.Contains(err.Error(), "precedes") {
		t.Fatalf("time regression error = %v", err)
	}
}

func TestNormalizeRejectsUnrepresentableLeaseDuration(t *testing.T) {
	record := testRecord(t, "192.0.2.10", "02:00:00:00:00:01", 10)
	record.LeaseTimeSeconds = maxLeaseSeconds + 1
	source := model.LeaseSnapshot{
		SchemaVersion: model.SchemaVersion,
		Leases:        model.LeaseTable{ReportedCount: 1, Records: []model.LeaseRecord{record}},
		ARP:           model.ARPTable{Neighbors: []model.ARPNeighbor{}},
	}
	if _, err := Normalize(source, time.Now().UTC(), testGenerator(t, 'a')); err == nil {
		t.Fatal("unrepresentable lease duration was accepted")
	}
}

func TestSaveLoadRoundTripUsesPrivateMode(t *testing.T) {
	snapshot := normalizeRecords(t, testGenerator(t, 'a'), time.Now().UTC(), []model.LeaseRecord{
		testRecord(t, "192.0.2.10", "02:00:00:00:00:01", 10),
	})
	path := filepath.Join(t.TempDir(), "last-good.json")
	if err := Save(path, snapshot); err != nil {
		t.Fatalf("save state: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat state: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("state mode = %o, want 600", info.Mode().Perm())
	}
	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("load state: %v", err)
	}
	if !reflect.DeepEqual(snapshot, loaded) {
		t.Fatal("state changed during save/load round trip")
	}
}

func TestSaveRejectsInvalidStateWithoutReplacingLastGood(t *testing.T) {
	snapshot := normalizeRecords(t, testGenerator(t, 'a'), time.Now().UTC(), []model.LeaseRecord{
		testRecord(t, "192.0.2.10", "02:00:00:00:00:01", 10),
	})
	path := filepath.Join(t.TempDir(), "last-good.json")
	if err := Save(path, snapshot); err != nil {
		t.Fatalf("save initial state: %v", err)
	}
	invalid := snapshot
	invalid.SchemaVersion++
	if err := Save(path, invalid); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("invalid save error = %v, want ErrInvalidState", err)
	}
	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("load preserved state: %v", err)
	}
	if !reflect.DeepEqual(snapshot, loaded) {
		t.Fatal("invalid save replaced last-good state")
	}
}

func TestLoadRejectsUnsafeOrCorruptState(t *testing.T) {
	directory := t.TempDir()
	tests := []struct {
		name    string
		content string
		mode    os.FileMode
	}{
		{name: "corrupt", content: "{", mode: 0o600},
		{name: "trailing JSON", content: "{}{}", mode: 0o600},
		{name: "unknown field", content: `{"unknown":true}`, mode: 0o600},
		{name: "insecure mode", content: `{}`, mode: 0o644},
		{name: "oversized", content: strings.Repeat(" ", MaxStateBytes+1), mode: 0o600},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(directory, strings.ReplaceAll(test.name, " ", "-")+".json")
			if err := os.WriteFile(path, []byte(test.content), test.mode); err != nil {
				t.Fatalf("write fixture: %v", err)
			}
			if _, err := Load(path); !errors.Is(err, ErrInvalidState) {
				t.Fatalf("load error = %v, want ErrInvalidState", err)
			}
		})
	}
}

func TestLoadRejectsStateSymlink(t *testing.T) {
	snapshot := normalizeRecords(t, testGenerator(t, 'a'), time.Now().UTC(), []model.LeaseRecord{
		testRecord(t, "192.0.2.10", "02:00:00:00:00:01", 10),
	})
	directory := t.TempDir()
	target := filepath.Join(directory, "target.json")
	if err := Save(target, snapshot); err != nil {
		t.Fatalf("save target state: %v", err)
	}
	link := filepath.Join(directory, "last-good.json")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("create state symlink: %v", err)
	}
	if _, err := Load(link); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("load error = %v, want ErrInvalidState", err)
	}
}

func readGoldenSnapshot(t *testing.T) model.LeaseSnapshot {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "testdata", "expected", "normal.json"))
	if err != nil {
		t.Fatalf("read golden snapshot: %v", err)
	}
	var snapshot model.LeaseSnapshot
	if err := json.Unmarshal(data, &snapshot); err != nil {
		t.Fatalf("unmarshal golden snapshot: %v", err)
	}
	return snapshot
}

func testGenerator(t *testing.T, fill byte) *identity.Generator {
	t.Helper()
	generator, err := identity.NewGenerator([]byte(strings.Repeat(string(fill), identity.MinimumKeyBytes)))
	if err != nil {
		t.Fatalf("create identity generator: %v", err)
	}
	return generator
}

func normalizeRecords(
	t *testing.T,
	generator *identity.Generator,
	observedAt time.Time,
	records []model.LeaseRecord,
) Snapshot {
	t.Helper()
	source := model.LeaseSnapshot{
		SchemaVersion: model.SchemaVersion,
		Leases: model.LeaseTable{
			ReportedCount: len(records),
			Records:       records,
		},
		ARP: model.ARPTable{Neighbors: []model.ARPNeighbor{}},
	}
	snapshot, err := Normalize(source, observedAt, generator)
	if err != nil {
		t.Fatalf("normalize records: %v", err)
	}
	return snapshot
}

func testRecord(t *testing.T, ipValue, macValue string, boundSeconds int64) model.LeaseRecord {
	t.Helper()
	address, err := model.ParseMACAddress(macValue)
	if err != nil {
		t.Fatalf("parse MAC: %v", err)
	}
	return model.LeaseRecord{
		Assignment:       model.AssignmentDynamic,
		IP:               netip.MustParseAddr(ipValue),
		HardwareAddress:  address,
		BoundTimeSeconds: boundSeconds,
		LeaseTimeSeconds: 3600,
		State:            model.LeaseStateBound,
		Profile:          "fixture-profile",
	}
}

func findLease(t *testing.T, snapshot Snapshot, deviceID string) Lease {
	t.Helper()
	for _, lease := range snapshot.Leases {
		if lease.DeviceID == deviceID {
			return lease
		}
	}
	t.Fatalf("device %q not found", deviceID)
	return Lease{}
}
