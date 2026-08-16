package ix2106

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/takanao14/dhcp-lease-observer/internal/model"
)

func TestParseLeaseGoldenFixtures(t *testing.T) {
	tests := []struct {
		name      string
		fixture   string
		golden    string
		fromRoot  bool
		wantCount int
	}{
		{
			name:      "normal",
			fixture:   "normal-lease.txt",
			golden:    "normal.json",
			fromRoot:  true,
			wantCount: 24,
		},
		{
			name:      "multiple profiles",
			fixture:   "multi-profile-lease.txt",
			golden:    "multi-profile-lease.json",
			wantCount: 2,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual := parseLeaseFixture(t, test.fixture)
			expected := readGoldenLeaseTable(t, test.golden, test.fromRoot)
			if !reflect.DeepEqual(actual, expected) {
				t.Fatal("Go parser result differs from Stage 1 golden JSON")
			}
			if actual.ReportedCount != test.wantCount {
				t.Fatalf("reported count = %d, want %d", actual.ReportedCount, test.wantCount)
			}
		})
	}
}

func TestParseLeaseEmptyFixture(t *testing.T) {
	table := parseLeaseFixture(t, "empty-lease.txt")
	if table.ReportedCount != 0 || len(table.Records) != 0 {
		t.Fatalf("empty fixture parsed as %#v", table)
	}
}

func TestParseLeaseRejectsFailureFixtures(t *testing.T) {
	tests := []struct {
		name    string
		fixture string
		want    error
	}{
		{name: "truncated", fixture: "truncated-lease.txt", want: ErrInvalidLeaseTranscript},
		{name: "paged", fixture: "paged-lease.txt", want: ErrPagedTranscript},
		{name: "unknown state", fixture: "unknown-state-lease.txt", want: ErrInvalidLeaseTranscript},
		{name: "config occupied", fixture: "config-occupied.txt", want: ErrConfigOccupied},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			file, err := os.Open(fixturePath(test.fixture))
			if err != nil {
				t.Fatalf("open fixture: %v", err)
			}
			defer file.Close()

			_, err = ParseLease(file)
			if !errors.Is(err, test.want) {
				t.Fatalf("error = %v, want errors.Is(_, %v)", err, test.want)
			}
		})
	}
}

func TestParseLeaseAcceptsBodyWithoutPrompt(t *testing.T) {
	data, err := os.ReadFile(fixturePath("empty-lease.txt"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	body := strings.ReplaceAll(string(data), "ix-fixture(config)%", "")
	table, err := ParseLease(strings.NewReader(body))
	if err != nil {
		t.Fatalf("parse body without prompt: %v", err)
	}
	if table.ReportedCount != 0 {
		t.Fatalf("reported count = %d, want 0", table.ReportedCount)
	}
}

func TestParseLeaseErrorDoesNotContainRejectedRow(t *testing.T) {
	transcript := strings.Join([]string{
		"Leased to 1 clients",
		leaseCodes,
		leaseColumns,
		"D 192.0.2.99 02:00:00:00:00:99 1 60 FixtureUnknown fixture-profile",
		"ix-fixture(config)%",
	}, "\n")
	_, err := ParseLease(strings.NewReader(transcript))
	if err == nil {
		t.Fatal("invalid row unexpectedly parsed")
	}
	if strings.Contains(err.Error(), "192.0.2.99") || strings.Contains(err.Error(), "02:00") {
		t.Fatalf("error leaked rejected row: %v", err)
	}
}

func parseLeaseFixture(t *testing.T, name string) model.LeaseTable {
	t.Helper()
	file, err := os.Open(fixturePath(name))
	if err != nil {
		t.Fatalf("open fixture: %v", err)
	}
	defer file.Close()
	table, err := ParseLease(file)
	if err != nil {
		t.Fatalf("parse fixture: %v", err)
	}
	return table
}

func readGoldenLeaseTable(t *testing.T, name string, fromRoot bool) model.LeaseTable {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(testdataRoot(), "expected", name))
	if err != nil {
		t.Fatalf("read golden file: %v", err)
	}
	if fromRoot {
		var snapshot model.LeaseSnapshot
		if err := json.Unmarshal(data, &snapshot); err != nil {
			t.Fatalf("unmarshal golden snapshot: %v", err)
		}
		return snapshot.Leases
	}
	var table model.LeaseTable
	if err := json.Unmarshal(data, &table); err != nil {
		t.Fatalf("unmarshal golden lease table: %v", err)
	}
	return table
}

func fixturePath(name string) string {
	return filepath.Join(testdataRoot(), "ix2106", name)
}

func testdataRoot() string {
	return filepath.Join("..", "..", "..", "testdata")
}
