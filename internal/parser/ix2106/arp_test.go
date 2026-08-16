package ix2106

import (
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/takanao14/dhcp-lease-observer/internal/model"
)

func TestParseARPNormalFixtureMatchesGolden(t *testing.T) {
	actual := parseARPFixture(t, "normal-arp.txt")

	data, err := os.ReadFile(testdataRoot() + "/expected/normal.json")
	if err != nil {
		t.Fatalf("read golden file: %v", err)
	}
	var snapshot model.LeaseSnapshot
	if err := json.Unmarshal(data, &snapshot); err != nil {
		t.Fatalf("unmarshal golden snapshot: %v", err)
	}
	if !reflect.DeepEqual(actual, snapshot.ARP) {
		t.Fatal("Go parser result differs from Stage 1 golden JSON")
	}
	if actual.ReportedDynamic != 40 {
		t.Fatalf("reported dynamic = %d, want 40", actual.ReportedDynamic)
	}
}

func TestParseARPEmptyFixture(t *testing.T) {
	table := parseARPFixture(t, "empty-arp.txt")
	if table.ReportedDynamic != 0 || len(table.Neighbors) != 0 {
		t.Fatalf("empty fixture parsed as %#v", table)
	}
}

func TestParseARPRejectsFailureFixtures(t *testing.T) {
	tests := []struct {
		name    string
		fixture string
		want    error
	}{
		{name: "truncated", fixture: "truncated-arp.txt", want: ErrInvalidARPTranscript},
		{name: "paged", fixture: "paged-lease.txt", want: ErrPagedTranscript},
		{name: "config occupied", fixture: "config-occupied.txt", want: ErrConfigOccupied},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			file, err := os.Open(fixturePath(test.fixture))
			if err != nil {
				t.Fatalf("open fixture: %v", err)
			}
			defer file.Close()

			_, err = ParseARP(file)
			if !errors.Is(err, test.want) {
				t.Fatalf("error = %v, want errors.Is(_, %v)", err, test.want)
			}
		})
	}
}

func TestParseARPAcceptsBodyWithoutPrompt(t *testing.T) {
	data, err := os.ReadFile(fixturePath("empty-arp.txt"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	body := strings.ReplaceAll(string(data), "ix-fixture(config)%", "")
	table, err := ParseARP(strings.NewReader(body))
	if err != nil {
		t.Fatalf("parse body without prompt: %v", err)
	}
	if table.ReportedDynamic != 0 {
		t.Fatalf("reported dynamic = %d, want 0", table.ReportedDynamic)
	}
}

func TestParseARPReadsEnabledRefreshState(t *testing.T) {
	transcript := strings.Join([]string{
		"ARP Neighbor Cache - 0 dynamic, 2048 free, 0 garbage, 0 static",
		"ARP neighbor cache auto refresh is enabled",
		arpColumns,
		"ix-fixture(config)%",
	}, "\n")
	table, err := ParseARP(strings.NewReader(transcript))
	if err != nil {
		t.Fatalf("parse enabled refresh state: %v", err)
	}
	if !table.AutoRefresh {
		t.Fatal("auto refresh = false, want true")
	}
}

func TestParseARPErrorDoesNotContainRejectedRow(t *testing.T) {
	transcript := strings.Join([]string{
		"ARP Neighbor Cache - 1 dynamic, 2047 free, 0 garbage, 0 static",
		"ARP neighbor cache auto refresh is disabled",
		arpColumns,
		"192.0.2.99 02:00:00:00:00:99 0:04:00 1h2m3s",
		"ix-fixture(config)%",
	}, "\n")
	_, err := ParseARP(strings.NewReader(transcript))
	if err == nil {
		t.Fatal("invalid row unexpectedly parsed")
	}
	if strings.Contains(err.Error(), "192.0.2.99") || strings.Contains(err.Error(), "02:00") {
		t.Fatalf("error leaked rejected row: %v", err)
	}
}

func parseARPFixture(t *testing.T, name string) model.ARPTable {
	t.Helper()
	file, err := os.Open(fixturePath(name))
	if err != nil {
		t.Fatalf("open fixture: %v", err)
	}
	defer file.Close()
	table, err := ParseARP(file)
	if err != nil {
		t.Fatalf("parse fixture: %v", err)
	}
	return table
}
