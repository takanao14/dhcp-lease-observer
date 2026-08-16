package state

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/takanao14/dhcp-lease-observer/internal/identity"
	"github.com/takanao14/dhcp-lease-observer/internal/model"
)

func FuzzDiff(f *testing.F) {
	generator, err := identity.NewGenerator(bytes.Repeat([]byte{'f'}, identity.MinimumKeyBytes))
	if err != nil {
		f.Fatalf("create identity generator: %v", err)
	}
	observedAt := time.Date(2026, 8, 16, 1, 2, 3, 0, time.UTC)
	seedData, err := os.ReadFile(filepath.Join("..", "..", "testdata", "expected", "normal.json"))
	if err != nil {
		f.Fatalf("read seed snapshot: %v", err)
	}
	var seed model.LeaseSnapshot
	if err := json.Unmarshal(seedData, &seed); err != nil {
		f.Fatalf("decode seed snapshot: %v", err)
	}
	previous, err := Normalize(seed, observedAt, generator)
	if err != nil {
		f.Fatalf("normalize previous seed: %v", err)
	}
	current, err := Normalize(seed, observedAt.Add(time.Minute), generator)
	if err != nil {
		f.Fatalf("normalize current seed: %v", err)
	}
	previousJSON, err := json.Marshal(previous)
	if err != nil {
		f.Fatalf("marshal previous seed: %v", err)
	}
	currentJSON, err := json.Marshal(current)
	if err != nil {
		f.Fatalf("marshal current seed: %v", err)
	}
	f.Add(previousJSON, currentJSON)
	f.Add([]byte("null"), []byte("{}"))

	f.Fuzz(func(t *testing.T, previousData, currentData []byte) {
		if len(previousData) > MaxStateBytes || len(currentData) > MaxStateBytes {
			return
		}
		var fuzzPrevious Snapshot
		var fuzzCurrent Snapshot
		if json.Unmarshal(previousData, &fuzzPrevious) != nil ||
			json.Unmarshal(currentData, &fuzzCurrent) != nil {
			return
		}
		events, diffErr := Diff(&fuzzPrevious, fuzzCurrent)
		if diffErr != nil {
			return
		}
		for index, event := range events {
			if validateErr := event.Validate(); validateErr != nil {
				t.Fatalf("event %d is invalid: %v", index, validateErr)
			}
		}
	})
}
