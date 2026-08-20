package state

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/takanao14/dhcp-lease-observer/internal/atomicfile"
	"github.com/takanao14/dhcp-lease-observer/internal/safefile"
)

const MaxStateBytes = 4 << 20

var ErrInvalidState = errors.New("invalid last-good state")

func Load(path string) (Snapshot, error) {
	file, err := safefile.OpenRegular(path, 0o077, MaxStateBytes)
	if err != nil {
		if errors.Is(err, safefile.ErrUnsafeFile) {
			return Snapshot{}, ErrInvalidState
		}
		return Snapshot{}, err
	}
	defer file.Close()

	limited := io.LimitReader(file, MaxStateBytes+1)
	decoder := json.NewDecoder(limited)
	decoder.DisallowUnknownFields()
	var snapshot Snapshot
	if err := decoder.Decode(&snapshot); err != nil {
		return Snapshot{}, ErrInvalidState
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return Snapshot{}, ErrInvalidState
	}
	if err := snapshot.Validate(); err != nil {
		return Snapshot{}, ErrInvalidState
	}
	return snapshot, nil
}

func Save(path string, snapshot Snapshot) error {
	if err := snapshot.Validate(); err != nil {
		return fmt.Errorf("%w: validation failed", ErrInvalidState)
	}
	return atomicfile.Write(path, 0o600, MaxStateBytes, func(writer io.Writer) error {
		encoder := json.NewEncoder(writer)
		encoder.SetIndent("", "  ")
		return encoder.Encode(snapshot)
	})
}

func ensureJSONEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("state contains trailing JSON")
	}
	return nil
}
