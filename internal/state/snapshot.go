// Package state defines and persists privacy-preserving last-good state.
package state

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"time"

	"github.com/takanao14/dhcp-lease-observer/internal/identity"
	"github.com/takanao14/dhcp-lease-observer/internal/model"
)

const SchemaVersion = 1

const maxLeaseSeconds = int64(^uint64(0)>>1) / int64(time.Second)

type Snapshot struct {
	SchemaVersion   int       `json:"schema_version"`
	ObservedAt      time.Time `json:"observed_at"`
	IdentityKeyID   string    `json:"identity_key_id"`
	ARPAvailable    bool      `json:"arp_available"`
	ARPFailureClass string    `json:"arp_failure_class,omitempty"`
	Leases          []Lease   `json:"leases"`
}

type Lease struct {
	DeviceID   string           `json:"device_id"`
	IP         netip.Addr       `json:"ip"`
	Assignment model.Assignment `json:"assignment"`
	State      model.LeaseState `json:"state"`
	Profile    string           `json:"profile"`
	BoundAt    time.Time        `json:"bound_at"`
	ExpiresAt  time.Time        `json:"expires_at"`
}

var opaqueIDPattern = regexp.MustCompile(`^[dk]1_[A-Za-z0-9_-]{22}$`)

func Normalize(
	source model.LeaseSnapshot,
	observedAt time.Time,
	generator *identity.Generator,
) (Snapshot, error) {
	if err := source.Validate(); err != nil {
		return Snapshot{}, fmt.Errorf("source snapshot is invalid: %w", err)
	}
	if observedAt.IsZero() {
		return Snapshot{}, errors.New("observation time is empty")
	}
	keyID, err := generator.KeyID()
	if err != nil {
		return Snapshot{}, err
	}

	observedAt = observedAt.UTC()
	snapshot := Snapshot{
		SchemaVersion: SchemaVersion,
		ObservedAt:    observedAt,
		IdentityKeyID: keyID,
		ARPAvailable:  true,
		Leases:        make([]Lease, 0, len(source.Leases.Records)),
	}
	for _, record := range source.Leases.Records {
		if record.BoundTimeSeconds > record.LeaseTimeSeconds ||
			record.LeaseTimeSeconds > maxLeaseSeconds {
			return Snapshot{}, errors.New("lease timer is out of range")
		}
		deviceID, err := generator.DeviceID(record.HardwareAddress)
		if err != nil {
			return Snapshot{}, err
		}
		boundAt := observedAt.Add(-time.Duration(record.BoundTimeSeconds) * time.Second)
		expiresAt := boundAt.Add(time.Duration(record.LeaseTimeSeconds) * time.Second)
		snapshot.Leases = append(snapshot.Leases, Lease{
			DeviceID:   deviceID,
			IP:         record.IP,
			Assignment: record.Assignment,
			State:      record.State,
			Profile:    record.Profile,
			BoundAt:    boundAt,
			ExpiresAt:  expiresAt,
		})
	}
	sort.Slice(snapshot.Leases, func(left, right int) bool {
		return snapshot.Leases[left].DeviceID < snapshot.Leases[right].DeviceID
	})
	if err := snapshot.Validate(); err != nil {
		return Snapshot{}, err
	}
	return snapshot, nil
}

func (snapshot Snapshot) Validate() error {
	if snapshot.SchemaVersion != SchemaVersion {
		return fmt.Errorf("unsupported state schema version: %d", snapshot.SchemaVersion)
	}
	if snapshot.ObservedAt.IsZero() || !isUTC(snapshot.ObservedAt) {
		return errors.New("observation time must be UTC")
	}
	if !validOpaqueID(snapshot.IdentityKeyID, 'k') {
		return errors.New("identity key ID is invalid")
	}
	if snapshot.ARPAvailable {
		if snapshot.ARPFailureClass != "" {
			return errors.New("available ARP data has a failure class")
		}
	} else if !failureClassPattern.MatchString(snapshot.ARPFailureClass) {
		return errors.New("unavailable ARP data lacks a failure class")
	}
	seenDevices := make(map[string]struct{}, len(snapshot.Leases))
	seenIPs := make(map[netip.Addr]struct{}, len(snapshot.Leases))
	for index, lease := range snapshot.Leases {
		if err := lease.Validate(snapshot.ObservedAt); err != nil {
			return fmt.Errorf("lease %d: %w", index, err)
		}
		if _, exists := seenDevices[lease.DeviceID]; exists {
			return fmt.Errorf("lease %d: duplicate device ID", index)
		}
		if _, exists := seenIPs[lease.IP]; exists {
			return fmt.Errorf("lease %d: duplicate IP address", index)
		}
		seenDevices[lease.DeviceID] = struct{}{}
		seenIPs[lease.IP] = struct{}{}
	}
	return nil
}

func (lease Lease) Validate(observedAt time.Time) error {
	if !validOpaqueID(lease.DeviceID, 'd') {
		return errors.New("device ID is invalid")
	}
	if !lease.IP.IsValid() || !lease.IP.Is4() {
		return errors.New("IP address must be IPv4")
	}
	if lease.Assignment != model.AssignmentDynamic && lease.Assignment != model.AssignmentFixed {
		return errors.New("assignment is invalid")
	}
	if lease.State != model.LeaseStateBound {
		return errors.New("state is invalid")
	}
	if lease.BoundAt.IsZero() || lease.ExpiresAt.IsZero() ||
		!isUTC(lease.BoundAt) || !isUTC(lease.ExpiresAt) {
		return errors.New("lease times must be UTC")
	}
	if lease.BoundAt.After(observedAt) {
		return errors.New("bound time is after observation")
	}
	if lease.ExpiresAt.Before(observedAt) || !lease.ExpiresAt.After(lease.BoundAt) {
		return errors.New("expiry time is unreasonable")
	}
	return nil
}

func validOpaqueID(value string, kind byte) bool {
	if !opaqueIDPattern.MatchString(value) || value[0] != kind {
		return false
	}
	decoded, err := base64.RawURLEncoding.DecodeString(value[3:])
	return err == nil && len(decoded) == 16
}

func isUTC(value time.Time) bool {
	_, offset := value.Zone()
	return offset == 0
}
