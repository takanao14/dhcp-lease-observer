package state

import (
	"errors"
	"net/netip"
	"regexp"
	"sort"
	"time"

	"github.com/takanao14/dhcp-lease-observer/internal/model"
)

type EventType string

const (
	EventLeaseBound   EventType = "lease_bound"
	EventLeaseRenewed EventType = "lease_renewed"
	EventLeaseMoved   EventType = "lease_moved"
	EventLeaseRemoved EventType = "lease_removed"

	renewalTolerance = 5 * time.Second
)

var ErrIdentityKeyChanged = errors.New("identity key changed since last-good state")
var failureClassPattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)

type Event struct {
	SchemaVersion int              `json:"schema_version"`
	Type          EventType        `json:"type"`
	ObservedAt    time.Time        `json:"observed_at"`
	DeviceID      string           `json:"device_id"`
	IP            netip.Addr       `json:"ip"`
	PreviousIP    *netip.Addr      `json:"previous_ip,omitempty"`
	Assignment    model.Assignment `json:"assignment"`
	State         model.LeaseState `json:"state"`
	Profile       string           `json:"profile"`
}

func (event Event) Validate() error {
	if event.SchemaVersion != SchemaVersion {
		return errors.New("event schema version is invalid")
	}
	switch event.Type {
	case EventLeaseBound, EventLeaseRenewed, EventLeaseRemoved:
		if event.PreviousIP != nil {
			return errors.New("previous IP is only valid for a moved lease")
		}
	case EventLeaseMoved:
		if event.PreviousIP == nil || !event.PreviousIP.IsValid() || !event.PreviousIP.Is4() {
			return errors.New("moved lease requires a previous IPv4 address")
		}
	default:
		return errors.New("event type is invalid")
	}
	if event.ObservedAt.IsZero() || !isUTC(event.ObservedAt) {
		return errors.New("event observation time must be UTC")
	}
	if !validOpaqueID(event.DeviceID, 'd') {
		return errors.New("event device ID is invalid")
	}
	if !event.IP.IsValid() || !event.IP.Is4() {
		return errors.New("event IP address must be IPv4")
	}
	if event.Assignment != model.AssignmentDynamic && event.Assignment != model.AssignmentFixed {
		return errors.New("event assignment is invalid")
	}
	if event.State != model.LeaseStateBound {
		return errors.New("event state is invalid")
	}
	return nil
}

func Diff(previous *Snapshot, current Snapshot) ([]Event, error) {
	if err := current.Validate(); err != nil {
		return nil, err
	}
	if previous == nil {
		events := make([]Event, 0, len(current.Leases))
		for _, lease := range current.Leases {
			events = append(events, eventFromLease(EventLeaseBound, current.ObservedAt, lease))
		}
		sortEvents(events)
		return validateEvents(events)
	}
	if err := previous.Validate(); err != nil {
		return nil, err
	}
	if previous.IdentityKeyID != current.IdentityKeyID {
		return nil, ErrIdentityKeyChanged
	}
	if current.ObservedAt.Before(previous.ObservedAt) {
		return nil, errors.New("current observation precedes last-good state")
	}

	previousByDevice := make(map[string]Lease, len(previous.Leases))
	currentByDevice := make(map[string]Lease, len(current.Leases))
	for _, lease := range previous.Leases {
		previousByDevice[lease.DeviceID] = lease
	}
	for _, lease := range current.Leases {
		currentByDevice[lease.DeviceID] = lease
	}

	events := make([]Event, 0)
	for _, lease := range current.Leases {
		old, exists := previousByDevice[lease.DeviceID]
		switch {
		case !exists:
			events = append(events, eventFromLease(EventLeaseBound, current.ObservedAt, lease))
		case old.IP != lease.IP:
			previousIP := old.IP
			event := eventFromLease(EventLeaseMoved, current.ObservedAt, lease)
			event.PreviousIP = &previousIP
			events = append(events, event)
		case lease.BoundAt.After(old.BoundAt.Add(renewalTolerance)):
			events = append(events, eventFromLease(EventLeaseRenewed, current.ObservedAt, lease))
		}
	}
	for _, lease := range previous.Leases {
		if _, exists := currentByDevice[lease.DeviceID]; !exists {
			events = append(events, eventFromLease(EventLeaseRemoved, current.ObservedAt, lease))
		}
	}
	sortEvents(events)
	return validateEvents(events)
}

func eventFromLease(eventType EventType, observedAt time.Time, lease Lease) Event {
	return Event{
		SchemaVersion: SchemaVersion,
		Type:          eventType,
		ObservedAt:    observedAt,
		DeviceID:      lease.DeviceID,
		IP:            lease.IP,
		Assignment:    lease.Assignment,
		State:         lease.State,
		Profile:       lease.Profile,
	}
}

func sortEvents(events []Event) {
	sort.Slice(events, func(left, right int) bool {
		if events[left].DeviceID == events[right].DeviceID {
			return events[left].Type < events[right].Type
		}
		return events[left].DeviceID < events[right].DeviceID
	})
}

func validateEvents(events []Event) ([]Event, error) {
	for _, event := range events {
		if err := event.Validate(); err != nil {
			return nil, err
		}
	}
	return events, nil
}
