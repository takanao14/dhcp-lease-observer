package output

import (
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"regexp"
	"time"

	"github.com/takanao14/dhcp-lease-observer/internal/model"
	"github.com/takanao14/dhcp-lease-observer/internal/state"
)

const MaxEvents = 4096

const (
	SeverityInfo  = "info"
	SeverityWarn  = "warn"
	SeverityError = "error"

	StatusDegraded = "degraded"
	StatusFailed   = "failed"
)

type TransitionEvent struct {
	SchemaVersion  int              `json:"schema_version"`
	ObservedAt     time.Time        `json:"observed_at"`
	Event          state.EventType  `json:"event"`
	Severity       string           `json:"severity"`
	Source         string           `json:"source"`
	SourceInstance string           `json:"source_instance"`
	DeviceID       string           `json:"device_id"`
	IP             netip.Addr       `json:"ip"`
	PreviousIP     *netip.Addr      `json:"previous_ip,omitempty"`
	Assignment     model.Assignment `json:"assignment"`
	State          model.LeaseState `json:"state"`
	Profile        string           `json:"profile"`
}

type StatusEvent struct {
	SchemaVersion  int       `json:"schema_version"`
	ObservedAt     time.Time `json:"observed_at"`
	Event          string    `json:"event"`
	Severity       string    `json:"severity"`
	Source         string    `json:"source"`
	SourceInstance string    `json:"source_instance"`
	Status         string    `json:"status"`
	FailureClass   string    `json:"failure_class,omitempty"`
	Retryable      bool      `json:"retryable"`
	Command        string    `json:"command,omitempty"`
}

type StartupFailureEvent struct {
	SchemaVersion  int       `json:"schema_version"`
	ObservedAt     time.Time `json:"observed_at"`
	Event          string    `json:"event"`
	Severity       string    `json:"severity"`
	Source         string    `json:"source,omitempty"`
	SourceInstance string    `json:"source_instance,omitempty"`
	FailureClass   string    `json:"failure_class"`
	Retryable      bool      `json:"retryable"`
}

var failureClassPattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)

func WriteEvents(writer io.Writer, source, sourceInstance string, events []state.Event) error {
	if len(events) > MaxEvents {
		return errors.New("event limit exceeded")
	}
	if !validLabelID(source) || !validLabelID(sourceInstance) {
		return errors.New("event source is invalid")
	}
	for _, event := range events {
		if err := event.Validate(); err != nil {
			return err
		}
	}
	encoder := json.NewEncoder(writer)
	encoder.SetEscapeHTML(false)
	for _, event := range events {
		structured := TransitionEvent{
			SchemaVersion:  event.SchemaVersion,
			ObservedAt:     event.ObservedAt,
			Event:          event.Type,
			Severity:       SeverityInfo,
			Source:         source,
			SourceInstance: sourceInstance,
			DeviceID:       event.DeviceID,
			IP:             event.IP,
			PreviousIP:     event.PreviousIP,
			Assignment:     event.Assignment,
			State:          event.State,
			Profile:        event.Profile,
		}
		if err := encoder.Encode(structured); err != nil {
			return err
		}
	}
	return nil
}

func WriteStatusEvent(writer io.Writer, event StatusEvent) error {
	_, offset := event.ObservedAt.Zone()
	if event.SchemaVersion != 1 || event.Event != "collector_status" ||
		event.ObservedAt.IsZero() || offset != 0 ||
		!validLabelID(event.Source) || !validLabelID(event.SourceInstance) ||
		!failureClassPattern.MatchString(event.FailureClass) {
		return errors.New("invalid collector status event")
	}
	switch event.Status {
	case StatusDegraded:
		if event.Severity != SeverityWarn {
			return errors.New("degraded status event has an invalid severity")
		}
	case StatusFailed:
		if event.Severity != SeverityError {
			return errors.New("failed status event has an invalid severity")
		}
	default:
		return errors.New("collector status event has an invalid status")
	}
	authorizationFailure := event.FailureClass == "authorization_failed" ||
		event.FailureClass == "arp_authorization_failed"
	if authorizationFailure != validFixedCommand(event.Command) {
		return errors.New("collector status event has an invalid command")
	}
	encoder := json.NewEncoder(writer)
	encoder.SetEscapeHTML(false)
	return encoder.Encode(event)
}

func WriteStartupFailureEvent(writer io.Writer, event StartupFailureEvent) error {
	_, offset := event.ObservedAt.Zone()
	if event.SchemaVersion != 1 || event.Event != "collector_start_failed" ||
		event.Severity != SeverityError || event.ObservedAt.IsZero() || offset != 0 ||
		!failureClassPattern.MatchString(event.FailureClass) || event.Retryable {
		return errors.New("invalid collector startup failure event")
	}
	if (event.Source == "") != (event.SourceInstance == "") {
		return errors.New("collector startup source is incomplete")
	}
	if event.Source != "" && (!validLabelID(event.Source) || !validLabelID(event.SourceInstance)) {
		return errors.New("collector startup source is invalid")
	}
	encoder := json.NewEncoder(writer)
	encoder.SetEscapeHTML(false)
	return encoder.Encode(event)
}

func validFixedCommand(command string) bool {
	switch command {
	case "configure", "terminal length 0", "show ip dhcp lease", "show arp entry", "exit":
		return true
	default:
		return false
	}
}
