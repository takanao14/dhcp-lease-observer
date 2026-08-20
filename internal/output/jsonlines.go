package output

import (
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"time"

	"github.com/takanao14/dhcp-lease-observer/internal/state"
)

const MaxEvents = 4096

type StatusEvent struct {
	SchemaVersion  int       `json:"schema_version"`
	ObservedAt     time.Time `json:"observed_at"`
	Event          string    `json:"event"`
	SourceInstance string    `json:"source_instance"`
	Up             bool      `json:"up"`
	Degraded       bool      `json:"degraded,omitempty"`
	FailureClass   string    `json:"failure_class,omitempty"`
	Retryable      bool      `json:"retryable,omitempty"`
	Command        string    `json:"command,omitempty"`
}

var failureClassPattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)

func WriteEvents(writer io.Writer, events []state.Event) error {
	if len(events) > MaxEvents {
		return errors.New("event limit exceeded")
	}
	for _, event := range events {
		if err := event.Validate(); err != nil {
			return err
		}
	}
	encoder := json.NewEncoder(writer)
	encoder.SetEscapeHTML(false)
	for _, event := range events {
		if err := encoder.Encode(event); err != nil {
			return err
		}
	}
	return nil
}

func WriteStatusEvent(writer io.Writer, event StatusEvent) error {
	_, offset := event.ObservedAt.Zone()
	if event.SchemaVersion != 1 || event.Event != "collector_status" ||
		event.ObservedAt.IsZero() || offset != 0 || !validLabelID(event.SourceInstance) {
		return errors.New("invalid collector status event")
	}
	if event.Up {
		if event.Degraded {
			if !failureClassPattern.MatchString(event.FailureClass) {
				return errors.New("degraded status event lacks a valid failure class")
			}
		} else if event.FailureClass != "" || event.Retryable {
			return errors.New("successful status event contains a failure")
		}
	} else if event.Degraded || !failureClassPattern.MatchString(event.FailureClass) {
		return errors.New("failed status event lacks a valid failure class")
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

func validFixedCommand(command string) bool {
	switch command {
	case "configure", "terminal length 0", "show ip dhcp lease", "show arp entry", "exit":
		return true
	default:
		return false
	}
}
