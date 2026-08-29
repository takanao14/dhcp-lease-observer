package output

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/takanao14/dhcp-lease-observer/internal/model"
	"github.com/takanao14/dhcp-lease-observer/internal/state"
)

func TestWritePrometheusRendersDeterministicLastGoodMetrics(t *testing.T) {
	metrics := testMetrics()
	var output bytes.Buffer
	if err := WritePrometheus(&output, metrics); err != nil {
		t.Fatalf("write metrics: %v", err)
	}
	text := output.String()
	required := []string{
		"# TYPE dhcp_lease_observer_up gauge\n",
		"dhcp_lease_observer_up{source_instance=\"fixture-router\"} 0\n",
		"dhcp_lease_observer_last_attempt_timestamp_seconds{source_instance=\"fixture-router\"} 1786842123.5\n",
		"dhcp_lease_observer_last_success_timestamp_seconds{source_instance=\"fixture-router\"} 1786842060\n",
		"dhcp_lease_observer_collection_duration_seconds{source_instance=\"fixture-router\"} 1.25\n",
		"dhcp_lease_observer_leases{source_instance=\"fixture-router\",state=\"bound\"} 2\n",
	}
	for _, value := range required {
		if !strings.Contains(text, value) {
			t.Fatalf("metrics missing %q:\n%s", value, text)
		}
	}
	first := strings.Index(text, `device_id="d1_AAAAAAAAAAAAAAAAAAAAAA"`)
	second := strings.Index(text, `device_id="d1_BBBBBBBBBBBBBBBBBBBBBB"`)
	if first < 0 || second < 0 || first >= second {
		t.Fatalf("lease metrics are not deterministically sorted:\n%s", text)
	}
	if strings.Contains(text, "hardware_address") || strings.Contains(text, "fixture-profile") {
		t.Fatal("metrics leaked a MAC or source profile")
	}
}

func TestMetricsValidationRejectsInjectionAndDuplicates(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Metrics)
	}{
		{name: "source injection", mutate: func(metrics *Metrics) { metrics.SourceInstance = "bad\nmetric" }},
		{name: "missing success", mutate: func(metrics *Metrics) { metrics.Up = true; metrics.LastSuccess = time.Time{} }},
		{name: "negative duration", mutate: func(metrics *Metrics) { metrics.CollectionDuration = -time.Second }},
		{name: "scope injection", mutate: func(metrics *Metrics) { metrics.Leases[0].Scope = `bad"scope` }},
		{name: "duplicate device", mutate: func(metrics *Metrics) { metrics.Leases[1].DeviceID = metrics.Leases[0].DeviceID }},
		{name: "duplicate IP", mutate: func(metrics *Metrics) { metrics.Leases[1].IP = metrics.Leases[0].IP }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			metrics := testMetrics()
			test.mutate(&metrics)
			var output bytes.Buffer
			if err := WritePrometheus(&output, metrics); err == nil {
				t.Fatal("invalid metrics were accepted")
			}
			if output.Len() != 0 {
				t.Fatal("invalid metrics produced partial output")
			}
		})
	}
}

func TestLabelEscapingMatchesPrometheusTextFormat(t *testing.T) {
	actual := escapeLabel("line1\nline2\\\"")
	if actual != `line1\nline2\\\"` {
		t.Fatalf("escaped label = %q", actual)
	}
}

func TestSavePrometheusUsesAtomicPublicReadableFile(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "observer.prom")
	if err := SavePrometheus(path, testMetrics()); err != nil {
		t.Fatalf("save metrics: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat metrics: %v", err)
	}
	if info.Mode().Perm() != 0o644 {
		t.Fatalf("metrics mode = %o, want 644", info.Mode().Perm())
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read metrics: %v", err)
	}
	if !bytes.HasSuffix(data, []byte("\n")) {
		t.Fatal("metrics file does not end with a newline")
	}
	matches, err := filepath.Glob(filepath.Join(directory, ".atomic-*"))
	if err != nil {
		t.Fatalf("glob temporary files: %v", err)
	}
	if len(matches) != 0 {
		t.Fatalf("temporary files remain: %v", matches)
	}
}

func TestWriteEventsProducesValidatedJSONLines(t *testing.T) {
	events := []state.Event{
		testEvent(state.EventLeaseBound, "d1_AAAAAAAAAAAAAAAAAAAAAA", "192.0.2.10"),
		testEvent(state.EventLeaseRemoved, "d1_BBBBBBBBBBBBBBBBBBBBBB", "192.0.2.11"),
	}
	events[0].Profile = "<fixture-profile>"
	var output bytes.Buffer
	if err := WriteEvents(&output, "ix2106_cli", "fixture-router", events); err != nil {
		t.Fatalf("write events: %v", err)
	}
	lines := strings.Split(strings.TrimSuffix(output.String(), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("line count = %d, want 2", len(lines))
	}
	for index, line := range lines {
		var decoded TransitionEvent
		if err := json.Unmarshal([]byte(line), &decoded); err != nil {
			t.Fatalf("decode line %d: %v", index, err)
		}
		if decoded.Event != events[index].Type || decoded.DeviceID != events[index].DeviceID ||
			decoded.Severity != SeverityInfo || decoded.Source != "ix2106_cli" ||
			decoded.SourceInstance != "fixture-router" {
			t.Fatalf("decoded event %d = %#v", index, decoded)
		}
	}
	text := output.String()
	if strings.Contains(text, "\\u003c") || strings.Contains(text, "hardware_address") || strings.Contains(text, "02:00:") {
		t.Fatalf("JSON Lines output was escaped unexpectedly or leaked a MAC: %s", text)
	}
}

func TestWriteEventsValidatesAllEventsBeforeWriting(t *testing.T) {
	events := []state.Event{
		testEvent(state.EventLeaseBound, "d1_AAAAAAAAAAAAAAAAAAAAAA", "192.0.2.10"),
		testEvent(state.EventType("invalid"), "d1_BBBBBBBBBBBBBBBBBBBBBB", "192.0.2.11"),
	}
	var output bytes.Buffer
	if err := WriteEvents(&output, "ix2106_cli", "fixture-router", events); err == nil {
		t.Fatal("invalid event was accepted")
	}
	if output.Len() != 0 {
		t.Fatal("invalid event set produced partial output")
	}
}

func TestWriteStatusEventIsSanitized(t *testing.T) {
	event := StatusEvent{
		SchemaVersion:  1,
		ObservedAt:     time.Unix(1786842123, 0).UTC(),
		Event:          "collector_status",
		Severity:       SeverityError,
		Source:         "ix2106_cli",
		SourceInstance: "fixture-router",
		Status:         StatusFailed,
		FailureClass:   "authentication_failed",
		Retryable:      false,
	}
	var output bytes.Buffer
	if err := WriteStatusEvent(&output, event); err != nil {
		t.Fatalf("write status event: %v", err)
	}
	text := output.String()
	if !strings.Contains(text, `"failure_class":"authentication_failed"`) ||
		strings.Contains(text, "password") || strings.Contains(text, "transcript") {
		t.Fatalf("unexpected status event: %s", text)
	}
}

func TestWriteStatusEventRecordsOnlyAllowlistedAuthorizationCommand(t *testing.T) {
	event := StatusEvent{
		SchemaVersion:  1,
		ObservedAt:     time.Unix(1786842123, 0).UTC(),
		Event:          "collector_status",
		Severity:       SeverityError,
		Source:         "ix2106_cli",
		SourceInstance: "fixture-router",
		Status:         StatusFailed,
		FailureClass:   "authorization_failed",
		Command:        "show ip dhcp lease",
	}
	var output bytes.Buffer
	if err := WriteStatusEvent(&output, event); err != nil {
		t.Fatalf("write authorization status: %v", err)
	}
	if !strings.Contains(output.String(), `"command":"show ip dhcp lease"`) {
		t.Fatalf("authorization command was not recorded: %s", output.String())
	}
	event.Command = "show running-config secret"
	if err := WriteStatusEvent(&bytes.Buffer{}, event); err == nil {
		t.Fatal("non-allowlisted command was accepted")
	}
}

func TestWriteStatusEventAcceptsDegradedSuccess(t *testing.T) {
	event := StatusEvent{
		SchemaVersion:  1,
		ObservedAt:     time.Unix(1786842123, 0).UTC(),
		Event:          "collector_status",
		Severity:       SeverityWarn,
		Source:         "ix2106_cli",
		SourceInstance: "fixture-router",
		Status:         StatusDegraded,
		FailureClass:   "arp_parse_failed",
	}
	var output bytes.Buffer
	if err := WriteStatusEvent(&output, event); err != nil {
		t.Fatalf("write degraded status event: %v", err)
	}
	if !strings.Contains(output.String(), `"status":"degraded","failure_class":"arp_parse_failed","retryable":false`) {
		t.Fatalf("unexpected degraded event: %s", output.String())
	}
}

func TestWriteStartupFailureEventAllowsMissingSourceBeforeConfigLoad(t *testing.T) {
	event := StartupFailureEvent{
		SchemaVersion: 1,
		ObservedAt:    time.Unix(1786842123, 0).UTC(),
		Event:         "collector_start_failed",
		Severity:      SeverityError,
		FailureClass:  "configuration_invalid",
	}
	var output bytes.Buffer
	if err := WriteStartupFailureEvent(&output, event); err != nil {
		t.Fatalf("write startup failure: %v", err)
	}
	if !strings.Contains(output.String(), `"event":"collector_start_failed"`) ||
		strings.Contains(output.String(), `"source"`) {
		t.Fatalf("unexpected startup failure: %s", output.String())
	}
}

func TestWritersPropagateDestinationFailure(t *testing.T) {
	writer := failingWriter{}
	if err := WritePrometheus(writer, testMetrics()); err == nil {
		t.Fatal("Prometheus writer failure was ignored")
	}
	if err := WriteEvents(writer, "ix2106_cli", "fixture-router", []state.Event{
		testEvent(state.EventLeaseBound, "d1_AAAAAAAAAAAAAAAAAAAAAA", "192.0.2.10"),
	}); err == nil {
		t.Fatal("JSON Lines writer failure was ignored")
	}
}

func testMetrics() Metrics {
	return Metrics{
		SourceInstance:     "fixture-router",
		Up:                 false,
		LastAttempt:        time.Unix(1786842123, 500_000_000).UTC(),
		LastSuccess:        time.Unix(1786842060, 0).UTC(),
		CollectionDuration: 1250 * time.Millisecond,
		Leases: []LeaseMetric{
			{DeviceID: "d1_BBBBBBBBBBBBBBBBBBBBBB", IP: netip.MustParseAddr("192.0.2.11"), Scope: "fixture-lan", State: model.LeaseStateBound},
			{DeviceID: "d1_AAAAAAAAAAAAAAAAAAAAAA", IP: netip.MustParseAddr("192.0.2.10"), Scope: "fixture-lan", State: model.LeaseStateBound},
		},
	}
}

func testEvent(eventType state.EventType, deviceID, ip string) state.Event {
	return state.Event{
		SchemaVersion: state.SchemaVersion,
		Type:          eventType,
		ObservedAt:    time.Unix(1786842123, 0).UTC(),
		DeviceID:      deviceID,
		IP:            netip.MustParseAddr(ip),
		Assignment:    model.AssignmentDynamic,
		State:         model.LeaseStateBound,
		Profile:       "fixture-profile",
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) {
	return 0, errors.New("fixture destination failure")
}
