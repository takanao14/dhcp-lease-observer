package collector

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/takanao14/dhcp-lease-observer/internal/identity"
	"github.com/takanao14/dhcp-lease-observer/internal/state"
	transport "github.com/takanao14/dhcp-lease-observer/internal/transport/ix2106"
)

func TestRunPersistsStateMetricsAndEvents(t *testing.T) {
	runner, outputBuffer := newTestRunner(t, fixtureBodies(t))
	result, err := runner.Run(context.Background())
	if err != nil {
		t.Fatalf("run collector: %v", err)
	}
	if result.Events != 24 || !result.ARPAvailable {
		t.Fatalf("result = %#v", result)
	}
	snapshot, err := state.Load(runner.StatePath)
	if err != nil {
		t.Fatalf("load state: %v", err)
	}
	if len(snapshot.Leases) != 24 || !snapshot.ARPAvailable {
		t.Fatalf("snapshot = %#v", snapshot)
	}
	metrics := readFile(t, runner.PrometheusPath)
	if !strings.Contains(metrics, `dhcp_lease_observer_up{source_instance="fixture-router"} 1`) ||
		!strings.Contains(metrics, `dhcp_lease_observer_leases{source_instance="fixture-router",state="bound"} 24`) {
		t.Fatalf("unexpected metrics:\n%s", metrics)
	}
	if strings.Count(outputBuffer.String(), `"type":"lease_bound"`) != 24 {
		t.Fatalf("unexpected events: %s", outputBuffer.String())
	}
}

func TestRunKeepsLastGoodStateOnAcquisitionFailure(t *testing.T) {
	runner, _ := newTestRunner(t, fixtureBodies(t))
	if _, err := runner.Run(context.Background()); err != nil {
		t.Fatalf("seed collector: %v", err)
	}
	before := readFile(t, runner.StatePath)
	events := &bytes.Buffer{}
	runner.Events = events
	runner.Source = SourceFunc(func(context.Context) (transport.CommandBodies, error) {
		return transport.CommandBodies{}, errors.New("secret fixture detail")
	})
	_, err := runner.Run(context.Background())
	var failure *Failure
	if !errors.As(err, &failure) || failure.Kind() != "acquisition_failed" || !failure.Retryable() {
		t.Fatalf("failure = %#v, err = %v", failure, err)
	}
	if after := readFile(t, runner.StatePath); after != before {
		t.Fatal("last-good state changed after acquisition failure")
	}
	metrics := readFile(t, runner.PrometheusPath)
	if !strings.Contains(metrics, `dhcp_lease_observer_up{source_instance="fixture-router"} 0`) ||
		!strings.Contains(metrics, `dhcp_lease_observer_lease_info{`) {
		t.Fatalf("last-good metrics were not retained:\n%s", metrics)
	}
	if strings.Contains(events.String(), "secret") || !strings.Contains(events.String(), `"failure_class":"acquisition_failed"`) {
		t.Fatalf("status event was not sanitized: %s", events.String())
	}
}

func TestRunTreatsARPFailureAsDegradedSuccess(t *testing.T) {
	bodies := fixtureBodies(t)
	bodies.ARP = nil
	bodies.ARPFailure = errors.New("raw router output")
	runner, events := newTestRunner(t, bodies)
	result, err := runner.Run(context.Background())
	if err != nil {
		t.Fatalf("run collector: %v", err)
	}
	if result.ARPAvailable {
		t.Fatal("ARP failure was not reported")
	}
	snapshot, err := state.Load(runner.StatePath)
	if err != nil {
		t.Fatalf("load state: %v", err)
	}
	if snapshot.ARPAvailable || snapshot.ARPFailureClass != "arp_acquisition_failed" {
		t.Fatalf("ARP metadata = %#v", snapshot)
	}
	if strings.Contains(events.String(), "raw router") ||
		!strings.Contains(events.String(), `"up":true,"degraded":true,"failure_class":"arp_acquisition_failed"`) {
		t.Fatalf("degraded event was not sanitized: %s", events.String())
	}
}

func TestRunRejectsCorruptPreviousStateBeforeCollection(t *testing.T) {
	runner, events := newTestRunner(t, fixtureBodies(t))
	if err := os.WriteFile(runner.StatePath, []byte("not json"), 0o600); err != nil {
		t.Fatalf("write corrupt state: %v", err)
	}
	called := false
	runner.Source = SourceFunc(func(context.Context) (transport.CommandBodies, error) {
		called = true
		return transport.CommandBodies{}, nil
	})
	_, err := runner.Run(context.Background())
	var failure *Failure
	if !errors.As(err, &failure) || failure.Kind() != "state_load_failed" || called {
		t.Fatalf("failure = %#v, called = %t", failure, called)
	}
	if readFile(t, runner.StatePath) != "not json" {
		t.Fatal("corrupt state was overwritten")
	}
	if !strings.Contains(events.String(), `"failure_class":"state_load_failed"`) {
		t.Fatalf("missing failure status: %s", events.String())
	}
}

func TestRunDoesNotCreateStateWhenLeaseParsingFails(t *testing.T) {
	bodies := fixtureBodies(t)
	bodies.Lease = []byte("password=do-not-copy")
	runner, events := newTestRunner(t, bodies)
	_, err := runner.Run(context.Background())
	var failure *Failure
	if !errors.As(err, &failure) || failure.Kind() != "parse_failed" {
		t.Fatalf("failure = %#v, err = %v", failure, err)
	}
	if _, statErr := os.Stat(runner.StatePath); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("state exists after parse failure: %v", statErr)
	}
	if strings.Contains(events.String(), "password") {
		t.Fatalf("raw transcript leaked: %s", events.String())
	}
	if strings.Contains(readFile(t, runner.PrometheusPath), "lease_info{") {
		t.Fatal("lease details were emitted without last-good state")
	}
}

func TestRunDoesNotAdvanceStateWhenEventOutputFails(t *testing.T) {
	runner, _ := newTestRunner(t, fixtureBodies(t))
	runner.Events = failingEventWriter{}
	_, err := runner.Run(context.Background())
	var failure *Failure
	if !errors.As(err, &failure) || failure.Kind() != "event_output_failed" {
		t.Fatalf("failure = %#v, err = %v", failure, err)
	}
	if _, statErr := os.Stat(runner.StatePath); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("state advanced after event failure: %v", statErr)
	}
}

func TestRunEmitsEventsAndAdvancesStateBeforeMetricsFailure(t *testing.T) {
	runner, events := newTestRunner(t, fixtureBodies(t))
	runner.PrometheusPath = t.TempDir()
	_, err := runner.Run(context.Background())
	var failure *Failure
	if !errors.As(err, &failure) || failure.Kind() != "metrics_write_failed" {
		t.Fatalf("failure = %#v, err = %v", failure, err)
	}
	if _, loadErr := state.Load(runner.StatePath); loadErr != nil {
		t.Fatalf("state was not advanced after accepted events: %v", loadErr)
	}
	if strings.Count(events.String(), `"type":"lease_bound"`) != 24 {
		t.Fatalf("events were not emitted before metrics failure: %s", events.String())
	}
}

func newTestRunner(t *testing.T, bodies transport.CommandBodies) (Runner, *bytes.Buffer) {
	t.Helper()
	directory := t.TempDir()
	generator, err := identity.NewGenerator(bytes.Repeat([]byte{0x42}, identity.MinimumKeyBytes))
	if err != nil {
		t.Fatalf("new identity generator: %v", err)
	}
	now := time.Date(2026, 8, 16, 1, 2, 3, 0, time.UTC)
	events := &bytes.Buffer{}
	return Runner{
		Source: SourceFunc(func(context.Context) (transport.CommandBodies, error) {
			return bodies, nil
		}),
		Identity:       generator,
		StatePath:      filepath.Join(directory, "last-good.json"),
		PrometheusPath: filepath.Join(directory, "collector.prom"),
		SourceInstance: "fixture-router",
		Scope:          "fixture-lan",
		Events:         events,
		Now: func() time.Time {
			now = now.Add(time.Second)
			return now
		},
	}, events
}

func fixtureBodies(t *testing.T) transport.CommandBodies {
	t.Helper()
	return transport.CommandBodies{
		Lease: readFixture(t, "normal-lease.txt"),
		ARP:   readFixture(t, "normal-arp.txt"),
	}
}

func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "testdata", "ix2106", name))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return data
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(data)
}

type failingEventWriter struct{}

func (failingEventWriter) Write([]byte) (int, error) {
	return 0, errors.New("fixture event destination failure")
}
