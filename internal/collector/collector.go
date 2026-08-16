// Package collector orchestrates one bounded collection attempt.
package collector

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"regexp"
	"time"

	"github.com/takanao14/dhcp-lease-observer/internal/identity"
	"github.com/takanao14/dhcp-lease-observer/internal/model"
	"github.com/takanao14/dhcp-lease-observer/internal/output"
	parser "github.com/takanao14/dhcp-lease-observer/internal/parser/ix2106"
	sessioncontract "github.com/takanao14/dhcp-lease-observer/internal/session/ix2106"
	"github.com/takanao14/dhcp-lease-observer/internal/state"
	transport "github.com/takanao14/dhcp-lease-observer/internal/transport/ix2106"
)

type Source interface {
	Collect(context.Context) (transport.CommandBodies, error)
}

type SourceFunc func(context.Context) (transport.CommandBodies, error)

func (function SourceFunc) Collect(ctx context.Context) (transport.CommandBodies, error) {
	return function(ctx)
}

type Runner struct {
	Source         Source
	Identity       *identity.Generator
	StatePath      string
	PrometheusPath string
	SourceInstance string
	Scope          string
	Events         io.Writer
	Now            func() time.Time
}

type Result struct {
	Events       int
	ARPAvailable bool
}

type Failure struct {
	kind      string
	retryable bool
}

var labelPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)

func (failure *Failure) Error() string {
	return "collector attempt failed: " + failure.kind
}

func (failure *Failure) Kind() string {
	return failure.kind
}

func (failure *Failure) Retryable() bool {
	return failure.retryable
}

func (runner Runner) Run(ctx context.Context) (Result, error) {
	if runner.Source == nil || runner.Identity == nil || runner.Events == nil || runner.Now == nil ||
		runner.StatePath == "" || runner.PrometheusPath == "" ||
		!labelPattern.MatchString(runner.SourceInstance) || !labelPattern.MatchString(runner.Scope) {
		return Result{}, newFailure("invalid_runner", false)
	}
	startedAt := runner.Now().UTC()
	previous, previousExists, err := loadPrevious(runner.StatePath)
	if err != nil {
		return Result{}, runner.fail(startedAt, nil, newFailure("state_load_failed", false))
	}
	previousState := previousPointer(previous, previousExists)

	bodies, err := runner.Source.Collect(ctx)
	if err != nil {
		kind, retryable := classifyError(err)
		return Result{}, runner.fail(startedAt, previousState, newFailure(kind, retryable))
	}
	leases, err := parser.ParseLease(bytes.NewReader(bodies.Lease))
	if err != nil {
		return Result{}, runner.fail(startedAt, previousState, newFailure("parse_failed", false))
	}

	arp := model.ARPTable{Neighbors: []model.ARPNeighbor{}}
	arpAvailable := bodies.ARPFailure == nil
	arpFailureClass := ""
	if arpAvailable {
		arp, err = parser.ParseARP(bytes.NewReader(bodies.ARP))
		if err != nil {
			arpAvailable = false
			arpFailureClass = "arp_parse_failed"
		}
	} else {
		kind, _ := classifyError(bodies.ARPFailure)
		arpFailureClass = "arp_" + kind
		if len(arpFailureClass) > 64 {
			arpFailureClass = "arp_acquisition_failed"
		}
	}

	observedAt := runner.Now().UTC()
	source := model.LeaseSnapshot{SchemaVersion: model.SchemaVersion, Leases: leases, ARP: arp}
	current, err := state.Normalize(source, observedAt, runner.Identity)
	if err != nil {
		return Result{}, runner.fail(startedAt, previousState, newFailure("normalize_failed", false))
	}
	current.ARPAvailable = arpAvailable
	current.ARPFailureClass = arpFailureClass
	if err := current.Validate(); err != nil {
		return Result{}, runner.fail(startedAt, previousState, newFailure("normalize_failed", false))
	}
	events, err := state.Diff(previousState, current)
	if err != nil {
		kind := "diff_failed"
		if errors.Is(err, state.ErrIdentityKeyChanged) {
			kind = "identity_key_changed"
		}
		return Result{}, runner.fail(startedAt, previousState, newFailure(kind, false))
	}
	if err := state.Save(runner.StatePath, current); err != nil {
		return Result{}, runner.fail(startedAt, previousState, newFailure("state_save_failed", true))
	}
	duration := nonNegativeDuration(runner.Now().UTC().Sub(startedAt))
	if err := output.SavePrometheus(
		runner.PrometheusPath,
		runner.metrics(true, startedAt, duration, &current),
	); err != nil {
		return Result{}, newFailure("metrics_write_failed", true)
	}
	if err := output.WriteEvents(runner.Events, events); err != nil {
		return Result{}, newFailure("event_output_failed", true)
	}
	if !arpAvailable {
		if err := output.WriteStatusEvent(runner.Events, output.StatusEvent{
			SchemaVersion:  1,
			ObservedAt:     observedAt,
			Event:          "collector_status",
			SourceInstance: runner.SourceInstance,
			Up:             true,
			Degraded:       true,
			FailureClass:   arpFailureClass,
		}); err != nil {
			return Result{}, newFailure("event_output_failed", true)
		}
	}
	return Result{Events: len(events), ARPAvailable: arpAvailable}, nil
}

func (runner Runner) fail(startedAt time.Time, previous *state.Snapshot, failure *Failure) error {
	observedAt := runner.Now().UTC()
	statusErr := output.WriteStatusEvent(runner.Events, output.StatusEvent{
		SchemaVersion:  1,
		ObservedAt:     observedAt,
		Event:          "collector_status",
		SourceInstance: runner.SourceInstance,
		Up:             false,
		FailureClass:   failure.kind,
		Retryable:      failure.retryable,
	})
	metrics := runner.metrics(false, startedAt, nonNegativeDuration(observedAt.Sub(startedAt)), previous)
	if err := output.SavePrometheus(runner.PrometheusPath, metrics); err != nil {
		return newFailure("metrics_write_failed", true)
	}
	if statusErr != nil {
		return newFailure("event_output_failed", true)
	}
	return failure
}

func (runner Runner) metrics(
	up bool,
	lastAttempt time.Time,
	duration time.Duration,
	snapshot *state.Snapshot,
) output.Metrics {
	metrics := output.Metrics{
		SourceInstance:     runner.SourceInstance,
		Up:                 up,
		LastAttempt:        lastAttempt,
		CollectionDuration: duration,
		Leases:             []output.LeaseMetric{},
	}
	if snapshot == nil {
		return metrics
	}
	metrics.LastSuccess = snapshot.ObservedAt
	metrics.Leases = make([]output.LeaseMetric, 0, len(snapshot.Leases))
	for _, lease := range snapshot.Leases {
		metrics.Leases = append(metrics.Leases, output.LeaseMetric{
			DeviceID: lease.DeviceID,
			IP:       lease.IP,
			Scope:    runner.Scope,
			State:    lease.State,
		})
	}
	return metrics
}

func loadPrevious(path string) (state.Snapshot, bool, error) {
	previous, err := state.Load(path)
	if errors.Is(err, os.ErrNotExist) {
		return state.Snapshot{}, false, nil
	}
	if err != nil {
		return state.Snapshot{}, false, err
	}
	return previous, true, nil
}

func previousPointer(snapshot state.Snapshot, exists bool) *state.Snapshot {
	if !exists {
		return nil
	}
	return &snapshot
}

func classifyError(err error) (string, bool) {
	var sessionFailure *sessioncontract.Failure
	if errors.As(err, &sessionFailure) {
		return string(sessionFailure.Kind()), sessionFailure.Retryable()
	}
	var transportFailure *transport.Error
	if errors.As(err, &transportFailure) {
		return string(transportFailure.Kind()), transportFailure.Retryable()
	}
	return "acquisition_failed", true
}

func newFailure(kind string, retryable bool) *Failure {
	return &Failure{kind: kind, retryable: retryable}
}

func nonNegativeDuration(value time.Duration) time.Duration {
	if value < 0 {
		return 0
	}
	return value
}
