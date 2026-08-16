// Package output renders collector metrics and events without retaining them.
package output

import (
	"errors"
	"fmt"
	"io"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/takanao14/dhcp-lease-observer/internal/atomicfile"
	"github.com/takanao14/dhcp-lease-observer/internal/model"
)

const (
	MaxPrometheusBytes = 4 << 20
	MaxLeaseMetrics    = 2048
	MaxLabelIDBytes    = 128
)

type Metrics struct {
	SourceInstance     string
	Up                 bool
	LastAttempt        time.Time
	LastSuccess        time.Time
	CollectionDuration time.Duration
	Leases             []LeaseMetric
}

type LeaseMetric struct {
	DeviceID string
	IP       netip.Addr
	Scope    string
	State    model.LeaseState
}

var (
	labelIDPattern  = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)
	deviceIDPattern = regexp.MustCompile(`^d1_[A-Za-z0-9_-]{22}$`)
)

func (metrics Metrics) Validate() error {
	if !validLabelID(metrics.SourceInstance) {
		return errors.New("source instance is invalid")
	}
	if metrics.LastAttempt.IsZero() || metrics.CollectionDuration < 0 {
		return errors.New("health timing is invalid")
	}
	if metrics.Up && metrics.LastSuccess.IsZero() {
		return errors.New("successful collection requires last success time")
	}
	if len(metrics.Leases) > MaxLeaseMetrics {
		return errors.New("lease metric limit exceeded")
	}
	seenDevices := make(map[string]struct{}, len(metrics.Leases))
	seenIPs := make(map[netip.Addr]struct{}, len(metrics.Leases))
	for index, lease := range metrics.Leases {
		if !deviceIDPattern.MatchString(lease.DeviceID) ||
			!lease.IP.IsValid() || !lease.IP.Is4() ||
			!validLabelID(lease.Scope) || lease.State != model.LeaseStateBound {
			return fmt.Errorf("lease metric %d is invalid", index)
		}
		if _, exists := seenDevices[lease.DeviceID]; exists {
			return fmt.Errorf("lease metric %d duplicates a device", index)
		}
		if _, exists := seenIPs[lease.IP]; exists {
			return fmt.Errorf("lease metric %d duplicates an IP address", index)
		}
		seenDevices[lease.DeviceID] = struct{}{}
		seenIPs[lease.IP] = struct{}{}
	}
	return nil
}

func WritePrometheus(writer io.Writer, metrics Metrics) error {
	if err := metrics.Validate(); err != nil {
		return err
	}
	leases := append([]LeaseMetric(nil), metrics.Leases...)
	sort.Slice(leases, func(left, right int) bool {
		return leases[left].DeviceID < leases[right].DeviceID
	})

	instance := escapeLabel(metrics.SourceInstance)
	up := 0
	if metrics.Up {
		up = 1
	}
	lastSuccess := "0"
	if !metrics.LastSuccess.IsZero() {
		lastSuccess = formatSeconds(metrics.LastSuccess)
	}

	lines := []string{
		"# HELP dhcp_lease_observer_up Whether the latest collection succeeded.",
		"# TYPE dhcp_lease_observer_up gauge",
		fmt.Sprintf("dhcp_lease_observer_up{source_instance=\"%s\"} %d", instance, up),
		"# HELP dhcp_lease_observer_last_attempt_timestamp_seconds Unix time of the latest collection attempt.",
		"# TYPE dhcp_lease_observer_last_attempt_timestamp_seconds gauge",
		fmt.Sprintf("dhcp_lease_observer_last_attempt_timestamp_seconds{source_instance=\"%s\"} %s", instance, formatSeconds(metrics.LastAttempt)),
		"# HELP dhcp_lease_observer_last_success_timestamp_seconds Unix time of the latest successful collection.",
		"# TYPE dhcp_lease_observer_last_success_timestamp_seconds gauge",
		fmt.Sprintf("dhcp_lease_observer_last_success_timestamp_seconds{source_instance=\"%s\"} %s", instance, lastSuccess),
		"# HELP dhcp_lease_observer_collection_duration_seconds Duration of the latest collection attempt.",
		"# TYPE dhcp_lease_observer_collection_duration_seconds gauge",
		fmt.Sprintf("dhcp_lease_observer_collection_duration_seconds{source_instance=\"%s\"} %s", instance, formatDuration(metrics.CollectionDuration)),
		"# HELP dhcp_lease_observer_leases Number of leases in the last-good snapshot.",
		"# TYPE dhcp_lease_observer_leases gauge",
		fmt.Sprintf("dhcp_lease_observer_leases{source_instance=\"%s\",state=\"bound\"} %d", instance, len(leases)),
		"# HELP dhcp_lease_observer_lease_info Current last-good lease mapping.",
		"# TYPE dhcp_lease_observer_lease_info gauge",
	}
	for _, lease := range leases {
		lines = append(lines, fmt.Sprintf(
			"dhcp_lease_observer_lease_info{source_instance=\"%s\",device_id=\"%s\",ip=\"%s\",scope=\"%s\",state=\"bound\"} 1",
			instance,
			escapeLabel(lease.DeviceID),
			escapeLabel(lease.IP.String()),
			escapeLabel(lease.Scope),
		))
	}
	_, err := io.WriteString(writer, strings.Join(lines, "\n")+"\n")
	return err
}

func SavePrometheus(path string, metrics Metrics) error {
	return atomicfile.Write(path, 0o644, MaxPrometheusBytes, func(writer io.Writer) error {
		return WritePrometheus(writer, metrics)
	})
}

func validLabelID(value string) bool {
	return value != "" && len(value) <= MaxLabelIDBytes &&
		utf8.ValidString(value) && labelIDPattern.MatchString(value)
}

func escapeLabel(value string) string {
	return strings.NewReplacer("\\", "\\\\", "\n", "\\n", "\"", "\\\"").Replace(value)
}

func formatSeconds(value time.Time) string {
	seconds := float64(value.Unix()) + float64(value.Nanosecond())/float64(time.Second)
	return strconv.FormatFloat(seconds, 'f', -1, 64)
}

func formatDuration(value time.Duration) string {
	return strconv.FormatFloat(value.Seconds(), 'f', -1, 64)
}
