// Package ix2106 parses bounded command output from NEC IX2106 devices.
package ix2106

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"regexp"
	"strconv"
	"strings"

	"github.com/takanao14/dhcp-lease-observer/internal/model"
)

const (
	leaseCodes        = "Codes : D - Dynamic assignments, F - Fixed assignments"
	leaseColumns      = "IP Address      MAC Address       BoundTime LeaseTime State     Profile"
	maxTranscriptSize = 1 << 20
	maxLineSize       = 64 << 10
	maxLeaseRecords   = 2048
)

var (
	ErrInvalidLeaseTranscript = errors.New("invalid IX2106 lease transcript")
	ErrPagedTranscript        = errors.New("paged IX2106 transcript")
	ErrConfigOccupied         = errors.New("IX2106 config process is occupied")

	leaseCountPattern = regexp.MustCompile(`^Leased to ([0-9]+) clients$`)
	leaseRowPattern   = regexp.MustCompile(
		`^([DF])\s+([0-9]{1,3}(?:\.[0-9]{1,3}){3})\s+` +
			`([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})\s+` +
			`([0-9]+)\s+([0-9]+)\s+(\S+)\s+(\S+)$`,
	)
	configPromptPattern = regexp.MustCompile(`^[A-Za-z0-9._-]+\(config\)%$`)
)

// ParseLease parses one complete `show ip dhcp lease` command result.
func ParseLease(reader io.Reader) (model.LeaseTable, error) {
	lines, err := readTranscriptLines(reader, invalidLease)
	if err != nil {
		return model.LeaseTable{}, err
	}
	if len(lines) > 0 && configPromptPattern.MatchString(lines[len(lines)-1]) {
		lines = lines[:len(lines)-1]
	}
	if len(lines) < 3 {
		return model.LeaseTable{}, invalidLease("missing headers")
	}

	countMatch := leaseCountPattern.FindStringSubmatch(lines[0])
	if countMatch == nil {
		return model.LeaseTable{}, invalidLease("unsupported summary")
	}
	reportedCount, err := strconv.Atoi(countMatch[1])
	if err != nil || reportedCount > maxLeaseRecords {
		return model.LeaseTable{}, invalidLease("reported count is out of range")
	}
	if lines[1] != leaseCodes || lines[2] != leaseColumns {
		return model.LeaseTable{}, invalidLease("unsupported table header")
	}

	table := model.LeaseTable{
		ReportedCount: reportedCount,
		Records:       make([]model.LeaseRecord, 0, reportedCount),
	}
	for index, line := range lines[3:] {
		if len(table.Records) >= maxLeaseRecords {
			return model.LeaseTable{}, invalidLease("record limit exceeded")
		}
		record, err := parseLeaseRow(line)
		if err != nil {
			return model.LeaseTable{}, invalidLease("row %d is unsupported", index+4)
		}
		table.Records = append(table.Records, record)
	}

	if err := table.Validate(); err != nil {
		return model.LeaseTable{}, fmt.Errorf("%w: validation failed", ErrInvalidLeaseTranscript)
	}
	return table, nil
}

type invalidTranscriptFunc func(string, ...any) error

func readTranscriptLines(reader io.Reader, invalid invalidTranscriptFunc) ([]string, error) {
	limited := io.LimitReader(reader, maxTranscriptSize+1)
	scanner := bufio.NewScanner(limited)
	scanner.Buffer(make([]byte, 4096), maxLineSize)
	lines := make([]string, 0, 64)
	readSize := 0
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		readSize += len(scanner.Bytes()) + 1
		if readSize > maxTranscriptSize {
			return nil, invalid("transcript size limit exceeded")
		}
		if strings.Contains(line, "--More--") {
			return nil, ErrPagedTranscript
		}
		if strings.Contains(strings.ToLower(line), "config process is occupied") {
			return nil, ErrConfigOccupied
		}
		if line != "" {
			lines = append(lines, line)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, invalid("cannot read transcript")
	}
	return lines, nil
}

func parseLeaseRow(line string) (model.LeaseRecord, error) {
	match := leaseRowPattern.FindStringSubmatch(line)
	if match == nil {
		return model.LeaseRecord{}, ErrInvalidLeaseTranscript
	}

	assignment := model.AssignmentDynamic
	if match[1] == "F" {
		assignment = model.AssignmentFixed
	}
	ip, err := netip.ParseAddr(match[2])
	if err != nil || !ip.Is4() {
		return model.LeaseRecord{}, ErrInvalidLeaseTranscript
	}
	hardwareAddress, err := model.ParseMACAddress(match[3])
	if err != nil {
		return model.LeaseRecord{}, ErrInvalidLeaseTranscript
	}
	boundTime, err := strconv.ParseInt(match[4], 10, 64)
	if err != nil {
		return model.LeaseRecord{}, ErrInvalidLeaseTranscript
	}
	leaseTime, err := strconv.ParseInt(match[5], 10, 64)
	if err != nil {
		return model.LeaseRecord{}, ErrInvalidLeaseTranscript
	}
	if match[6] != "Bound" {
		return model.LeaseRecord{}, ErrInvalidLeaseTranscript
	}

	return model.LeaseRecord{
		Assignment:       assignment,
		IP:               ip,
		HardwareAddress:  hardwareAddress,
		BoundTimeSeconds: boundTime,
		LeaseTimeSeconds: leaseTime,
		State:            model.LeaseStateBound,
		Profile:          match[7],
	}, nil
}

func invalidLease(format string, arguments ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidLeaseTranscript, fmt.Sprintf(format, arguments...))
}
