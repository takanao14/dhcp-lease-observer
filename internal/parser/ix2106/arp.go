package ix2106

import (
	"errors"
	"fmt"
	"io"
	"net/netip"
	"regexp"
	"strconv"

	"github.com/takanao14/dhcp-lease-observer/internal/model"
)

const (
	arpColumns    = "Protocol Address  Hardware Address   TTL       Uptime       Interface"
	maxARPRecords = 2048
)

var (
	ErrInvalidARPTranscript = errors.New("invalid IX2106 ARP transcript")

	arpSummaryPattern = regexp.MustCompile(
		`^ARP Neighbor Cache - ([0-9]+) dynamic, ([0-9]+) free, ` +
			`([0-9]+) garbage, ([0-9]+) static$`,
	)
	arpRefreshPattern = regexp.MustCompile(
		`^ARP neighbor cache auto refresh is (enabled|disabled)$`,
	)
	arpRowPattern = regexp.MustCompile(
		`^([0-9]{1,3}(?:\.[0-9]{1,3}){3})\s+` +
			`([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})\s+` +
			`(\S+)\s+(\S+)\s+(\S+)$`,
	)
)

// ParseARP parses one complete `show arp entry` command result.
func ParseARP(reader io.Reader) (model.ARPTable, error) {
	lines, err := readTranscriptLines(reader, invalidARP)
	if err != nil {
		return model.ARPTable{}, err
	}
	if len(lines) > 0 && configPromptPattern.MatchString(lines[len(lines)-1]) {
		lines = lines[:len(lines)-1]
	}
	if len(lines) < 3 {
		return model.ARPTable{}, invalidARP("missing headers")
	}

	summary := arpSummaryPattern.FindStringSubmatch(lines[0])
	if summary == nil {
		return model.ARPTable{}, invalidARP("unsupported summary")
	}
	counts, err := parseARPCounts(summary[1:])
	if err != nil || counts[0] > maxARPRecords {
		return model.ARPTable{}, invalidARP("summary count is out of range")
	}
	refresh := arpRefreshPattern.FindStringSubmatch(lines[1])
	if refresh == nil || lines[2] != arpColumns {
		return model.ARPTable{}, invalidARP("unsupported table header")
	}

	table := model.ARPTable{
		ReportedDynamic: counts[0],
		Free:            counts[1],
		Garbage:         counts[2],
		Static:          counts[3],
		AutoRefresh:     refresh[1] == "enabled",
		Neighbors:       make([]model.ARPNeighbor, 0, counts[0]),
	}
	for index, line := range lines[3:] {
		if len(table.Neighbors) >= maxARPRecords {
			return model.ARPTable{}, invalidARP("record limit exceeded")
		}
		neighbor, err := parseARPRow(line)
		if err != nil {
			return model.ARPTable{}, invalidARP("row %d is unsupported", index+4)
		}
		table.Neighbors = append(table.Neighbors, neighbor)
	}

	if err := table.Validate(); err != nil {
		return model.ARPTable{}, fmt.Errorf("%w: validation failed", ErrInvalidARPTranscript)
	}
	return table, nil
}

func parseARPCounts(values []string) ([4]int, error) {
	var counts [4]int
	for index, value := range values {
		count, err := strconv.Atoi(value)
		if err != nil {
			return [4]int{}, err
		}
		counts[index] = count
	}
	return counts, nil
}

func parseARPRow(line string) (model.ARPNeighbor, error) {
	match := arpRowPattern.FindStringSubmatch(line)
	if match == nil {
		return model.ARPNeighbor{}, ErrInvalidARPTranscript
	}
	ip, err := netip.ParseAddr(match[1])
	if err != nil || !ip.Is4() {
		return model.ARPNeighbor{}, ErrInvalidARPTranscript
	}
	hardwareAddress, err := model.ParseMACAddress(match[2])
	if err != nil {
		return model.ARPNeighbor{}, ErrInvalidARPTranscript
	}

	return model.ARPNeighbor{
		IP:              ip,
		HardwareAddress: hardwareAddress,
		TTL:             match[3],
		Uptime:          match[4],
		Interface:       match[5],
	}, nil
}

func invalidARP(format string, arguments ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidARPTranscript, fmt.Sprintf(format, arguments...))
}
