// Package model defines source-neutral DHCP lease snapshot types.
package model

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
)

const SchemaVersion = 1

type Assignment string

const (
	AssignmentDynamic Assignment = "dynamic"
	AssignmentFixed   Assignment = "fixed"
)

type LeaseState string

const LeaseStateBound LeaseState = "bound"

// MACAddress is a canonical six-byte IEEE 802 hardware address.
type MACAddress [6]byte

func ParseMACAddress(value string) (MACAddress, error) {
	parsed, err := net.ParseMAC(value)
	if err != nil || len(parsed) != len(MACAddress{}) {
		return MACAddress{}, errors.New("invalid six-byte MAC address")
	}
	var address MACAddress
	copy(address[:], parsed)
	return address, nil
}

func (address MACAddress) String() string {
	return net.HardwareAddr(address[:]).String()
}

func (address MACAddress) IsZero() bool {
	return address == MACAddress{}
}

func (address MACAddress) MarshalJSON() ([]byte, error) {
	return json.Marshal(address.String())
}

func (address *MACAddress) UnmarshalJSON(data []byte) error {
	var value string
	if err := json.Unmarshal(data, &value); err != nil {
		return errors.New("MAC address must be a JSON string")
	}
	parsed, err := ParseMACAddress(value)
	if err != nil {
		return err
	}
	*address = parsed
	return nil
}

type LeaseSnapshot struct {
	SchemaVersion int        `json:"schema_version"`
	Leases        LeaseTable `json:"leases"`
	ARP           ARPTable   `json:"arp"`
}

type LeaseTable struct {
	ReportedCount int           `json:"reported_count"`
	Records       []LeaseRecord `json:"records"`
}

type LeaseRecord struct {
	Assignment       Assignment `json:"assignment"`
	IP               netip.Addr `json:"ip"`
	HardwareAddress  MACAddress `json:"hardware_address"`
	BoundTimeSeconds int64      `json:"bound_time_seconds"`
	LeaseTimeSeconds int64      `json:"lease_time_seconds"`
	State            LeaseState `json:"state"`
	Profile          string     `json:"profile"`
}

type ARPTable struct {
	ReportedDynamic int           `json:"reported_dynamic"`
	Free            int           `json:"free"`
	Garbage         int           `json:"garbage"`
	Static          int           `json:"static"`
	AutoRefresh     bool          `json:"auto_refresh"`
	Neighbors       []ARPNeighbor `json:"neighbors"`
}

type ARPNeighbor struct {
	IP              netip.Addr `json:"ip"`
	HardwareAddress MACAddress `json:"hardware_address"`
	TTL             string     `json:"ttl"`
	Uptime          string     `json:"uptime"`
	Interface       string     `json:"interface"`
}

func (snapshot LeaseSnapshot) Validate() error {
	if snapshot.SchemaVersion != SchemaVersion {
		return fmt.Errorf("unsupported schema version: %d", snapshot.SchemaVersion)
	}
	if err := snapshot.Leases.Validate(); err != nil {
		return fmt.Errorf("leases: %w", err)
	}
	if err := snapshot.ARP.Validate(); err != nil {
		return fmt.Errorf("ARP: %w", err)
	}
	return nil
}

func (table LeaseTable) Validate() error {
	if table.ReportedCount < 0 || table.ReportedCount != len(table.Records) {
		return errors.New("reported count does not match lease records")
	}

	seenIPs := make(map[netip.Addr]struct{}, len(table.Records))
	seenMACs := make(map[MACAddress]struct{}, len(table.Records))
	for index, record := range table.Records {
		if err := record.Validate(); err != nil {
			return fmt.Errorf("record %d: %w", index, err)
		}
		if _, exists := seenIPs[record.IP]; exists {
			return fmt.Errorf("record %d: duplicate IP address", index)
		}
		if _, exists := seenMACs[record.HardwareAddress]; exists {
			return fmt.Errorf("record %d: duplicate MAC address", index)
		}
		seenIPs[record.IP] = struct{}{}
		seenMACs[record.HardwareAddress] = struct{}{}
	}
	return nil
}

func (record LeaseRecord) Validate() error {
	if record.Assignment != AssignmentDynamic && record.Assignment != AssignmentFixed {
		return errors.New("unsupported assignment")
	}
	if !record.IP.IsValid() || !record.IP.Is4() {
		return errors.New("IP address must be IPv4")
	}
	if record.HardwareAddress.IsZero() {
		return errors.New("MAC address is empty")
	}
	if record.BoundTimeSeconds < 0 {
		return errors.New("bound time is negative")
	}
	if record.LeaseTimeSeconds <= 0 {
		return errors.New("lease time must be positive")
	}
	if record.State != LeaseStateBound {
		return errors.New("unsupported lease state")
	}
	return nil
}

func (table ARPTable) Validate() error {
	if table.ReportedDynamic < 0 || table.ReportedDynamic != len(table.Neighbors) {
		return errors.New("reported dynamic count does not match ARP neighbors")
	}
	if table.Free < 0 || table.Garbage < 0 || table.Static < 0 {
		return errors.New("ARP summary count is negative")
	}

	seenIPs := make(map[netip.Addr]struct{}, len(table.Neighbors))
	for index, neighbor := range table.Neighbors {
		if err := neighbor.Validate(); err != nil {
			return fmt.Errorf("neighbor %d: %w", index, err)
		}
		if _, exists := seenIPs[neighbor.IP]; exists {
			return fmt.Errorf("neighbor %d: duplicate IP address", index)
		}
		seenIPs[neighbor.IP] = struct{}{}
	}
	return nil
}

func (neighbor ARPNeighbor) Validate() error {
	if !neighbor.IP.IsValid() || !neighbor.IP.Is4() {
		return errors.New("IP address must be IPv4")
	}
	if neighbor.HardwareAddress.IsZero() {
		return errors.New("MAC address is empty")
	}
	if neighbor.Interface == "" {
		return errors.New("interface is empty")
	}
	return nil
}
