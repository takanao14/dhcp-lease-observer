package identity

import (
	"strings"
	"testing"

	"github.com/takanao14/dhcp-lease-observer/internal/model"
)

func TestDeviceIDIsStableOpaqueAndKeyScoped(t *testing.T) {
	address, err := model.ParseMACAddress("02:00:00:00:00:01")
	if err != nil {
		t.Fatalf("parse MAC: %v", err)
	}
	first, err := NewGenerator([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatalf("create first generator: %v", err)
	}
	second, err := NewGenerator([]byte("fedcba9876543210fedcba9876543210"))
	if err != nil {
		t.Fatalf("create second generator: %v", err)
	}

	firstID, err := first.DeviceID(address)
	if err != nil {
		t.Fatalf("derive first ID: %v", err)
	}
	repeatedID, err := first.DeviceID(address)
	if err != nil {
		t.Fatalf("derive repeated ID: %v", err)
	}
	secondID, err := second.DeviceID(address)
	if err != nil {
		t.Fatalf("derive second ID: %v", err)
	}
	if firstID != repeatedID {
		t.Fatal("same key and MAC produced different IDs")
	}
	if firstID == secondID {
		t.Fatal("different keys produced the same ID")
	}
	if !strings.HasPrefix(firstID, "d1_") || len(firstID) != 25 {
		t.Fatalf("device ID format = %q", firstID)
	}
	if strings.Contains(firstID, address.String()) {
		t.Fatalf("device ID leaked MAC address: %q", firstID)
	}

	firstKeyID, err := first.KeyID()
	if err != nil {
		t.Fatalf("derive first key ID: %v", err)
	}
	secondKeyID, err := second.KeyID()
	if err != nil {
		t.Fatalf("derive second key ID: %v", err)
	}
	if firstKeyID == secondKeyID || !strings.HasPrefix(firstKeyID, "k1_") {
		t.Fatalf("unexpected key IDs %q and %q", firstKeyID, secondKeyID)
	}
}

func TestGeneratorRejectsWeakOrInvalidInputs(t *testing.T) {
	if _, err := NewGenerator([]byte("too-short")); err == nil {
		t.Fatal("short key was accepted")
	}
	generator, err := NewGenerator(make([]byte, MinimumKeyBytes))
	if err != nil {
		t.Fatalf("create generator: %v", err)
	}
	if _, err := generator.DeviceID(model.MACAddress{}); err == nil {
		t.Fatal("empty MAC was accepted")
	}
	var missing *Generator
	if _, err := missing.KeyID(); err == nil {
		t.Fatal("nil generator was accepted")
	}
}
