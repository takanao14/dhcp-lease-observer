// Package identity derives stable opaque device identifiers.
package identity

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"

	"github.com/takanao14/dhcp-lease-observer/internal/model"
)

const (
	MinimumKeyBytes = 32
	idBytes         = 16
)

var (
	deviceDomain = []byte("dhcp-lease-observer/device-id/v1\x00")
	keyDomain    = []byte("dhcp-lease-observer/identity-key-id/v1\x00")
)

type Generator struct {
	key []byte
}

func NewGenerator(key []byte) (*Generator, error) {
	if len(key) < MinimumKeyBytes {
		return nil, errors.New("identity key must contain at least 32 bytes")
	}
	return &Generator{key: append([]byte(nil), key...)}, nil
}

func (generator *Generator) DeviceID(address model.MACAddress) (string, error) {
	if generator == nil || len(generator.key) < MinimumKeyBytes {
		return "", errors.New("identity generator is not initialized")
	}
	if address.IsZero() {
		return "", errors.New("MAC address is empty")
	}
	digest := generator.sum(deviceDomain, []byte(address.String()))
	return "d1_" + base64.RawURLEncoding.EncodeToString(digest[:idBytes]), nil
}

// KeyID detects identity-key rotation without persisting a key or plain hash.
func (generator *Generator) KeyID() (string, error) {
	if generator == nil || len(generator.key) < MinimumKeyBytes {
		return "", errors.New("identity generator is not initialized")
	}
	digest := generator.sum(keyDomain, nil)
	return "k1_" + base64.RawURLEncoding.EncodeToString(digest[:idBytes]), nil
}

// Clear overwrites the copied identity key when the generator is no longer used.
func (generator *Generator) Clear() {
	if generator == nil {
		return
	}
	for index := range generator.key {
		generator.key[index] = 0
	}
	generator.key = nil
}

func (generator *Generator) sum(domain, value []byte) [sha256.Size]byte {
	digest := hmac.New(sha256.New, generator.key)
	_, _ = digest.Write(domain)
	_, _ = digest.Write(value)
	var result [sha256.Size]byte
	copy(result[:], digest.Sum(nil))
	return result
}
