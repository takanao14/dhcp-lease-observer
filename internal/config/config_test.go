package config

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const validConfigJSON = `{
  "schema_version": 1,
  "source_instance": "fixture-router",
  "scope": "fixture-lan",
  "collection_timeout_seconds": 30,
  "ix2106": {
    "address": "192.0.2.1:22",
    "username": "fixture-user",
    "host_key_sha256": "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    "connect_timeout_seconds": 5,
    "handshake_timeout_seconds": 10,
    "auth_timeout_seconds": 5,
    "command_timeout_seconds": 10,
    "max_frame_bytes": 1048576
  },
  "state_path": "/var/lib/dhcp-lease-observer/last-good.json",
  "prometheus_path": "/var/lib/prometheus/node-exporter/dhcp_lease_observer.prom"
}`

func TestLoadValidConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	writeFile(t, path, []byte(validConfigJSON), 0o640)
	config, err := Load(path)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if config.SourceInstance != "fixture-router" || config.Transport().Address != "192.0.2.1:22" {
		t.Fatalf("loaded config = %#v", config)
	}
}

func TestLoadRejectsInvalidConfig(t *testing.T) {
	tests := []struct {
		name    string
		content string
		mode    os.FileMode
	}{
		{name: "unknown field", content: strings.Replace(validConfigJSON, `"scope":`, `"unknown": true, "scope":`, 1), mode: 0o640},
		{name: "trailing JSON", content: validConfigJSON + `{}`, mode: 0o640},
		{name: "relative state", content: strings.Replace(validConfigJSON, "/var/lib/dhcp-lease-observer/last-good.json", "last-good.json", 1), mode: 0o640},
		{name: "unsafe label", content: strings.Replace(validConfigJSON, "fixture-lan", "fixture lan", 1), mode: 0o640},
		{name: "excessive timeout", content: strings.Replace(validConfigJSON, `"command_timeout_seconds": 10`, `"command_timeout_seconds": 60`, 1), mode: 0o640},
		{name: "insecure mode", content: validConfigJSON, mode: 0o666},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.json")
			writeFile(t, path, []byte(test.content), test.mode)
			if _, err := Load(path); !errors.Is(err, ErrInvalidConfig) {
				t.Fatalf("load error = %v, want ErrInvalidConfig", err)
			}
		})
	}
}

func TestLoadRejectsConfigSymlink(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "target.json")
	writeFile(t, target, []byte(validConfigJSON), 0o640)
	link := filepath.Join(directory, "config.json")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("create symlink: %v", err)
	}
	if _, err := Load(link); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("load error = %v, want ErrInvalidConfig", err)
	}
}

func TestLoadCredentialsAndClear(t *testing.T) {
	directory := t.TempDir()
	writeFile(t, filepath.Join(directory, PasswordCredential), []byte("fixture-password\n"), 0o600)
	writeFile(t, filepath.Join(directory, IdentityCredential), []byte(strings.Repeat("k", 32)+"\n"), 0o600)
	credentials, err := LoadCredentials(directory)
	if err != nil {
		t.Fatalf("load credentials: %v", err)
	}
	if string(credentials.Password) != "fixture-password" || len(credentials.IdentityKey) != 32 {
		t.Fatal("credentials were not normalized")
	}
	passwordBacking := credentials.Password
	keyBacking := credentials.IdentityKey
	credentials.Clear()
	if !bytes.Equal(passwordBacking, make([]byte, len(passwordBacking))) ||
		!bytes.Equal(keyBacking, make([]byte, len(keyBacking))) {
		t.Fatal("credential backing memory was not cleared")
	}
}

func TestLoadCredentialsRejectsUnsafeInput(t *testing.T) {
	tests := []struct {
		name     string
		password string
		key      string
		mode     os.FileMode
	}{
		{name: "short key", password: "fixture-password", key: "short", mode: 0o600},
		{name: "password newline", password: "fixture\npassword", key: strings.Repeat("k", 32), mode: 0o600},
		{name: "insecure mode", password: "fixture-password", key: strings.Repeat("k", 32), mode: 0o644},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			directory := t.TempDir()
			writeFile(t, filepath.Join(directory, PasswordCredential), []byte(test.password), test.mode)
			writeFile(t, filepath.Join(directory, IdentityCredential), []byte(test.key), test.mode)
			if _, err := LoadCredentials(directory); err == nil {
				t.Fatal("unsafe credentials were accepted")
			}
		})
	}
}

func TestLoadCredentialsRejectsSymlink(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "password-target")
	writeFile(t, target, []byte("fixture-password"), 0o600)
	if err := os.Symlink(target, filepath.Join(directory, PasswordCredential)); err != nil {
		t.Fatalf("create credential symlink: %v", err)
	}
	writeFile(t, filepath.Join(directory, IdentityCredential), []byte(strings.Repeat("k", 32)), 0o600)
	if _, err := LoadCredentials(directory); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("load error = %v, want ErrInvalidCredentials", err)
	}
}

func writeFile(t *testing.T, path string, data []byte, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, data, mode); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatalf("chmod %s: %v", path, err)
	}
}
