package app

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const validConfig = `{
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

func TestRunVersionDoesNotLoadConfiguration(t *testing.T) {
	stdout, stderr := &bytes.Buffer{}, &bytes.Buffer{}
	if code := Run([]string{"--version"}, stdout, stderr, "v0.1.0-test"); code != ExitSuccess {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
	}
	if stdout.String() != "v0.1.0-test\n" {
		t.Fatalf("stdout = %q", stdout.String())
	}
}

func TestRunCheckConfigDoesNotRequireCredentials(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "config.json")
	if err := os.WriteFile(path, []byte(validConfig), 0o640); err != nil {
		t.Fatalf("write config: %v", err)
	}
	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatalf("chmod config: %v", err)
	}
	stdout, stderr := &bytes.Buffer{}, &bytes.Buffer{}
	code := Run([]string{"--config", path, "--check-config"}, stdout, stderr, "test")
	if code != ExitSuccess || stdout.String() != "configuration valid\n" || stderr.Len() != 0 {
		t.Fatalf("code = %d, stdout = %q, stderr = %q", code, stdout.String(), stderr.String())
	}
}

func TestRunSanitizesConfigurationErrors(t *testing.T) {
	stdout, stderr := &bytes.Buffer{}, &bytes.Buffer{}
	secretPath := filepath.Join(t.TempDir(), "secret-name.json")
	code := Run([]string{"--config", secretPath, "--check-config"}, stdout, stderr, "test")
	if code != ExitUsage || strings.Contains(stderr.String(), secretPath) {
		t.Fatalf("code = %d, stderr = %q", code, stderr.String())
	}
}

func TestRunRequiresAbsoluteCredentialsDirectory(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "config.json")
	if err := os.WriteFile(path, []byte(validConfig), 0o640); err != nil {
		t.Fatalf("write config: %v", err)
	}
	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatalf("chmod config: %v", err)
	}
	stdout, stderr := &bytes.Buffer{}, &bytes.Buffer{}
	code := Run([]string{"--config", path, "--credentials-dir", "relative"}, stdout, stderr, "test")
	if code != ExitUsage || !strings.Contains(stderr.String(), "absolute clean path") {
		t.Fatalf("code = %d, stderr = %q", code, stderr.String())
	}
}
