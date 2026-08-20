// Package config loads trusted collector configuration and credentials.
package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/takanao14/dhcp-lease-observer/internal/safefile"
	transport "github.com/takanao14/dhcp-lease-observer/internal/transport/ix2106"
)

const (
	SchemaVersion       = 1
	MaxConfigBytes      = 64 << 10
	PasswordCredential  = "ix2106-password"
	IdentityCredential  = "identity-key"
	maxPasswordBytes    = 1024
	maxIdentityKeyBytes = 4096
)

var ErrInvalidConfig = errors.New("invalid collector configuration")
var ErrInvalidCredentials = errors.New("invalid collector credentials")

type Config struct {
	SchemaVersion            int    `json:"schema_version"`
	SourceInstance           string `json:"source_instance"`
	Scope                    string `json:"scope"`
	CollectionTimeoutSeconds int    `json:"collection_timeout_seconds"`
	IX2106                   IX2106 `json:"ix2106"`
	StatePath                string `json:"state_path"`
	PrometheusPath           string `json:"prometheus_path"`
}

type IX2106 struct {
	Address                 string `json:"address"`
	Username                string `json:"username"`
	HostKeySHA256           string `json:"host_key_sha256"`
	ConnectTimeoutSeconds   int    `json:"connect_timeout_seconds"`
	HandshakeTimeoutSeconds int    `json:"handshake_timeout_seconds"`
	AuthTimeoutSeconds      int    `json:"auth_timeout_seconds"`
	CommandTimeoutSeconds   int    `json:"command_timeout_seconds"`
	MaxFrameBytes           int    `json:"max_frame_bytes"`
}

var labelPattern = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

func Load(path string) (Config, error) {
	file, err := safefile.OpenRegular(path, 0o022, MaxConfigBytes)
	if err != nil {
		if errors.Is(err, safefile.ErrUnsafeFile) {
			return Config{}, ErrInvalidConfig
		}
		return Config{}, err
	}
	defer file.Close()
	decoder := json.NewDecoder(io.LimitReader(file, MaxConfigBytes+1))
	decoder.DisallowUnknownFields()
	var config Config
	if err := decoder.Decode(&config); err != nil {
		return Config{}, ErrInvalidConfig
	}
	if err := ensureEOF(decoder); err != nil {
		return Config{}, ErrInvalidConfig
	}
	if err := config.Validate(); err != nil {
		return Config{}, err
	}
	return config, nil
}

func (config Config) Validate() error {
	if config.SchemaVersion != SchemaVersion ||
		!validLabel(config.SourceInstance) || !validLabel(config.Scope) {
		return ErrInvalidConfig
	}
	if config.CollectionTimeoutSeconds < 1 || config.CollectionTimeoutSeconds > 300 {
		return ErrInvalidConfig
	}
	if !validTimeout(config.IX2106.ConnectTimeoutSeconds, config.CollectionTimeoutSeconds) ||
		!validTimeout(config.IX2106.HandshakeTimeoutSeconds, config.CollectionTimeoutSeconds) ||
		!validTimeout(config.IX2106.AuthTimeoutSeconds, config.CollectionTimeoutSeconds) ||
		!validTimeout(config.IX2106.CommandTimeoutSeconds, config.CollectionTimeoutSeconds) {
		return ErrInvalidConfig
	}
	if config.IX2106.MaxFrameBytes < 4096 || config.IX2106.MaxFrameBytes > transport.DefaultMaxFrameBytes {
		return ErrInvalidConfig
	}
	if !validAbsolutePath(config.StatePath, ".json") ||
		!validAbsolutePath(config.PrometheusPath, ".prom") ||
		config.StatePath == config.PrometheusPath {
		return ErrInvalidConfig
	}
	if err := config.Transport().Validate(); err != nil {
		return ErrInvalidConfig
	}
	return nil
}

func (config Config) CollectionTimeout() time.Duration {
	return time.Duration(config.CollectionTimeoutSeconds) * time.Second
}

func (config Config) Transport() transport.Config {
	return transport.Config{
		Address:          config.IX2106.Address,
		Username:         config.IX2106.Username,
		HostKeySHA256:    config.IX2106.HostKeySHA256,
		ConnectTimeout:   time.Duration(config.IX2106.ConnectTimeoutSeconds) * time.Second,
		HandshakeTimeout: time.Duration(config.IX2106.HandshakeTimeoutSeconds) * time.Second,
		AuthTimeout:      time.Duration(config.IX2106.AuthTimeoutSeconds) * time.Second,
		CommandTimeout:   time.Duration(config.IX2106.CommandTimeoutSeconds) * time.Second,
		MaxFrameBytes:    config.IX2106.MaxFrameBytes,
	}
}

type Credentials struct {
	Password    []byte
	IdentityKey []byte
}

func LoadCredentials(directory string) (Credentials, error) {
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory {
		return Credentials{}, ErrInvalidCredentials
	}
	password, err := readCredential(filepath.Join(directory, PasswordCredential), maxPasswordBytes)
	if err != nil {
		return Credentials{}, err
	}
	identityKey, err := readCredential(filepath.Join(directory, IdentityCredential), maxIdentityKeyBytes)
	if err != nil {
		clearBytes(password)
		return Credentials{}, err
	}
	if len(password) == 0 || len(identityKey) < 32 ||
		bytes.IndexByte(password, 0) >= 0 || bytes.ContainsAny(password, "\r\n") ||
		bytes.ContainsAny(identityKey, "\r\n") {
		clearBytes(password)
		clearBytes(identityKey)
		return Credentials{}, ErrInvalidCredentials
	}
	return Credentials{Password: password, IdentityKey: identityKey}, nil
}

func (credentials *Credentials) Clear() {
	if credentials == nil {
		return
	}
	clearBytes(credentials.Password)
	clearBytes(credentials.IdentityKey)
	credentials.Password = nil
	credentials.IdentityKey = nil
}

func readCredential(path string, maxBytes int64) ([]byte, error) {
	file, err := safefile.OpenRegular(path, 0o077, maxBytes)
	if err != nil {
		if errors.Is(err, safefile.ErrUnsafeFile) {
			return nil, ErrInvalidCredentials
		}
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxBytes+1))
	if err != nil || int64(len(data)) > maxBytes {
		return nil, ErrInvalidCredentials
	}
	data = bytes.TrimSuffix(data, []byte("\n"))
	data = bytes.TrimSuffix(data, []byte("\r"))
	return data, nil
}

func ensureEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return ErrInvalidConfig
	}
	return nil
}

func validLabel(value string) bool {
	return value != "" && len(value) <= 128 && labelPattern.MatchString(value)
}

func validTimeout(value, overall int) bool {
	return value >= 1 && value <= 60 && value <= overall
}

func validAbsolutePath(path, extension string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path && strings.HasSuffix(path, extension)
}

func clearBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
