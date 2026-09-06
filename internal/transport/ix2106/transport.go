// Package ix2106 implements the bounded SSH transport for NEC IX2106 devices.
package ix2106

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	sessioncontract "github.com/takanao14/dhcp-lease-observer/internal/session/ix2106"
	"golang.org/x/crypto/ssh"
)

const (
	commandConfigure = "configure"
	commandPagerOff  = "terminal length 0"
	commandLease     = "show ip dhcp lease"
	commandARP       = "show arp entry"
	commandExit      = "exit"

	DefaultConnectTimeout   = 5 * time.Second
	DefaultHandshakeTimeout = 10 * time.Second
	DefaultAuthTimeout      = 5 * time.Second
	DefaultCommandTimeout   = 10 * time.Second
	DefaultMaxFrameBytes    = 1 << 20
)

type ErrorKind string

const (
	ErrorInvalidConfig         ErrorKind = "invalid_config"
	ErrorConnectFailed         ErrorKind = "connect_failed"
	ErrorHandshakeFailed       ErrorKind = "handshake_failed"
	ErrorHandshakeTimeout      ErrorKind = "handshake_timeout"
	ErrorAuthenticationTimeout ErrorKind = "authentication_timeout"
	ErrorSessionFailed         ErrorKind = "session_failed"
	ErrorResponseLimit         ErrorKind = "response_limit_exceeded"
)

type Error struct {
	kind      ErrorKind
	retryable bool
}

func (transportError *Error) Error() string {
	if message, ok := transportErrorMessages[transportError.kind]; ok {
		return message
	}
	return "IX2106 SSH transport failed"
}

func (transportError *Error) Kind() ErrorKind {
	return transportError.kind
}

func (transportError *Error) Retryable() bool {
	return transportError.retryable
}

type Config struct {
	Address          string
	Username         string
	HostKeySHA256    string
	ConnectTimeout   time.Duration
	HandshakeTimeout time.Duration
	AuthTimeout      time.Duration
	CommandTimeout   time.Duration
	MaxFrameBytes    int
}

func NewConfig(address, username, hostKeySHA256 string) Config {
	return Config{
		Address:          address,
		Username:         username,
		HostKeySHA256:    hostKeySHA256,
		ConnectTimeout:   DefaultConnectTimeout,
		HandshakeTimeout: DefaultHandshakeTimeout,
		AuthTimeout:      DefaultAuthTimeout,
		CommandTimeout:   DefaultCommandTimeout,
		MaxFrameBytes:    DefaultMaxFrameBytes,
	}
}

func (config Config) Validate() error {
	host, port, err := net.SplitHostPort(config.Address)
	if err != nil || host == "" || port == "" {
		return newTransportError(ErrorInvalidConfig, false)
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65535 {
		return newTransportError(ErrorInvalidConfig, false)
	}
	if !usernamePattern.MatchString(config.Username) {
		return newTransportError(ErrorInvalidConfig, false)
	}
	if !validSHA256Fingerprint(config.HostKeySHA256) {
		return newTransportError(ErrorInvalidConfig, false)
	}
	if config.ConnectTimeout <= 0 || config.HandshakeTimeout <= 0 ||
		config.AuthTimeout <= 0 || config.CommandTimeout <= 0 {
		return newTransportError(ErrorInvalidConfig, false)
	}
	if config.MaxFrameBytes <= 0 || config.MaxFrameBytes > DefaultMaxFrameBytes {
		return newTransportError(ErrorInvalidConfig, false)
	}
	return nil
}

type CommandBodies struct {
	Lease      []byte
	ARP        []byte
	ARPFailure error
}

var (
	operationPromptPattern = regexp.MustCompile(`^[A-Za-z0-9._-]+%$`)
	anyPromptPattern       = regexp.MustCompile(`^[A-Za-z0-9._-]+(?:\(config\))?[#%]$`)
	usernamePattern        = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)
	errHostKeyMismatch     = errors.New("host key mismatch")

	transportErrorMessages = map[ErrorKind]string{
		ErrorInvalidConfig:         "IX2106 SSH transport configuration is invalid",
		ErrorConnectFailed:         "TCP connection to IX2106 failed",
		ErrorHandshakeFailed:       "SSH handshake with IX2106 failed",
		ErrorHandshakeTimeout:      "SSH handshake deadline expired",
		ErrorAuthenticationTimeout: "SSH authentication deadline expired",
		ErrorSessionFailed:         "IX2106 SSH shell session failed",
		ErrorResponseLimit:         "IX2106 command response exceeded the configured limit",
	}
)

// Collect retrieves complete command bodies using only the fixed IX2106
// command sequence. It does not parse or persist device output.
func Collect(ctx context.Context, config Config, password []byte) (CommandBodies, error) {
	if err := config.Validate(); err != nil {
		return CommandBodies{}, err
	}
	if len(password) == 0 {
		return CommandBodies{}, newTransportError(ErrorInvalidConfig, false)
	}
	client, err := dial(ctx, config, password)
	if err != nil {
		return CommandBodies{}, err
	}
	defer client.close()

	return client.collect(ctx, config)
}

type client struct {
	network net.Conn
	ssh     *ssh.Client
}

func dial(ctx context.Context, config Config, password []byte) (*client, error) {
	dialer := net.Dialer{Timeout: config.ConnectTimeout}
	network, err := dialer.DialContext(ctx, "tcp", config.Address)
	if err != nil {
		return nil, newTransportError(ErrorConnectFailed, true)
	}

	authStarted := atomic.Bool{}
	sshConfig := clientConfig(ctx, config, network, password, &authStarted)
	if err := setDeadline(network, ctx, config.HandshakeTimeout); err != nil {
		network.Close()
		return nil, newTransportError(ErrorHandshakeFailed, true)
	}
	connection, channels, requests, err := ssh.NewClientConn(network, config.Address, sshConfig)
	if err != nil {
		network.Close()
		if errors.Is(err, errHostKeyMismatch) {
			failure, _ := sessioncontract.ConnectionFailure(sessioncontract.FailureHostKeyMismatch)
			return nil, failure
		}
		if isTimeout(err) {
			if authStarted.Load() {
				return nil, newTransportError(ErrorAuthenticationTimeout, true)
			}
			return nil, newTransportError(ErrorHandshakeTimeout, true)
		}
		if authStarted.Load() {
			failure, _ := sessioncontract.ConnectionFailure(sessioncontract.FailureAuthentication)
			return nil, failure
		}
		return nil, newTransportError(ErrorHandshakeFailed, true)
	}
	if err := network.SetDeadline(time.Time{}); err != nil {
		connection.Close()
		return nil, newTransportError(ErrorSessionFailed, true)
	}
	return &client{network: network, ssh: ssh.NewClient(connection, channels, requests)}, nil
}

func clientConfig(
	ctx context.Context,
	config Config,
	network net.Conn,
	password []byte,
	authStarted *atomic.Bool,
) *ssh.ClientConfig {
	return &ssh.ClientConfig{
		Config: ssh.Config{
			KeyExchanges: []string{ssh.KeyExchangeDHGEXSHA256},
			Ciphers:      []string{"aes128-ctr", "aes192-ctr", "aes256-ctr"},
			MACs:         []string{ssh.HMACSHA256, ssh.HMACSHA512},
		},
		User: config.Username,
		Auth: []ssh.AuthMethod{ssh.PasswordCallback(func() (string, error) {
			authStarted.Store(true)
			if err := setDeadline(network, ctx, config.AuthTimeout); err != nil {
				return "", newTransportError(ErrorAuthenticationTimeout, true)
			}
			return string(password), nil
		})},
		HostKeyCallback:   pinnedHostKey(config.HostKeySHA256),
		HostKeyAlgorithms: []string{ssh.KeyAlgoRSA},
	}
}

func pinnedHostKey(expected string) ssh.HostKeyCallback {
	return func(_ string, _ net.Addr, key ssh.PublicKey) error {
		if key.Type() != ssh.KeyAlgoRSA {
			return errHostKeyMismatch
		}
		actual := ssh.FingerprintSHA256(key)
		if subtle.ConstantTimeCompare([]byte(actual), []byte(expected)) != 1 {
			return errHostKeyMismatch
		}
		return nil
	}
}

func (client *client) collect(ctx context.Context, config Config) (CommandBodies, error) {
	if err := setDeadline(client.network, ctx, config.CommandTimeout); err != nil {
		return CommandBodies{}, newTransportError(ErrorSessionFailed, true)
	}
	shell, err := client.ssh.NewSession()
	if err != nil {
		return CommandBodies{}, newTransportError(ErrorSessionFailed, true)
	}
	defer shell.Close()

	input, err := shell.StdinPipe()
	if err != nil {
		return CommandBodies{}, newTransportError(ErrorSessionFailed, true)
	}
	output := newOutputBuffer(config.MaxFrameBytes)
	shell.Stdout = output
	shell.Stderr = output
	if err := shell.RequestPty("vt100", 24, 80, ssh.TerminalModes{ssh.ECHO: 0}); err != nil {
		return CommandBodies{}, newTransportError(ErrorSessionFailed, false)
	}
	if err := shell.Shell(); err != nil {
		return CommandBodies{}, newTransportError(ErrorSessionFailed, false)
	}
	go func() {
		_ = shell.Wait()
		output.close()
	}()

	initial, event, err := client.nextFrame(ctx, output, config.CommandTimeout)
	if err != nil {
		return CommandBodies{}, err
	}
	if event != "" {
		failure, _ := sessioncontract.FramingFailure(eventFailure(event))
		return CommandBodies{}, failure
	}
	if !operationPromptPattern.MatchString(lastContent(initial)) {
		failure, _ := sessioncontract.FramingFailure(sessioncontract.FailurePromptMismatch)
		return CommandBodies{}, failure
	}

	if _, err := client.runCommand(ctx, input, output, config.CommandTimeout, commandConfigure); err != nil {
		return CommandBodies{}, err
	}
	if _, err := client.runCommand(ctx, input, output, config.CommandTimeout, commandPagerOff); err != nil {
		return CommandBodies{}, err
	}
	lease, err := client.runCommand(ctx, input, output, config.CommandTimeout, commandLease)
	if err != nil {
		return CommandBodies{}, err
	}
	arp, err := client.runCommand(ctx, input, output, config.CommandTimeout, commandARP)
	if err != nil {
		_, _ = io.WriteString(input, commandExit+"\n"+commandExit+"\n")
		return CommandBodies{Lease: lease, ARPFailure: err}, nil
	}

	_, _ = io.WriteString(input, commandExit+"\n"+commandExit+"\n")
	return CommandBodies{Lease: lease, ARP: arp}, nil
}

func (client *client) runCommand(
	ctx context.Context,
	input io.Writer,
	output *outputBuffer,
	timeout time.Duration,
	command string,
) ([]byte, error) {
	if err := setDeadline(client.network, ctx, timeout); err != nil {
		return nil, newTransportError(ErrorSessionFailed, true)
	}
	if _, err := io.WriteString(input, command+"\n"); err != nil {
		return nil, newTransportError(ErrorSessionFailed, true)
	}
	frame, event, err := client.nextFrame(ctx, output, timeout)
	if err != nil {
		return nil, err
	}
	body, err := sessioncontract.ExtractCompleteCommandBody(frame, event, command)
	if err != nil {
		return nil, err
	}
	return body, nil
}

func (client *client) nextFrame(
	ctx context.Context,
	output *outputBuffer,
	timeout time.Duration,
) ([]byte, sessioncontract.TerminalEvent, error) {
	commandContext, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	frame, err := output.nextFrame(commandContext)
	switch {
	case err == nil:
		return frame, "", nil
	case errors.Is(err, errResponseLimit):
		return nil, "", newTransportError(ErrorResponseLimit, false)
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled):
		return frame, sessioncontract.TerminalTimeout, nil
	case errors.Is(err, io.EOF):
		return frame, sessioncontract.TerminalEOF, nil
	default:
		return nil, "", newTransportError(ErrorSessionFailed, true)
	}
}

func (client *client) close() {
	client.ssh.Close()
	client.network.Close()
}

var errResponseLimit = errors.New("response limit exceeded")

type outputBuffer struct {
	mu       sync.Mutex
	data     []byte
	max      int
	overflow bool
	closed   bool
	notify   chan struct{}
}

func newOutputBuffer(max int) *outputBuffer {
	return &outputBuffer{max: max, notify: make(chan struct{}, 1)}
}

func (buffer *outputBuffer) Write(data []byte) (int, error) {
	buffer.mu.Lock()
	if !buffer.overflow {
		if len(buffer.data)+len(data) > buffer.max {
			buffer.overflow = true
		} else {
			buffer.data = append(buffer.data, data...)
		}
	}
	buffer.mu.Unlock()
	buffer.signal()
	return len(data), nil
}

func (buffer *outputBuffer) nextFrame(ctx context.Context) ([]byte, error) {
	for {
		data, overflow, closed := buffer.state()
		switch {
		case overflow:
			return nil, errResponseLimit
		case completeFrame(data):
			buffer.consume()
			return data, nil
		case closed:
			buffer.consume()
			return data, io.EOF
		}

		select {
		case <-buffer.notify:
		case <-ctx.Done():
			data, overflow, _ = buffer.state()
			if overflow {
				return nil, errResponseLimit
			}
			if completeFrame(data) {
				buffer.consume()
				return data, nil
			}
			return data, ctx.Err()
		}
	}
}

func (buffer *outputBuffer) state() ([]byte, bool, bool) {
	buffer.mu.Lock()
	defer buffer.mu.Unlock()
	return append([]byte(nil), buffer.data...), buffer.overflow, buffer.closed
}

func (buffer *outputBuffer) consume() {
	buffer.mu.Lock()
	buffer.data = nil
	buffer.overflow = false
	buffer.mu.Unlock()
}

func (buffer *outputBuffer) close() {
	buffer.mu.Lock()
	buffer.closed = true
	buffer.mu.Unlock()
	buffer.signal()
}

func (buffer *outputBuffer) signal() {
	select {
	case buffer.notify <- struct{}{}:
	default:
	}
}

func completeFrame(data []byte) bool {
	text := string(data)
	return strings.Contains(text, "--More--") ||
		strings.Contains(strings.ToLower(text), "config process is occupied") ||
		anyPromptPattern.MatchString(lastContent(data))
}

func lastContent(data []byte) string {
	lines := strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n")
	for index := len(lines) - 1; index >= 0; index-- {
		if line := strings.TrimSpace(lines[index]); line != "" {
			return line
		}
	}
	return ""
}

func eventFailure(event sessioncontract.TerminalEvent) sessioncontract.FailureKind {
	if event == sessioncontract.TerminalTimeout {
		return sessioncontract.FailureTimeout
	}
	return sessioncontract.FailureUnexpectedEOF
}

func validSHA256Fingerprint(value string) bool {
	if !strings.HasPrefix(value, "SHA256:") {
		return false
	}
	digest, err := base64.RawStdEncoding.DecodeString(strings.TrimPrefix(value, "SHA256:"))
	return err == nil && len(digest) == 32
}

func setDeadline(connection net.Conn, ctx context.Context, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	return connection.SetDeadline(deadline)
}

func isTimeout(err error) bool {
	var networkError net.Error
	return errors.As(err, &networkError) && networkError.Timeout()
}

func newTransportError(kind ErrorKind, retryable bool) *Error {
	return &Error{kind: kind, retryable: retryable}
}
