package ix2106

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	parser "github.com/takanao14/dhcp-lease-observer/internal/parser/ix2106"
	sessioncontract "github.com/takanao14/dhcp-lease-observer/internal/session/ix2106"
	"golang.org/x/crypto/ssh"
)

func TestCollectUsesFixedPromptDrivenSequence(t *testing.T) {
	server := startTestServer(t, "fixture-user", "fixture-password")
	defer server.close()

	config := NewConfig(server.address, "fixture-user", server.fingerprint)
	config.ConnectTimeout = 2 * time.Second
	config.HandshakeTimeout = 2 * time.Second
	config.AuthTimeout = 2 * time.Second
	config.CommandTimeout = 2 * time.Second

	bodies, err := Collect(context.Background(), config, []byte("fixture-password"))
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	lease, err := parser.ParseLease(strings.NewReader(string(bodies.Lease)))
	if err != nil {
		t.Fatalf("parse lease body: %v", err)
	}
	if lease.ReportedCount != 0 {
		t.Fatalf("lease count = %d, want 0", lease.ReportedCount)
	}
	arp, err := parser.ParseARP(strings.NewReader(string(bodies.ARP)))
	if err != nil {
		t.Fatalf("parse ARP body: %v", err)
	}
	if arp.ReportedDynamic != 0 {
		t.Fatalf("ARP dynamic count = %d, want 0", arp.ReportedDynamic)
	}
}

func TestCollectPreservesAuthoritativeLeaseWhenARPFramingFails(t *testing.T) {
	server := startTestServerOptions(t, "fixture-user", "fixture-password", 0, true)
	defer server.close()
	config := NewConfig(server.address, "fixture-user", server.fingerprint)
	config.ConnectTimeout = 2 * time.Second
	config.HandshakeTimeout = 2 * time.Second
	config.AuthTimeout = 2 * time.Second
	config.CommandTimeout = 2 * time.Second

	bodies, err := Collect(context.Background(), config, []byte("fixture-password"))
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if bodies.ARPFailure == nil || len(bodies.ARP) != 0 {
		t.Fatalf("ARP result = %#v, want sanitized failure", bodies)
	}
	if _, err := parser.ParseLease(strings.NewReader(string(bodies.Lease))); err != nil {
		t.Fatalf("authoritative lease body was not preserved: %v", err)
	}
}

func TestCollectClassifiesCommandAuthorizationFailure(t *testing.T) {
	server := startTestServerBehavior(t, "fixture-user", "fixture-password", testServerBehavior{
		deniedCommand: commandLease,
	})
	defer server.close()
	config := NewConfig(server.address, "fixture-user", server.fingerprint)
	config.ConnectTimeout = 2 * time.Second
	config.HandshakeTimeout = 2 * time.Second
	config.AuthTimeout = 2 * time.Second
	config.CommandTimeout = 2 * time.Second

	_, err := Collect(context.Background(), config, []byte("fixture-password"))
	var failure *sessioncontract.Failure
	if !errors.As(err, &failure) || failure.Kind() != sessioncontract.FailureAuthorization {
		t.Fatalf("error = %v, want authorization failure", err)
	}
	if failure.Command() != commandLease {
		t.Fatalf("authorization command = %q, want %q", failure.Command(), commandLease)
	}
}

func TestConfigRejectsUnsafeOrUnboundedValues(t *testing.T) {
	validPin := "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	tests := []struct {
		name   string
		mutate func(*Config)
	}{
		{name: "missing port", mutate: func(config *Config) { config.Address = "router.invalid" }},
		{name: "missing host", mutate: func(config *Config) { config.Address = ":22" }},
		{name: "invalid port", mutate: func(config *Config) { config.Address = "router.invalid:70000" }},
		{name: "invalid username", mutate: func(config *Config) { config.Username = "fixture user" }},
		{name: "invalid pin", mutate: func(config *Config) { config.HostKeySHA256 = "SHA256:short" }},
		{name: "zero timeout", mutate: func(config *Config) { config.AuthTimeout = 0 }},
		{name: "oversized frame", mutate: func(config *Config) { config.MaxFrameBytes = DefaultMaxFrameBytes + 1 }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := NewConfig("router.invalid:22", "fixture-user", validPin)
			test.mutate(&config)
			var transportError *Error
			if err := config.Validate(); !errors.As(err, &transportError) || transportError.Kind() != ErrorInvalidConfig {
				t.Fatalf("validation error = %v, want invalid_config", err)
			}
		})
	}
}

func TestCollectRejectsEmptyPasswordBeforeDial(t *testing.T) {
	config := NewConfig("router.invalid:22", "fixture-user", "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	var transportError *Error
	_, err := Collect(context.Background(), config, nil)
	if !errors.As(err, &transportError) || transportError.Kind() != ErrorInvalidConfig {
		t.Fatalf("error = %v, want invalid_config", err)
	}
}

func TestClientConfigUsesIX2106AlgorithmAllowlist(t *testing.T) {
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	config := NewConfig("router.invalid:22", "fixture-user", "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	started := atomic.Bool{}
	actual := clientConfig(context.Background(), config, left, []byte("fixture-password"), &started)

	assertStringsEqual(t, actual.KeyExchanges, []string{ssh.KeyExchangeDHGEXSHA256})
	assertStringsEqual(t, actual.Ciphers, []string{"aes128-ctr", "aes192-ctr", "aes256-ctr"})
	assertStringsEqual(t, actual.MACs, []string{ssh.HMACSHA256, ssh.HMACSHA512})
	assertStringsEqual(t, actual.HostKeyAlgorithms, []string{ssh.KeyAlgoRSA})
}

func TestPinnedHostKeyFailsClosedWithoutLeakingPin(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatalf("create signer: %v", err)
	}
	pin := ssh.FingerprintSHA256(signer.PublicKey())
	if err := pinnedHostKey(pin)("ignored", nil, signer.PublicKey()); err != nil {
		t.Fatalf("matching pin rejected: %v", err)
	}
	wrongPin := "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	err = pinnedHostKey(wrongPin)("ignored", nil, signer.PublicKey())
	if !errors.Is(err, errHostKeyMismatch) {
		t.Fatalf("mismatched pin error = %v", err)
	}
	if strings.Contains(err.Error(), pin) || strings.Contains(err.Error(), wrongPin) {
		t.Fatalf("host-key error leaked a pin: %v", err)
	}
}

func TestOutputBufferEnforcesFrameLimit(t *testing.T) {
	buffer := newOutputBuffer(8)
	if _, err := buffer.Write([]byte("123456789")); err != nil {
		t.Fatalf("write: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := buffer.nextFrame(ctx); !errors.Is(err, errResponseLimit) {
		t.Fatalf("next frame error = %v, want response limit", err)
	}
}

func TestAuthenticationAndHostKeyFailuresAreSanitized(t *testing.T) {
	authServer := startTestServer(t, "fixture-user", "correct-password")
	config := NewConfig(authServer.address, "fixture-user", authServer.fingerprint)
	config.ConnectTimeout = 2 * time.Second
	config.HandshakeTimeout = 2 * time.Second
	config.AuthTimeout = 2 * time.Second
	_, err := Collect(context.Background(), config, []byte("wrong-password"))
	authServer.close()
	assertSessionFailure(t, err, sessioncontract.FailureAuthentication)
	if strings.Contains(err.Error(), "fixture-user") || strings.Contains(err.Error(), "wrong-password") {
		t.Fatalf("authentication error leaked context: %v", err)
	}

	keyServer := startTestServer(t, "fixture-user", "fixture-password")
	config = NewConfig(keyServer.address, "fixture-user", "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	config.ConnectTimeout = 2 * time.Second
	config.HandshakeTimeout = 2 * time.Second
	config.AuthTimeout = 2 * time.Second
	_, err = Collect(context.Background(), config, []byte("fixture-password"))
	keyServer.close()
	assertSessionFailure(t, err, sessioncontract.FailureHostKeyMismatch)
	if strings.Contains(err.Error(), keyServer.address) || strings.Contains(err.Error(), config.HostKeySHA256) {
		t.Fatalf("host-key error leaked context: %v", err)
	}
}

func TestHandshakeTimeoutIsClassified(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer connection.Close()
		time.Sleep(200 * time.Millisecond)
	}()

	config := NewConfig(listener.Addr().String(), "fixture-user", "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	config.ConnectTimeout = time.Second
	config.HandshakeTimeout = 50 * time.Millisecond
	config.AuthTimeout = time.Second
	_, err = Collect(context.Background(), config, []byte("fixture-password"))
	listener.Close()
	<-done
	var transportError *Error
	if !errors.As(err, &transportError) || transportError.Kind() != ErrorHandshakeTimeout {
		t.Fatalf("error = %v, want handshake_timeout", err)
	}
}

func TestAuthenticationTimeoutIsClassified(t *testing.T) {
	server := startTestServerWithAuthDelay(t, "fixture-user", "fixture-password", 200*time.Millisecond)
	config := NewConfig(server.address, "fixture-user", server.fingerprint)
	config.ConnectTimeout = time.Second
	config.HandshakeTimeout = time.Second
	config.AuthTimeout = 50 * time.Millisecond
	_, err := Collect(context.Background(), config, []byte("fixture-password"))
	server.close()
	var transportError *Error
	if !errors.As(err, &transportError) || transportError.Kind() != ErrorAuthenticationTimeout {
		t.Fatalf("error = %v, want authentication_timeout", err)
	}
}

func assertSessionFailure(t *testing.T, err error, kind sessioncontract.FailureKind) {
	t.Helper()
	var failure *sessioncontract.Failure
	if !errors.As(err, &failure) || failure.Kind() != kind {
		t.Fatalf("error = %v, want session failure %q", err, kind)
	}
}

func assertStringsEqual(t *testing.T, actual, expected []string) {
	t.Helper()
	if strings.Join(actual, "\x00") != strings.Join(expected, "\x00") {
		t.Fatalf("algorithms = %v, want %v", actual, expected)
	}
}

type testServer struct {
	address     string
	fingerprint string
	listener    net.Listener
	done        chan struct{}
}

func startTestServer(t *testing.T, username, password string) *testServer {
	return startTestServerOptions(t, username, password, 0, false)
}

func startTestServerWithAuthDelay(
	t *testing.T,
	username string,
	password string,
	authDelay time.Duration,
) *testServer {
	return startTestServerOptions(t, username, password, authDelay, false)
}

func startTestServerOptions(
	t *testing.T,
	username string,
	password string,
	authDelay time.Duration,
	arpPager bool,
) *testServer {
	return startTestServerBehavior(t, username, password, testServerBehavior{
		authDelay: authDelay,
		arpPager:  arpPager,
	})
}

type testServerBehavior struct {
	authDelay     time.Duration
	arpPager      bool
	deniedCommand string
	stallSetup    string
	onPhase       func(string)
}

func startTestServerBehavior(
	t *testing.T,
	username string,
	password string,
	behavior testServerBehavior,
) *testServer {
	t.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate server key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		t.Fatalf("create server signer: %v", err)
	}
	serverConfig := &ssh.ServerConfig{
		Config: ssh.Config{
			KeyExchanges: []string{ssh.KeyExchangeDHGEXSHA256},
			Ciphers:      []string{"aes128-ctr", "aes192-ctr", "aes256-ctr"},
			MACs:         []string{ssh.HMACSHA256, ssh.HMACSHA512},
		},
		PasswordCallback: func(metadata ssh.ConnMetadata, supplied []byte) (*ssh.Permissions, error) {
			if behavior.onPhase != nil {
				behavior.onPhase("auth")
			}
			if behavior.authDelay > 0 {
				time.Sleep(behavior.authDelay)
			}
			if metadata.User() != username || string(supplied) != password {
				return nil, errors.New("rejected")
			}
			return nil, nil
		},
	}
	serverConfig.AddHostKey(signer)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	server := &testServer{
		address:     listener.Addr().String(),
		fingerprint: ssh.FingerprintSHA256(signer.PublicKey()),
		listener:    listener,
		done:        make(chan struct{}),
	}
	go func() {
		defer close(server.done)
		connection, err := listener.Accept()
		if err != nil {
			return
		}
		defer connection.Close()
		sshConnection, channels, requests, err := ssh.NewServerConn(connection, serverConfig)
		if err != nil {
			return
		}
		defer sshConnection.Close()
		go ssh.DiscardRequests(requests)
		for newChannel := range channels {
			if newChannel.ChannelType() != "session" {
				_ = newChannel.Reject(ssh.UnknownChannelType, "unsupported")
				continue
			}
			if behavior.onPhase != nil {
				behavior.onPhase("session")
			}
			if behavior.stallSetup == "session" {
				_ = sshConnection.Wait()
				return
			}
			channel, channelRequests, err := newChannel.Accept()
			if err != nil {
				return
			}
			handleTestSession(channel, channelRequests, behavior)
			return
		}
	}()
	return server
}

func handleTestSession(channel ssh.Channel, requests <-chan *ssh.Request, behavior testServerBehavior) {
	defer channel.Close()
	for request := range requests {
		if behavior.onPhase != nil {
			behavior.onPhase(request.Type)
		}
		if request.Type == behavior.stallSetup {
			continue
		}
		switch request.Type {
		case "pty-req":
			request.Reply(true, nil)
		case "shell":
			request.Reply(true, nil)
			serveTestCLI(channel, behavior)
			return
		default:
			request.Reply(false, nil)
		}
	}
}

func serveTestCLI(channel ssh.Channel, behavior testServerBehavior) {
	_, _ = fmt.Fprint(channel, "ix-fixture%")
	configurationMode := false
	scanner := bufio.NewScanner(channel)
	for scanner.Scan() {
		command := strings.TrimSpace(scanner.Text())
		_, _ = fmt.Fprintf(channel, "%s\r\n", command)
		if command == behavior.deniedCommand {
			prompt := "ix-fixture%"
			if configurationMode {
				prompt = "ix-fixture(config)%"
			}
			_, _ = fmt.Fprintf(channel, "?Invalid command\r\n%s", prompt)
			continue
		}
		switch command {
		case commandConfigure:
			configurationMode = true
			_, _ = fmt.Fprint(channel, "ix-fixture(config)%")
		case commandPagerOff:
			_, _ = fmt.Fprint(channel, "ix-fixture(config)%")
		case commandLease:
			_, _ = fmt.Fprint(channel,
				"Leased to 0 clients\r\n"+
					"Codes : D - Dynamic assignments, F - Fixed assignments\r\n"+
					"IP Address      MAC Address       BoundTime LeaseTime State     Profile\r\n"+
					"ix-fixture(config)%",
			)
		case commandARP:
			if behavior.arpPager {
				_, _ = fmt.Fprint(channel, "--More--")
				continue
			}
			_, _ = fmt.Fprint(channel,
				"ARP Neighbor Cache - 0 dynamic, 2048 free, 0 garbage, 0 static\r\n"+
					"ARP neighbor cache auto refresh is disabled\r\n"+
					"Protocol Address  Hardware Address   TTL       Uptime       Interface\r\n"+
					"ix-fixture(config)%",
			)
		case commandExit:
			if configurationMode {
				configurationMode = false
				_, _ = fmt.Fprint(channel, "ix-fixture%")
			} else {
				return
			}
		default:
			_, _ = fmt.Fprint(channel, "ix-fixture(config)%")
		}
	}
}

func (server *testServer) close() {
	server.listener.Close()
	select {
	case <-server.done:
	case <-time.After(3 * time.Second):
	}
}

func TestSessionSetupIsBounded(t *testing.T) {
	for _, phase := range []string{"session", "pty-req", "shell"} {
		for _, overall := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/overall=%t", phase, overall), func(t *testing.T) {
				server := startTestServerBehavior(t, "fixture-user", "fixture-password", testServerBehavior{stallSetup: phase})
				defer server.close()
				config := NewConfig(server.address, "fixture-user", server.fingerprint)
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()
				client, err := dial(ctx, config, []byte("fixture-password"))
				if err != nil {
					t.Fatal(err)
				}
				defer client.close()
				config.CommandTimeout = 50 * time.Millisecond
				if overall {
					config.CommandTimeout = 2 * time.Second
					var stop context.CancelFunc
					ctx, stop = context.WithTimeout(ctx, 50*time.Millisecond)
					defer stop()
				}
				started := time.Now()
				_, err = client.collect(ctx, config)
				if err == nil {
					t.Fatal("stalled setup succeeded")
				}
				if time.Since(started) > time.Second {
					t.Fatal("setup exceeded its deadline")
				}
			})
		}
	}
}

func TestCancellationInterruptsSSHWaits(t *testing.T) {
	for _, phase := range []string{"auth", "session", "pty-req", "shell"} {
		t.Run(phase, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			reached := make(chan struct{}, 1)
			behavior := testServerBehavior{stallSetup: phase, onPhase: func(actual string) {
				if actual == phase {
					reached <- struct{}{}
				}
			}}
			if phase == "auth" {
				behavior.authDelay = time.Second
			}
			server := startTestServerBehavior(t, "fixture-user", "fixture-password", behavior)
			defer server.close()
			config := NewConfig(server.address, "fixture-user", server.fingerprint)
			done := make(chan error, 1)
			go func() { _, err := Collect(ctx, config, []byte("fixture-password")); done <- err }()
			select {
			case <-reached:
			case <-time.After(3 * time.Second):
				t.Fatal("phase not reached")
			}
			cancel()
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("canceled collection succeeded")
				}
				var failure *sessioncontract.Failure
				if errors.As(err, &failure) && failure.Kind() == sessioncontract.FailureAuthentication {
					t.Fatal("cancellation was classified as rejected credentials")
				}
			case <-time.After(500 * time.Millisecond):
				t.Fatal("cancellation did not interrupt SSH wait")
			}
		})
	}
}

func TestCancellationInterruptsHandshake(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			accepted <- conn
		}
	}()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	config := NewConfig(listener.Addr().String(), "fixture-user", "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	done := make(chan error, 1)
	go func() { _, err := Collect(ctx, config, []byte("fixture-password")); done <- err }()
	var conn net.Conn
	select {
	case conn = <-accepted:
	case <-time.After(3 * time.Second):
		t.Fatal("connection not accepted")
	}
	defer conn.Close()
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("canceled handshake succeeded")
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("handshake ignored cancellation")
	}
}
