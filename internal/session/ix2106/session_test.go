package ix2106

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	parser "github.com/takanao14/dhcp-lease-observer/internal/parser/ix2106"
)

type contractFixture struct {
	ConnectionEvent FailureKind     `json:"connection_event"`
	CommandEvent    FailureKind     `json:"command_event"`
	Command         string          `json:"command"`
	TerminalEvent   TerminalEvent   `json:"terminal_event"`
	ExpectedCommand string          `json:"expected_command"`
	Transcript      string          `json:"transcript"`
	ExpectedFailure FailureContract `json:"expected_failure"`
}

func TestExtractCompleteCommandBodyParsesLease(t *testing.T) {
	transcript := readFixture(t, filepath.Join("ix2106", "normal-lease.txt"))
	body, err := ExtractCompleteCommandBody(transcript, TerminalEOF, "show ip dhcp lease")
	if err != nil {
		t.Fatalf("extract complete body: %v", err)
	}
	if strings.Contains(string(body), "ix-fixture(config)%") {
		t.Fatal("body retained config prompt")
	}
	table, err := parser.ParseLease(strings.NewReader(string(body)))
	if err != nil {
		t.Fatalf("parse extracted body: %v", err)
	}
	if table.ReportedCount != 24 {
		t.Fatalf("reported count = %d, want 24", table.ReportedCount)
	}
}

func TestExtractCompleteCommandBodyRemovesExactEcho(t *testing.T) {
	transcript := readFixture(t, filepath.Join("session", "echoed-lease.txt"))
	body, err := ExtractCompleteCommandBody(transcript, TerminalEOF, "show ip dhcp lease")
	if err != nil {
		t.Fatalf("extract echoed body: %v", err)
	}
	if strings.Contains(string(body), "show ip dhcp lease") {
		t.Fatal("body retained exact command echo")
	}
	if _, err := parser.ParseLease(strings.NewReader(string(body))); err != nil {
		t.Fatalf("parse extracted body: %v", err)
	}
}

func TestPromptWinsOverTerminalEvent(t *testing.T) {
	transcript := readFixture(t, filepath.Join("ix2106", "empty-lease.txt"))
	body, err := ExtractCompleteCommandBody(transcript, TerminalTimeout, "")
	if err != nil {
		t.Fatalf("complete body rejected after timeout: %v", err)
	}
	if _, err := parser.ParseLease(strings.NewReader(string(body))); err != nil {
		t.Fatalf("parse extracted body: %v", err)
	}
}

func TestExtractClassifiesAuthorizationFailureAndKeepsOnlyCommand(t *testing.T) {
	transcript := []byte("show ip dhcp lease\r\n?Invalid command\r\nix-fixture(config)%")
	_, err := ExtractCompleteCommandBody(transcript, TerminalEOF, "show ip dhcp lease")
	var failure *Failure
	if !errors.As(err, &failure) || failure.Kind() != FailureAuthorization {
		t.Fatalf("error = %v, want authorization failure", err)
	}
	if failure.Command() != "show ip dhcp lease" || strings.Contains(failure.Error(), "Invalid command") {
		t.Fatalf("authorization failure retained unsafe detail: %#v, %v", failure, failure)
	}
}

func TestFramingFailuresMatchStage1Contracts(t *testing.T) {
	tests := []struct {
		name string
		file string
	}{
		{name: "unexpected EOF", file: "unexpected-eof.json"},
		{name: "timeout", file: "timeout.json"},
		{name: "prompt mismatch", file: "prompt-mismatch.json"},
		{name: "command echo mismatch", file: "command-echo-mismatch.json"},
		{name: "pager detected", file: "pager-detected.json"},
		{name: "config occupied", file: "config-occupied.json"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := readContractFixture(t, test.file)
			transcriptPath := filepath.Clean(filepath.Join("session", fixture.Transcript))
			transcript := readFixture(t, transcriptPath)
			_, err := ExtractCompleteCommandBody(
				transcript,
				fixture.TerminalEvent,
				fixture.ExpectedCommand,
			)
			assertFailureContract(t, err, fixture.ExpectedFailure)
		})
	}
}

func TestConnectionAndCommandFailuresMatchStage1Contracts(t *testing.T) {
	connectionCases := []string{"authentication-failed.json", "host-key-mismatch.json"}
	for _, name := range connectionCases {
		t.Run(name, func(t *testing.T) {
			fixture := readContractFixture(t, name)
			failure, err := ConnectionFailure(fixture.ConnectionEvent)
			if err != nil {
				t.Fatalf("create connection failure: %v", err)
			}
			if !reflect.DeepEqual(failure.Contract(), fixture.ExpectedFailure) {
				t.Fatalf("contract = %#v, want %#v", failure.Contract(), fixture.ExpectedFailure)
			}
		})
	}

	fixture := readContractFixture(t, "authorization-failed.json")
	failure, err := CommandFailure(fixture.CommandEvent, fixture.Command)
	if err != nil {
		t.Fatalf("create command failure: %v", err)
	}
	if !reflect.DeepEqual(failure.Contract(), fixture.ExpectedFailure) {
		t.Fatalf("contract = %#v, want %#v", failure.Contract(), fixture.ExpectedFailure)
	}
}

func TestParserFailureMatchesStage1ContractAndRedactsDetails(t *testing.T) {
	fixture := readContractFixture(t, "parse-failed.json")
	sourceError := errors.New("rejected row contains 192.0.2.99 and 02:00:00:00:00:99")
	failure, err := ParserFailure(sourceError)
	if err != nil {
		t.Fatalf("create parser failure: %v", err)
	}
	if !reflect.DeepEqual(failure.Contract(), fixture.ExpectedFailure) {
		t.Fatalf("contract = %#v, want %#v", failure.Contract(), fixture.ExpectedFailure)
	}
	if strings.Contains(failure.Error(), "192.0.2") || strings.Contains(failure.Error(), "02:00") {
		t.Fatalf("failure leaked parser details: %v", failure)
	}
}

func TestUnsupportedFailureKindsAreRejected(t *testing.T) {
	if _, err := ConnectionFailure(FailureTimeout); err == nil {
		t.Fatal("unsupported connection failure kind was accepted")
	}
	if _, err := CommandFailure(FailureParse, "show ip dhcp lease"); err == nil {
		t.Fatal("unsupported command failure kind was accepted")
	}
	if _, err := CommandFailure(FailureAuthorization, "show running-config secret"); err == nil {
		t.Fatal("non-allowlisted command was accepted")
	}
	if _, err := FramingFailure(FailureAuthentication); err == nil {
		t.Fatal("unsupported framing failure kind was accepted")
	}
	if _, err := ParserFailure(nil); err == nil {
		t.Fatal("nil parser error was accepted")
	}
}

func assertFailureContract(t *testing.T, err error, expected FailureContract) {
	t.Helper()
	var failure *Failure
	if !errors.As(err, &failure) {
		t.Fatalf("error = %v, want *Failure", err)
	}
	if !reflect.DeepEqual(failure.Contract(), expected) {
		t.Fatalf("contract = %#v, want %#v", failure.Contract(), expected)
	}
}

func readContractFixture(t *testing.T, name string) contractFixture {
	t.Helper()
	data := readFixture(t, filepath.Join("session", name))
	var fixture contractFixture
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatalf("unmarshal contract fixture: %v", err)
	}
	return fixture
}

func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "..", "testdata", name))
	if err != nil {
		t.Fatalf("read fixture %q: %v", name, err)
	}
	return data
}
