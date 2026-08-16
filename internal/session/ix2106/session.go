// Package ix2106 defines the prompt-driven IX2106 session boundary.
package ix2106

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

type FailureKind string

const (
	FailureUnexpectedEOF       FailureKind = "unexpected_eof"
	FailureTimeout             FailureKind = "timeout"
	FailureAuthentication      FailureKind = "authentication_failed"
	FailureAuthorization       FailureKind = "authorization_failed"
	FailureHostKeyMismatch     FailureKind = "host_key_mismatch"
	FailureConfigOccupied      FailureKind = "config_occupied"
	FailurePagerDetected       FailureKind = "pager_detected"
	FailurePromptMismatch      FailureKind = "prompt_mismatch"
	FailureParse               FailureKind = "parse_failed"
	FailureCommandEchoMismatch FailureKind = "command_echo_mismatch"
)

type TerminalEvent string

const (
	TerminalEOF     TerminalEvent = "eof"
	TerminalTimeout TerminalEvent = "timeout"
)

type FailureContract struct {
	Kind           FailureKind `json:"kind"`
	Retryable      bool        `json:"retryable"`
	SnapshotUsable bool        `json:"snapshot_usable"`
	EmitRemovals   bool        `json:"emit_removals"`
}

// Failure is a sanitized session error. It never retains source output,
// credentials, addresses, host keys, or parser details.
type Failure struct {
	kind      FailureKind
	retryable bool
}

func (failure *Failure) Error() string {
	if message, ok := failureMessages[failure.kind]; ok {
		return message
	}
	return "IX2106 session failed"
}

func (failure *Failure) Kind() FailureKind {
	return failure.kind
}

func (failure *Failure) Retryable() bool {
	return failure.retryable
}

func (failure *Failure) Contract() FailureContract {
	return FailureContract{
		Kind:           failure.kind,
		Retryable:      failure.retryable,
		SnapshotUsable: false,
		EmitRemovals:   false,
	}
}

var (
	configPromptPattern = regexp.MustCompile(`^[A-Za-z0-9._-]+\(config\)%$`)
	promptLikePattern   = regexp.MustCompile(`^[A-Za-z0-9._-]+(?:\(config\))?[#%]$`)
	commandEchoPattern  = regexp.MustCompile(`(?i)^(?:show|terminal|configure|exit)(?:\s|$)`)

	failureMessages = map[FailureKind]string{
		FailureUnexpectedEOF:       "SSH channel reached EOF before the expected config prompt",
		FailureTimeout:             "command deadline expired before the expected config prompt",
		FailureAuthentication:      "SSH authentication was rejected",
		FailureAuthorization:       "authenticated SSH user is not authorized to run a fixed command",
		FailureHostKeyMismatch:     "SSH host key did not match the pinned identity",
		FailureConfigOccupied:      "IX2106 config process is occupied by another session",
		FailurePagerDetected:       "pager marker appeared after paging was disabled",
		FailurePromptMismatch:      "session ended at a prompt other than the expected Monitor config prompt",
		FailureParse:               "complete command output did not match the supported schema",
		FailureCommandEchoMismatch: "received command echo did not match the fixed command",
	}
)

func ConnectionFailure(kind FailureKind) (*Failure, error) {
	if kind != FailureAuthentication && kind != FailureHostKeyMismatch {
		return nil, fmt.Errorf("unsupported connection failure kind: %q", kind)
	}
	return newFailure(kind), nil
}

func CommandFailure(kind FailureKind) (*Failure, error) {
	if kind != FailureAuthorization {
		return nil, fmt.Errorf("unsupported command failure kind: %q", kind)
	}
	return newFailure(kind), nil
}

func FramingFailure(kind FailureKind) (*Failure, error) {
	switch kind {
	case FailureUnexpectedEOF,
		FailureTimeout,
		FailureConfigOccupied,
		FailurePagerDetected,
		FailurePromptMismatch,
		FailureCommandEchoMismatch:
		return newFailure(kind), nil
	default:
		return nil, fmt.Errorf("unsupported framing failure kind: %q", kind)
	}
}

// ParserFailure discards the parser error details at the session boundary.
func ParserFailure(err error) (*Failure, error) {
	if err == nil {
		return nil, errors.New("parser failure requires a non-nil error")
	}
	return newFailure(FailureParse), nil
}

// ExtractCompleteCommandBody accepts command output only after the expected
// Monitor configuration prompt. One exact fixed-command echo is removed.
func ExtractCompleteCommandBody(
	transcript []byte,
	event TerminalEvent,
	expectedCommand string,
) ([]byte, error) {
	text := strings.ReplaceAll(string(transcript), "\r\n", "\n")
	if strings.Contains(text, "--More--") {
		return nil, newFailure(FailurePagerDetected)
	}
	if strings.Contains(strings.ToLower(text), "config process is occupied") {
		return nil, newFailure(FailureConfigOccupied)
	}

	lines := strings.Split(text, "\n")
	last := lastContentLine(lines)
	if last >= 0 && configPromptPattern.MatchString(strings.TrimSpace(lines[last])) {
		body := append([]string(nil), lines[:last]...)
		if expectedCommand != "" {
			first := firstContentLine(body)
			if first >= 0 {
				echo := strings.TrimSpace(body[first])
				switch {
				case echo == expectedCommand:
					body = append(body[:first], body[first+1:]...)
				case commandEchoPattern.MatchString(echo):
					return nil, newFailure(FailureCommandEchoMismatch)
				}
			}
		}
		return []byte(strings.Join(body, "\n")), nil
	}

	if last >= 0 && promptLikePattern.MatchString(strings.TrimSpace(lines[last])) {
		return nil, newFailure(FailurePromptMismatch)
	}
	switch event {
	case TerminalEOF:
		return nil, newFailure(FailureUnexpectedEOF)
	case TerminalTimeout:
		return nil, newFailure(FailureTimeout)
	default:
		return nil, errors.New("unsupported terminal event")
	}
}

func firstContentLine(lines []string) int {
	for index, line := range lines {
		if strings.TrimSpace(line) != "" {
			return index
		}
	}
	return -1
}

func lastContentLine(lines []string) int {
	for index := len(lines) - 1; index >= 0; index-- {
		if strings.TrimSpace(lines[index]) != "" {
			return index
		}
	}
	return -1
}

func newFailure(kind FailureKind) *Failure {
	retryable := kind == FailureUnexpectedEOF || kind == FailureTimeout || kind == FailureConfigOccupied
	return &Failure{kind: kind, retryable: retryable}
}
