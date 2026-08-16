package atomicfile

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWriteAtomicallyReplacesFileWithRequestedMode(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "output.txt")
	if err := os.WriteFile(path, []byte("old"), 0o600); err != nil {
		t.Fatalf("write old file: %v", err)
	}
	if err := Write(path, 0o640, 32, func(writer io.Writer) error {
		_, err := io.WriteString(writer, "new\n")
		return err
	}); err != nil {
		t.Fatalf("atomic write: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	if string(data) != "new\n" {
		t.Fatalf("output = %q, want new", data)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat output: %v", err)
	}
	if info.Mode().Perm() != 0o640 {
		t.Fatalf("mode = %o, want 640", info.Mode().Perm())
	}
	matches, err := filepath.Glob(filepath.Join(directory, ".atomic-*"))
	if err != nil {
		t.Fatalf("glob temporary files: %v", err)
	}
	if len(matches) != 0 {
		t.Fatalf("temporary files remain: %v", matches)
	}
}

func TestWriteFailurePreservesExistingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "output.txt")
	if err := os.WriteFile(path, []byte("last-good"), 0o600); err != nil {
		t.Fatalf("write old file: %v", err)
	}
	sentinel := errors.New("fixture failure")
	err := Write(path, 0o600, 32, func(writer io.Writer) error {
		_, _ = io.WriteString(writer, "partial")
		return sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("write error = %v, want sentinel", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read preserved file: %v", err)
	}
	if string(data) != "last-good" {
		t.Fatalf("existing file changed to %q", data)
	}
}

func TestWriteLimitPreservesExistingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "output.txt")
	if err := os.WriteFile(path, []byte("last-good"), 0o600); err != nil {
		t.Fatalf("write old file: %v", err)
	}
	err := Write(path, 0o600, 4, func(writer io.Writer) error {
		_, err := io.WriteString(writer, strings.Repeat("x", 5))
		return err
	})
	if !errors.Is(err, ErrSizeLimit) {
		t.Fatalf("write error = %v, want ErrSizeLimit", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read preserved file: %v", err)
	}
	if string(data) != "last-good" {
		t.Fatalf("existing file changed to %q", data)
	}
}
