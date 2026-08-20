package safefile

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestOpenRegularValidatesOpenedDescriptor(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "input")
	if err := os.WriteFile(path, []byte("fixture"), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	file, err := OpenRegular(path, 0o077, 32)
	if err != nil {
		t.Fatalf("open regular file: %v", err)
	}
	file.Close()

	link := filepath.Join(directory, "link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatalf("create symlink: %v", err)
	}
	if _, err := OpenRegular(link, 0o077, 32); !errors.Is(err, ErrUnsafeFile) {
		t.Fatalf("symlink error = %v, want ErrUnsafeFile", err)
	}
}

func TestOpenRegularRejectsPermissionsAndSize(t *testing.T) {
	directory := t.TempDir()
	unsafeMode := filepath.Join(directory, "unsafe-mode")
	if err := os.WriteFile(unsafeMode, []byte("fixture"), 0o644); err != nil {
		t.Fatalf("write mode fixture: %v", err)
	}
	if _, err := OpenRegular(unsafeMode, 0o077, 32); !errors.Is(err, ErrUnsafeFile) {
		t.Fatalf("mode error = %v, want ErrUnsafeFile", err)
	}

	oversized := filepath.Join(directory, "oversized")
	if err := os.WriteFile(oversized, []byte("fixture"), 0o600); err != nil {
		t.Fatalf("write size fixture: %v", err)
	}
	if _, err := OpenRegular(oversized, 0o077, 3); !errors.Is(err, ErrUnsafeFile) {
		t.Fatalf("size error = %v, want ErrUnsafeFile", err)
	}
}
