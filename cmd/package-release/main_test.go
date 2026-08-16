package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestWriteArchiveIsDeterministicAndContainsOnlyReleaseFiles(t *testing.T) {
	directory := t.TempDir()
	binaryPath := filepath.Join(directory, binaryName)
	if err := os.WriteFile(binaryPath, []byte("fixture-binary"), 0o755); err != nil {
		t.Fatalf("write binary: %v", err)
	}
	first := filepath.Join(directory, "first.tar.gz")
	second := filepath.Join(directory, "second.tar.gz")
	for _, path := range []string{first, second} {
		if err := writeArchive(path, binaryPath, []byte("fixture-license")); err != nil {
			t.Fatalf("write archive: %v", err)
		}
	}
	firstData, err := os.ReadFile(first)
	if err != nil {
		t.Fatalf("read first archive: %v", err)
	}
	secondData, err := os.ReadFile(second)
	if err != nil {
		t.Fatalf("read second archive: %v", err)
	}
	if !bytes.Equal(firstData, secondData) {
		t.Fatal("archives are not deterministic")
	}
	if names := archiveNames(t, firstData); !reflect.DeepEqual(names, []string{"LICENSE", binaryName}) {
		t.Fatalf("archive names = %v", names)
	}
}

func TestVersionPattern(t *testing.T) {
	for _, version := range []string{"v0.1.0", "v1.2.3-rc.1"} {
		if !versionPattern.MatchString(version) {
			t.Fatalf("valid version rejected: %s", version)
		}
	}
	for _, version := range []string{"", "0.1.0", "v1", "v1.2.3/bad"} {
		if versionPattern.MatchString(version) {
			t.Fatalf("invalid version accepted: %s", version)
		}
	}
}

func archiveNames(t *testing.T, data []byte) []string {
	t.Helper()
	compressed, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("open gzip: %v", err)
	}
	defer compressed.Close()
	archive := tar.NewReader(compressed)
	var names []string
	for {
		header, err := archive.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("read tar: %v", err)
		}
		names = append(names, header.Name)
	}
	return names
}
