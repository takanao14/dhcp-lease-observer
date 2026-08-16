// Command package-release creates deterministic cross-compiled release archives.
package main

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

const binaryName = "dhcp-lease-observer"

var versionPattern = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z][0-9A-Za-z.-]*)?$`)

func main() {
	version := flag.String("version", "", "release version such as v0.1.0")
	outputDirectory := flag.String("output-dir", "dist", "artifact output directory")
	flag.Parse()
	if flag.NArg() != 0 || !versionPattern.MatchString(*version) {
		fmt.Fprintln(os.Stderr, "a valid --version is required and positional arguments are not accepted")
		os.Exit(2)
	}
	if err := buildRelease(context.Background(), *version, *outputDirectory); err != nil {
		fmt.Fprintln(os.Stderr, "release packaging failed")
		os.Exit(1)
	}
}

func buildRelease(ctx context.Context, version, outputDirectory string) error {
	if !versionPattern.MatchString(version) || !filepath.IsLocal(outputDirectory) || filepath.Clean(outputDirectory) != outputDirectory {
		return fmt.Errorf("invalid release input")
	}
	license, err := os.ReadFile("LICENSE")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(outputDirectory, 0o755); err != nil {
		return err
	}
	architectures := []string{"amd64", "arm64"}
	checksums := make([]string, 0, len(architectures))
	for _, architecture := range architectures {
		temporaryDirectory, err := os.MkdirTemp("", "dhcp-lease-observer-release-")
		if err != nil {
			return err
		}
		binaryPath := filepath.Join(temporaryDirectory, binaryName)
		err = buildBinary(ctx, version, architecture, binaryPath)
		if err == nil {
			archiveName := fmt.Sprintf("%s_%s_linux_%s.tar.gz", binaryName, version, architecture)
			archivePath := filepath.Join(outputDirectory, archiveName)
			err = writeArchive(archivePath, binaryPath, license)
			if err == nil {
				digest, digestErr := fileSHA256(archivePath)
				if digestErr != nil {
					err = digestErr
				} else {
					checksums = append(checksums, fmt.Sprintf("%x  %s", digest, archiveName))
				}
			}
		}
		_ = os.RemoveAll(temporaryDirectory)
		if err != nil {
			return err
		}
	}
	sort.Strings(checksums)
	return writeFileAtomic(filepath.Join(outputDirectory, "checksums.txt"), 0o644, []byte(strings.Join(checksums, "\n")+"\n"))
}

func buildBinary(ctx context.Context, version, architecture, destination string) error {
	command := exec.CommandContext(ctx, "go", "build", "-trimpath", "-ldflags", "-s -w -buildid= -X main.version="+version, "-o", destination, "./cmd/dhcp-lease-observer")
	command.Env = append(filteredEnvironment(os.Environ(), "GOOS", "GOARCH", "CGO_ENABLED"),
		"GOOS=linux", "GOARCH="+architecture, "CGO_ENABLED=0")
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	return command.Run()
}

func writeArchive(path, binaryPath string, license []byte) error {
	binary, err := os.ReadFile(binaryPath)
	if err != nil {
		return err
	}
	return writeAtomic(path, 0o644, func(writer io.Writer) error {
		compressed := gzip.NewWriter(writer)
		compressed.Header.ModTime = time.Unix(0, 0).UTC()
		compressed.Header.OS = 255
		archive := tar.NewWriter(compressed)
		entries := []struct {
			name string
			mode int64
			data []byte
		}{
			{name: "LICENSE", mode: 0o644, data: license},
			{name: binaryName, mode: 0o755, data: binary},
		}
		for _, entry := range entries {
			header := &tar.Header{
				Name: entry.name, Mode: entry.mode, Size: int64(len(entry.data)),
				ModTime: time.Unix(0, 0).UTC(), Typeflag: tar.TypeReg, Format: tar.FormatPAX,
			}
			if err := archive.WriteHeader(header); err != nil {
				return err
			}
			if _, err := archive.Write(entry.data); err != nil {
				return err
			}
		}
		if err := archive.Close(); err != nil {
			return err
		}
		return compressed.Close()
	})
}

func fileSHA256(path string) ([sha256.Size]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	defer file.Close()
	digest := sha256.New()
	if _, err := io.Copy(digest, file); err != nil {
		return [sha256.Size]byte{}, err
	}
	var result [sha256.Size]byte
	copy(result[:], digest.Sum(nil))
	return result, nil
}

func writeFileAtomic(path string, mode os.FileMode, data []byte) error {
	return writeAtomic(path, mode, func(writer io.Writer) error {
		_, err := writer.Write(data)
		return err
	})
}

func writeAtomic(path string, mode os.FileMode, write func(io.Writer) error) error {
	temporary, err := os.CreateTemp(filepath.Dir(path), ".release-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(mode); err != nil {
		temporary.Close()
		return err
	}
	if err := write(temporary); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporaryPath, path)
}

func filteredEnvironment(environment []string, names ...string) []string {
	blocked := make(map[string]struct{}, len(names))
	for _, name := range names {
		blocked[name] = struct{}{}
	}
	result := make([]string, 0, len(environment))
	for _, entry := range environment {
		name, _, _ := strings.Cut(entry, "=")
		if _, exists := blocked[name]; !exists {
			result = append(result, entry)
		}
	}
	return result
}
