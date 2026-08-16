// Package atomicfile writes bounded files with durable atomic replacement.
package atomicfile

import (
	"errors"
	"io"
	"os"
	"path/filepath"
)

var ErrSizeLimit = errors.New("atomic file size limit exceeded")

func Write(
	path string,
	mode os.FileMode,
	maxBytes int64,
	write func(io.Writer) error,
) error {
	if path == "" || mode.Perm() != mode || maxBytes <= 0 || write == nil {
		return errors.New("invalid atomic file options")
	}
	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, ".atomic-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	keepTemporary := true
	defer func() {
		if keepTemporary {
			_ = os.Remove(temporaryPath)
		}
	}()

	if err := temporary.Chmod(mode); err != nil {
		temporary.Close()
		return err
	}
	limited := &limitWriter{writer: temporary, remaining: maxBytes}
	if err := write(limited); err != nil {
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
	if err := os.Rename(temporaryPath, path); err != nil {
		return err
	}
	keepTemporary = false

	directoryHandle, err := os.Open(directory)
	if err != nil {
		return err
	}
	defer directoryHandle.Close()
	return directoryHandle.Sync()
}

type limitWriter struct {
	writer    io.Writer
	remaining int64
}

func (writer *limitWriter) Write(data []byte) (int, error) {
	if int64(len(data)) > writer.remaining {
		return 0, ErrSizeLimit
	}
	written, err := writer.writer.Write(data)
	writer.remaining -= int64(written)
	if written != len(data) && err == nil {
		return written, io.ErrShortWrite
	}
	return written, err
}
