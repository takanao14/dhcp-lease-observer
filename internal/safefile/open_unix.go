// Package safefile opens security-sensitive files without following a final
// path component that is a symlink.
package safefile

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

var ErrUnsafeFile = errors.New("unsafe file")

// OpenRegular opens path and validates the opened descriptor, closing the
// Lstat/Open race that would otherwise allow the path to be replaced.
func OpenRegular(path string, forbiddenPermissions os.FileMode, maxBytes int64) (*os.File, error) {
	if path == "" || maxBytes < 0 {
		return nil, ErrUnsafeFile
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		if errors.Is(err, unix.ELOOP) {
			return nil, ErrUnsafeFile
		}
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = unix.Close(fd)
		return nil, ErrUnsafeFile
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&forbiddenPermissions != 0 || info.Size() > maxBytes {
		_ = file.Close()
		return nil, ErrUnsafeFile
	}
	return file, nil
}
