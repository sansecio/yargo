//go:build !js && !windows

package scanner

import (
	"os"
	"time"

	"golang.org/x/sys/unix"
)

// ScanFile scans a file for matching rules using memory-mapped I/O.
//
// On Unix systems (Linux, macOS, BSD), the file is mapped into memory using
// mmap(2), allowing efficient zero-copy scanning of large files without
// loading the entire file into the Go heap.
//
// For empty files, ScanMem is called with nil data.
func (r *Rules) ScanFile(filename string, flags ScanFlags, timeout time.Duration, cb ScanCallback) error {
	f, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()

	fi, err := f.Stat()
	if err != nil {
		return err
	}

	size := fi.Size()
	if size == 0 {
		return r.ScanMem(nil, flags, timeout, cb)
	}

	data, err := unix.Mmap(int(f.Fd()), 0, int(size), unix.PROT_READ, unix.MAP_SHARED)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Munmap(data) }()

	return r.ScanMem(data, flags, timeout, cb)
}
