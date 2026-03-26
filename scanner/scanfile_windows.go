//go:build windows

package scanner

import (
	"os"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// ScanFile scans a file for matching rules using Windows memory-mapped I/O.
//
// On Windows, the file is mapped into memory using CreateFileMapping and
// MapViewOfFile, providing the same zero-copy scanning behavior as the Unix
// mmap implementation. This avoids loading the entire file into the Go heap,
// which is important for scanning large binaries or archives.
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

	// Create a read-only file mapping object.
	handle, err := windows.CreateFileMapping(
		windows.Handle(f.Fd()),
		nil,
		windows.PAGE_READONLY,
		uint32(size>>32),
		uint32(size),
		nil,
	)
	if err != nil {
		return err
	}
	defer func() { _ = windows.CloseHandle(handle) }()

	// Map a read-only view of the file into memory.
	addr, err := windows.MapViewOfFile(
		handle,
		windows.FILE_MAP_READ,
		0,
		0,
		uintptr(size),
	)
	if err != nil {
		return err
	}
	defer func() { _ = windows.UnmapViewOfFile(addr) }()

	// Create a byte slice backed by the mapped memory region.
	// This avoids a copy — the slice points directly at the mapped pages.
	data := unsafe.Slice((*byte)(unsafe.Pointer(addr)), size)

	return r.ScanMem(data, flags, timeout, cb)
}
