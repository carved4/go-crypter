package runpe

import (
	"fmt"
	"unsafe"

	"github.com/Binject/debug/pe"
	"github.com/carved4/go-direct-syscall"
)

// ExecuteTLSCallbacks locates and invokes TLS callbacks directly via unsafe pointer arithmetic.
// It handles both 32-bit and 64-bit images in a single streamlined loop.
func ExecuteTLSCallbacks(peFile *pe.File, base uintptr) error {
	// Locate TLS data directory
	var dir *pe.DataDirectory
	switch h := peFile.OptionalHeader.(type) {
	case *pe.OptionalHeader64:
		if len(h.DataDirectory) > pe.IMAGE_DIRECTORY_ENTRY_TLS {
			dir = &h.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_TLS]
		}
	case *pe.OptionalHeader32:
		if len(h.DataDirectory) > pe.IMAGE_DIRECTORY_ENTRY_TLS {
			dir = &h.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_TLS]
		}
	}
	if dir == nil || dir.VirtualAddress == 0 || dir.Size < 8 {
		return nil // no TLS callbacks
	}

	// Calculate pointer to TLS directory in memory
	tlsBase := base + uintptr(dir.VirtualAddress)

	// Read AddressOfCallBacks (RVA) directly
	var rva uint64
	if peFile.Machine == pe.IMAGE_FILE_MACHINE_AMD64 {
		rva = *(*uint64)(unsafe.Pointer(tlsBase + 24)) // offset 24
	} else {
		rva = uint64(*(*uint32)(unsafe.Pointer(tlsBase + 12))) // offset 12
	}
	if rva == 0 {
		return nil
	}

	// Iterate callback pointers
	ptr := base + uintptr(rva)
	const maxCallbacks = 128
	for i := 0; i < maxCallbacks; i++ {
		// Load function pointer
		var fn uintptr
		if peFile.Machine == pe.IMAGE_FILE_MACHINE_AMD64 {
			fn = uintptr(*(*uint64)(unsafe.Pointer(ptr)))
			ptr += 8
		} else {
			fn = uintptr(*(*uint32)(unsafe.Pointer(ptr)))
			ptr += 4
		}
		if fn == 0 {
			return nil // end of callbacks
		}

		// Invoke TLS callback using go-direct-syscall: (LPVOID DllBase, DWORD Reason, LPVOID Reserved)
		_, err := winapi.DirectSyscall("", fn, base, 1, 0) // 1 == DLL_PROCESS_ATTACH
		if err != nil {
			return fmt.Errorf("TLS callback at 0x%x failed: %w", fn, err)
		}
	}

	return fmt.Errorf("TLS callback limit (%d) exceeded", maxCallbacks)
}