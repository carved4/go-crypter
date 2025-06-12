package runpe

import (
	"unsafe"

	"github.com/Binject/debug/pe"
)

// ApplyRelocations applies base relocations in-place using unsafe pointer arithmetic
// This version uses direct memory access for speed and inlines relocation types.
func ApplyRelocations(peFile *pe.File, imageData []byte, oldBase, newBase uint64) error {
	// Locate the base relocation directory
	var dirEntry *pe.DataDirectory
	switch oh := peFile.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		if n := len(oh.DataDirectory); n > pe.IMAGE_DIRECTORY_ENTRY_BASERELOC {
			dirEntry = &oh.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_BASERELOC]
		}
	case *pe.OptionalHeader64:
		if n := len(oh.DataDirectory); n > pe.IMAGE_DIRECTORY_ENTRY_BASERELOC {
			dirEntry = &oh.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_BASERELOC]
		}
	default:
		return nil // unsupported header or no reloc
	}
	if dirEntry == nil || dirEntry.VirtualAddress == 0 || dirEntry.Size < 8 {
		return nil // nothing to do
	}

	start := int(dirEntry.VirtualAddress)
	size := int(dirEntry.Size)
	end := start + size
	buf := imageData

	// Iterate each relocation block
	for pos := start; pos < end; {
		pageRVA := *(*uint32)(unsafe.Pointer(&buf[pos]))
		blockSize := *(*uint32)(unsafe.Pointer(&buf[pos+4]))
		if blockSize < 8 {
			break
		}
		entries := (blockSize - 8) / 2

		// Process each entry
		head := pos + 8
		for i := uint32(0); i < entries; i++ {
			off := head + int(i*2)
			entry := *(*uint16)(unsafe.Pointer(&buf[off]))
			typ := entry >> 12
			relOff := uint32(entry & 0x0FFF)
			loc := int(pageRVA + relOff)
			ptr := unsafe.Pointer(&buf[loc])

			switch typ {
			case pe.IMAGE_REL_BASED_HIGHLOW: // 3
				orig := *(*uint32)(ptr)
				*(*uint32)(ptr) = (orig - uint32(oldBase)) + uint32(newBase)
			case pe.IMAGE_REL_BASED_DIR64: // 10
				orig64 := *(*uint64)(ptr)
				*(*uint64)(ptr) = (orig64 - oldBase) + newBase
			}
		}

		pos += int(blockSize)
	}
	return nil
}
