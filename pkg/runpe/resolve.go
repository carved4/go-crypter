package runpe

import (
	"strconv"
	"syscall"
	"unsafe"
	"fmt"
	"github.com/Binject/debug/pe"
)

// ResolveImports patches the import address table in-place using direct memory access.
// This version is optimized for AMD64 and unifies 32/64-bit handling with minimal overhead.
func ResolveImports(peFile *pe.File, baseAddress uintptr) error {
	// Locate import directory
	var dir *pe.DataDirectory
	switch oh := peFile.OptionalHeader.(type) {
	case *pe.OptionalHeader64:
		if len(oh.DataDirectory) > pe.IMAGE_DIRECTORY_ENTRY_IMPORT {
			dir = &oh.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_IMPORT]
		}
	case *pe.OptionalHeader32:
		if len(oh.DataDirectory) > pe.IMAGE_DIRECTORY_ENTRY_IMPORT {
			dir = &oh.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_IMPORT]
		}
	}
	if dir == nil || dir.VirtualAddress == 0 || dir.Size < 20 {
		return nil // no imports
	}

	// Get size of image to ensure we don't go out of bounds
	var sizeOfImage uint32
	switch oh := peFile.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		sizeOfImage = oh.SizeOfImage
	case *pe.OptionalHeader64:
		sizeOfImage = oh.SizeOfImage
	default:
		return fmt.Errorf("unsupported PE optional header type")
	}

	// Base pointer now directly uses the baseAddress
	start := int(dir.VirtualAddress)

	// Determine pointer size for target machine
	ptrSize := 8
	if peFile.Machine != pe.IMAGE_FILE_MACHINE_AMD64 {
		ptrSize = 4
	}

	// Iterate descriptors (20 bytes each)
	for off := 0; ; off += 20 {
		descPtr := unsafe.Pointer(baseAddress + uintptr(start+off))

		// Name RVA at offset 12
		nameRVA := *(*uint32)(unsafe.Pointer(uintptr(descPtr) + 12))
		if nameRVA == 0 {
			break // end of import descriptors
		}

		// IAT and ILT RVAs
		firstThunk := *(*uint32)(unsafe.Pointer(uintptr(descPtr) + 16))
		origThunk := *(*uint32)(unsafe.Pointer(descPtr))
		thunkRVA := origThunk
		if thunkRVA == 0 {
			thunkRVA = firstThunk
		}

		// Read DLL name
		dllData := (*[1 << 20]byte)(unsafe.Pointer(baseAddress + uintptr(nameRVA))) // assume name <1MB
		var i int
		for dllData[i] != 0 {
			i++
		}
		dllName := string(dllData[:i])

		// Load DLL once per descriptor
		hMod, err := syscall.LoadLibrary(dllName)
		if err != nil {
			return fmt.Errorf("LoadLibrary %s failed: %w", dllName, err)
		}

		// Iterate each thunk entry
		for j := 0; ; j += ptrSize {
			tEntryRVA := thunkRVA + uint32(j)
			iatEntryRVA := firstThunk + uint32(j)

			// Bounds check
			if int(tEntryRVA)+ptrSize > int(sizeOfImage) {
				break
			}

			// Read thunk
			var thunkVal uint64
			if ptrSize == 8 {
				thunkVal = *(*uint64)(unsafe.Pointer(baseAddress + uintptr(tEntryRVA)))
			} else {
				thunkVal = uint64(*(*uint32)(unsafe.Pointer(baseAddress + uintptr(tEntryRVA))))
			}
			if thunkVal == 0 {
				break // end of imports for this DLL
			}

			// Resolve by ordinal if high bit set
			var procAddr uintptr
			if (ptrSize == 8 && (thunkVal>>63) != 0) || (ptrSize == 4 && (thunkVal>>31) != 0) {
				ord := uint16(thunkVal & 0xFFFF)
				procAddr, err = syscall.GetProcAddress(hMod, "#"+strconv.Itoa(int(ord)))
			} else {
				// Name RVA + skip hint (2 bytes)
				nameOff := uint32(thunkVal&0xFFFFFFFF) + 2
				nameData := (*[1 << 20]byte)(unsafe.Pointer(baseAddress + uintptr(nameOff)))
				var k int
				for nameData[k] != 0 {
					k++
				}
				procAddr, err = syscall.GetProcAddress(hMod, string(nameData[:k]))
			}
			if err != nil {
				return fmt.Errorf("GetProcAddress failed: %w", err)
			}

			// Write IAT entry directly to the memory using the baseAddress
			if ptrSize == 8 {
				*(*uint64)(unsafe.Pointer(baseAddress + uintptr(iatEntryRVA))) = uint64(procAddr)
			} else {
				*(*uint32)(unsafe.Pointer(baseAddress + uintptr(iatEntryRVA))) = uint32(procAddr)
			}
		}
	}

	return nil
}