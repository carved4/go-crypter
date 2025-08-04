package runshellalt

import (
	"fmt"
	"sort"
	"strings"
	"unsafe"

	"github.com/carved4/go-native-syscall"
)

type ProcessInfo struct {
	Pid  uint32
	Name string
}

func getProcessList() ([]ProcessInfo, error) {
	// First call to get required buffer size
	var returnLength uintptr
	status, err := winapi.NtQuerySystemInformation(
		winapi.SystemProcessInformation,
		nil,
		0,
		&returnLength,
	)
	
	if status != winapi.STATUS_INFO_LENGTH_MISMATCH && status != winapi.STATUS_BUFFER_TOO_SMALL {
		return nil, fmt.Errorf("failed to get buffer size: %s", winapi.FormatNTStatus(status))
	}
	
	// Allocate buffer with some extra space
	bufferSize := returnLength + 4096
	buffer := make([]byte, bufferSize)
	
	// Second call to get actual data
	status, err = winapi.NtQuerySystemInformation(
		winapi.SystemProcessInformation,
		unsafe.Pointer(&buffer[0]),
		bufferSize,
		&returnLength,
	)
	
	if err != nil {
		return nil, fmt.Errorf("NtQuerySystemInformation error: %v", err)
	}
	
	if status != winapi.STATUS_SUCCESS {
		return nil, fmt.Errorf("NtQuerySystemInformation failed: %s", winapi.FormatNTStatus(status))
	}
	
	var processes []ProcessInfo
	offset := uintptr(0)
	processCount := 0
	
	for {
		// Safety check to prevent buffer overflow
		if offset >= uintptr(len(buffer)) {
			break
		}
		
		// Get current process entry
		processInfo := (*winapi.SYSTEM_PROCESS_INFORMATION)(unsafe.Pointer(&buffer[offset]))
		processCount++
		
		// Extract process name from UNICODE_STRING
		var processName string
		if processInfo.ImageName.Buffer != nil && processInfo.ImageName.Length > 0 {
			maxChars := int(processInfo.ImageName.Length / 2) // Length is in bytes, convert to chars
			if maxChars > 260 { // MAX_PATH protection
				maxChars = 260
			}
			processName = utf16ToString(processInfo.ImageName.Buffer, maxChars)
		} else {
			// Handle System Idle Process (PID 0) which has no name
			if processInfo.UniqueProcessId == 0 {
				processName = "System Idle Process"
			} else {
				processName = fmt.Sprintf("Process_%d", processInfo.UniqueProcessId)
			}
		}
		
		// Skip System Idle Process (PID 0) but include all others
		if processInfo.UniqueProcessId != 0 && processName != "" {
			// Try to open the process to check if we have access
			// Use a more permissive access check - try different access levels
			var processHandle uintptr
			clientId := winapi.CLIENT_ID{
				UniqueProcess: processInfo.UniqueProcessId,
				UniqueThread:  0,
			}
			
			// Initialize OBJECT_ATTRIBUTES to NULL equivalent
			objAttrs := winapi.OBJECT_ATTRIBUTES{
				Length: uint32(unsafe.Sizeof(winapi.OBJECT_ATTRIBUTES{})),
			}
			
			// Try with limited access first
			status, _ := winapi.NtOpenProcess(
				&processHandle,
				winapi.PROCESS_QUERY_LIMITED_INFORMATION,
				uintptr(unsafe.Pointer(&objAttrs)),
				uintptr(unsafe.Pointer(&clientId)),
			)
			
			// If that fails, try with even more limited access
			if status != winapi.STATUS_SUCCESS {
				status, _ = winapi.NtOpenProcess(
					&processHandle,
					winapi.PROCESS_QUERY_INFORMATION,
					uintptr(unsafe.Pointer(&objAttrs)),
					uintptr(unsafe.Pointer(&clientId)),
				)
			}
			
			// If that still fails, just add the process anyway (we know it exists)
			if status == winapi.STATUS_SUCCESS {
				winapi.NtClose(processHandle)
			}
			
			// Add process to list even if we can't access it for injection
			// We'll check access again when actually trying to inject
			processes = append(processes, ProcessInfo{
				Pid:  uint32(processInfo.UniqueProcessId),
				Name: processName,
			})
		}
		
		// Move to next entry
		if processInfo.NextEntryOffset == 0 {
			break
		}
		offset += uintptr(processInfo.NextEntryOffset)
	}
	
	// Sort processes by name for easier readability
	sort.Slice(processes, func(i, j int) bool {
		return processes[i].Name < processes[j].Name
	})
	
	return processes, nil
}

func isProcessRunning(pid uint32) error {
	// Open the process
	var processHandle uintptr
	clientId := winapi.CLIENT_ID{
		UniqueProcess: uintptr(pid),
		UniqueThread:  0,
	}
	
	// Initialize OBJECT_ATTRIBUTES properly
	objAttrs := winapi.OBJECT_ATTRIBUTES{
		Length: uint32(unsafe.Sizeof(winapi.OBJECT_ATTRIBUTES{})),
	}
	
	status, err := winapi.NtOpenProcess(
		&processHandle,
		winapi.PROCESS_QUERY_LIMITED_INFORMATION,
		uintptr(unsafe.Pointer(&objAttrs)),
		uintptr(unsafe.Pointer(&clientId)),
	)
	
	if err != nil {
		return fmt.Errorf("failed to open process for verification: %v", err)
	}
	
	if status != winapi.STATUS_SUCCESS {
		return fmt.Errorf("failed to open process: %s", winapi.FormatNTStatus(status))
	}
	
	defer winapi.NtClose(processHandle)
	
	// Query basic process information
	var processInfo winapi.PROCESS_BASIC_INFORMATION
	var returnLength uintptr
	
	status, err = winapi.NtQueryInformationProcess(
		processHandle,
		winapi.ProcessBasicInformation,
		unsafe.Pointer(&processInfo),
		unsafe.Sizeof(processInfo),
		&returnLength,
	)
	
	if err != nil {
		return fmt.Errorf("failed to query process information: %v", err)
	}
	
	if status != winapi.STATUS_SUCCESS {
		return fmt.Errorf("process query failed: %s", winapi.FormatNTStatus(status))
	}
	
	// If we can query the process, it's running
	// The ExitStatus would be non-zero if the process had exited
	return nil
}

func utf16ToString(ptr *uint16, maxLen int) string {
	if ptr == nil {
		return ""
	}
	
	var result []uint16
	for i := 0; i < maxLen; i++ {
		char := *(*uint16)(unsafe.Pointer(uintptr(unsafe.Pointer(ptr)) + uintptr(i)*2))
		if char == 0 {
			break
		}
		result = append(result, char)
	}
	
	// Simple conversion for ASCII characters
	var str strings.Builder
	for _, char := range result {
		if char < 128 {
			str.WriteByte(byte(char))
		} else {
			str.WriteRune('?') // Replace non-ASCII with ?
		}
	}
	return str.String()
}

// AutoSelectTarget automatically selects a suitable target process for injection
// It tests actual access rights rather than using hardcoded system process lists
func AutoSelectTarget() (uint32, string, error) {
	processes, err := getProcessList()
	if err != nil {
		return 0, "", fmt.Errorf("failed to get process list: %w", err)
	}

	// Required access rights for injection
	requiredAccess := uintptr(winapi.PROCESS_CREATE_THREAD | 
					  winapi.PROCESS_VM_OPERATION | 
					  winapi.PROCESS_VM_WRITE | 
					  winapi.PROCESS_VM_READ)

	for _, proc := range processes {
		// Skip very low PIDs (usually system processes)
		if proc.Pid < 10 {
			continue
		}

		// Skip our own process
		currentPID := winapi.GetCurrentProcessId()
		if proc.Pid == uint32(currentPID) {
			continue
		}

		// Test if we can open the process with required access
		var processHandle uintptr
		clientId := winapi.CLIENT_ID{
			UniqueProcess: uintptr(proc.Pid),
			UniqueThread:  0,
		}

		objAttrs := winapi.OBJECT_ATTRIBUTES{
			Length: uint32(unsafe.Sizeof(winapi.OBJECT_ATTRIBUTES{})),
		}

		status, _ := winapi.NtOpenProcess(
			&processHandle,
			requiredAccess,
			uintptr(unsafe.Pointer(&objAttrs)),
			uintptr(unsafe.Pointer(&clientId)),
		)

		if status == winapi.STATUS_SUCCESS {
			// We can access this process - do additional checks
			defer winapi.NtClose(processHandle)

			// Query process information to ensure it's not a system process
			var processInfo winapi.PROCESS_BASIC_INFORMATION
			var returnLength uintptr

			status, _ = winapi.NtQueryInformationProcess(
				processHandle,
				winapi.ProcessBasicInformation,
				unsafe.Pointer(&processInfo),
				unsafe.Sizeof(processInfo),
				&returnLength,
			)

			if status == winapi.STATUS_SUCCESS {
				// Additional heuristics to avoid system processes:
				// 1. Avoid processes with very low PIDs
				// 2. Avoid processes we can't get basic info from
				// 3. Prefer user processes (non-system session)

				// Check if it's in a user session (not session 0 which is typically system)
				var sessionInfo uint32
				status, _ = winapi.NtQueryInformationProcess(
					processHandle,
					winapi.ProcessSessionInformation,
					unsafe.Pointer(&sessionInfo),
					unsafe.Sizeof(sessionInfo),
					&returnLength,
				)

				// Prefer processes in user sessions (session > 0) but don't strictly require it
				isUserSession := (status == winapi.STATUS_SUCCESS && sessionInfo > 0)

				// Additional safety checks based on process name
				processName := strings.ToLower(proc.Name)
				
				// Skip obvious system processes by name patterns
				systemPatterns := []string{
					"system", "registry", "csrss", "winlogon", "services", 
					"lsass", "svchost", "smss", "wininit", "dwm", "conhost",
				}
				
				isSystemProcess := false
				for _, pattern := range systemPatterns {
					if strings.Contains(processName, pattern) {
						isSystemProcess = true
						break
					}
				}

				// If it's not an obvious system process and we have good access, use it
				if !isSystemProcess {
					// Close the handle before returning since we opened it for testing
					winapi.NtClose(processHandle)
					
					// Additional validation - make sure process is still running
					if err := isProcessRunning(proc.Pid); err == nil {
						sessionStr := ""
						if isUserSession {
							sessionStr = fmt.Sprintf(" (User Session %d)", sessionInfo)
						}
						
						return proc.Pid, fmt.Sprintf("%s [PID: %d]%s", proc.Name, proc.Pid, sessionStr), nil
					}
				}
			}
		}
	}

	return 0, "", fmt.Errorf("no suitable target process found - all accessible processes appear to be system processes")
}

