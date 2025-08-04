package types

import (
	"fmt"
	"unsafe"
)

const (
	IMAGE_DIRECTORY_ENTRY_EXPORT    = 0x0
	IMAGE_DIRECTORY_ENTRY_IMPORT    = 0x1
	IMAGE_DIRECTORY_ENTRY_BASERELOC = 0x5
	DLL_PROCESS_ATTACH              = 0x1
	
	
	// Memory constants
	MEM_COMMIT     = 0x00001000
	MEM_RESERVE    = 0x00002000
	MEM_RELEASE    = 0x00008000
	PAGE_NOACCESS  = 0x01
	PAGE_EXECUTE_READWRITE = 0x40
	PAGE_READWRITE = 0x04
	PAGE_EXECUTE_READ = 0x20
	PAGE_READONLY = 0x02
	
	// SystemFunction / RtlEncryptMemory constants
	RTL_ENCRYPT_OPTION_SAME_PROCESS   = 0x01
	RTL_ENCRYPT_OPTION_CROSS_PROCESS  = 0x02
	RTL_ENCRYPT_OPTION_SAME_LOGON     = 0x04
	RTL_ENCRYPT_MEMORY_SIZE           = 0x08  // 8 bytes minimum
	
	// Thread access rights
	THREAD_SUSPEND_RESUME = 0x0002
	THREAD_ALL_ACCESS     = 0x1FFFFF
)

type ULONGLONG uint64


type IMAGE_DOS_HEADER struct {
	E_magic    uint16
	E_cblp     uint16
	E_cp       uint16
	E_crlc     uint16
	E_cparhdr  uint16
	E_minalloc uint16
	E_maxalloc uint16
	E_ss       uint16
	E_sp       uint16
	E_csum     uint16
	E_ip       uint16
	E_cs       uint16
	E_lfarlc   uint16
	E_ovno     uint16
	E_res      [4]uint16
	E_oemid    uint16
	E_oeminfo  uint16
	E_res2     [10]uint16
	E_lfanew   uint32
}

type IMAGE_OPTIONAL_HEADER64 struct {
	Magic                       uint16
	MajorLinkerVersion          uint8
	MinorLinkerVersion          uint8
	SizeOfCode                  uint32
	SizeOfInitializedData       uint32
	SizeOfUninitializedData     uint32
	AddressOfEntryPoint         uint32
	BaseOfCode                  uint32
	ImageBase                   uint64
	SectionAlignment            uint32
	FileAlignment               uint32
	MajorOperatingSystemVersion uint16
	MinorOperatingSystemVersion uint16
	MajorImageVersion           uint16
	MinorImageVersion           uint16
	MajorSubsystemVersion       uint16
	MinorSubsystemVersion       uint16
	Win32VersionValue           uint32
	SizeOfImage                 uint32
	SizeOfHeaders               uint32
	CheckSum                    uint32
	Subsystem                   uint16
	DllCharacteristics          uint16
	SizeOfStackReserve          uint64
	SizeOfStackCommit           uint64
	SizeOfHeapReserve           uint64
	SizeOfHeapCommit            uint64
	LoaderFlags                 uint32
	NumberOfRvaAndSizes         uint32

	DataDirectory [16]IMAGE_DATA_DIRECTORY
}

type IMAGE_DATA_DIRECTORY struct {
	VirtualAddress uint32
	Size           uint32
}

type IMAGE_FILE_HEADER struct {
	Machine              uint16
	NumberOfSections     uint16
	TimeDateStamp        uint32
	PointerToSymbolTable uint32
	NumberOfSymbols      uint32
	SizeOfOptionalHeader uint16
	Characteristics      uint16
}

type IMAGE_NT_HEADERS64 struct {
	Signature      uint32
	FileHeader     IMAGE_FILE_HEADER
	OptionalHeader IMAGE_OPTIONAL_HEADER64
}

type IMAGE_NT_HEADERS struct {
	Signature      uint32
	FileHeader     IMAGE_FILE_HEADER
	OptionalHeader IMAGE_OPTIONAL_HEADER64
}

type IMAGE_SECTION_HEADER struct {
	Name                 [8]byte
	VirtualSize          uint32
	VirtualAddress       uint32
	SizeOfRawData        uint32
	PointerToRawData     uint32
	PointerToRelocations uint32
	PointerToLinenumbers uint32
	NumberOfRelocations  uint16
	NumberOfLinenumbers  uint16
	Characteristics      uint32
}

type BASE_RELOCATION_BLOCK struct {
	PageAddress uint32
	BlockSize   uint32
}

type BASE_RELOCATION_ENTRY struct {
	OffsetType uint16
}

func (bre BASE_RELOCATION_ENTRY) Offset() uint16 {
	return bre.OffsetType & 0xFFF
}

func (bre BASE_RELOCATION_ENTRY) Type() uint16 {
	return (bre.OffsetType >> 12) & 0xF
}

type IMAGE_IMPORT_DESCRIPTOR struct {
	Characteristics     uint32
	TimeDateStamp       uint32
	ForwarderChain      uint32
	Name                uint32
	FirstThunk          uint32
	OriginalFirstThunk  uint32
}

type IMAGE_EXPORT_DIRECTORY struct {
	Characteristics       uint32
	TimeDateStamp         uint32
	MajorVersion          uint16
	MinorVersion          uint16
	Name                  uint32
	Base                  uint32
	NumberOfFunctions     uint32
	NumberOfNames         uint32
	AddressOfFunctions    uint32
	AddressOfNames        uint32
	AddressOfNameOrdinals uint32
}

type IMAGE_BASE_RELOCATION struct {
	VirtualAddress uint32
	SizeOfBlock    uint32
}

type ImageThunkData64 struct {
	AddressOfData uintptr
}

type ImageThunkData = ImageThunkData64
type OriginalImageThunkData = ImageThunkData64

type ImageReloc struct {
	Data uint16
}

func (r *ImageReloc) GetType() uint16 {
	return (r.Data >> 12) & 0xF
}

func (r *ImageReloc) GetOffset() uint16 {
	return r.Data & 0xFFF
}

// VEH Exception handling structures (future)
type EXCEPTION_RECORD struct {
	ExceptionCode        uint32
	ExceptionFlags       uint32
	ExceptionRecord      *EXCEPTION_RECORD
	ExceptionAddress     uintptr
	NumberParameters     uint32
	ExceptionInformation [15]uintptr
}

type EXCEPTION_POINTERS struct {
	ExceptionRecord *EXCEPTION_RECORD
	ContextRecord   *CONTEXT
}

func NtH(baseAddress uintptr) *IMAGE_NT_HEADERS {
	dosHeader := (*IMAGE_DOS_HEADER)(unsafe.Pointer(baseAddress))
	return (*IMAGE_NT_HEADERS)(unsafe.Pointer(baseAddress + uintptr(dosHeader.E_lfanew)))
}

func CstrVal(ptr unsafe.Pointer) []byte {
	var result []byte
	for i := 0; ; i++ {
		b := *(*byte)(unsafe.Pointer(uintptr(ptr) + uintptr(i)))
		if b == 0 {
			break
		}
		result = append(result, b)
	}
	return result
}

func IsMSBSet(value uintptr) bool {
	return (value & 0x8000000000000000) != 0
}

func ParseOrdinal(addressOfData uintptr) (unsafe.Pointer, string) {
	ord := uint16(addressOfData & 0xFFFF)
	return unsafe.Pointer(uintptr(ord)), fmt.Sprintf("#%d", ord)
}

func ParseFuncAddress(baseAddress uintptr, addressOfData uintptr) (unsafe.Pointer, string) {
	nameAddr := baseAddress + addressOfData + 2 // Skip hint
	nameBytes := CstrVal(unsafe.Pointer(nameAddr))
	return unsafe.Pointer(nameAddr), string(nameBytes)
}


func GetRelocTable(ntHeaders *IMAGE_NT_HEADERS) *IMAGE_DATA_DIRECTORY {
	if ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress == 0 {
		return nil
	}
	return &ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]
}

func Memcpy(dst, src uintptr, size uintptr) {
	srcSlice := (*[^uint32(0)]byte)(unsafe.Pointer(src))[:size:size]
	dstSlice := (*[^uint32(0)]byte)(unsafe.Pointer(dst))[:size:size]
	copy(dstSlice, srcSlice)
}

func Memset(ptr uintptr, value byte, size uintptr) {
	slice := (*[^uint32(0)]byte)(unsafe.Pointer(ptr))[:size:size]
	for i := range slice {
		slice[i] = value
	}
}

func Contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

type M128A struct {
	Low  uint64
	High int64
}

type CONTEXT struct {
	P1Home               uint64
	P2Home               uint64
	P3Home               uint64
	P4Home               uint64
	P5Home               uint64
	P6Home               uint64
	ContextFlags         uint32
	MxCsr                uint32
	SegCs                uint16
	SegDs                uint16
	SegEs                uint16
	SegFs                uint16
	SegGs                uint16
	SegSs                uint16
	EFlags               uint32
	Dr0                  uint64
	Dr1                  uint64
	Dr2                  uint64
	Dr3                  uint64
	Dr6                  uint64
	Dr7                  uint64
	Rax                  uint64
	Rcx                  uint64
	Rdx                  uint64
	Rbx                  uint64
	Rsp                  uint64
	Rbp                  uint64
	Rsi                  uint64
	Rdi                  uint64
	R8                   uint64
	R9                   uint64
	R10                  uint64
	R11                  uint64
	R12                  uint64
	R13                  uint64
	R14                  uint64
	R15                  uint64
	Rip                  uint64
	VectorRegister       [26]M128A
	VectorControl        uint64
	DebugControl         uint64
	LastBranchToRip      uint64
	LastBranchFromRip    uint64
	LastExceptionToRip   uint64
	LastExceptionFromRip uint64
}

type UString struct {
	Length        uint32
	MaximumLength uint32
	Buffer        *byte // This corresponds to PUCHAR in C
}

// CLIENT_ID structure for NT thread operations
type CLIENT_ID struct {
	UniqueProcess uintptr
	UniqueThread  uintptr
}