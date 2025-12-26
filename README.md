# go-crypter

this is a loader that consists of two parts - the encrypter and the loader, both PEs and shellcode can be encrypted and embedded
into a loader that offers multiple execution options for shellcode, pe's are just mapped and their entry point is executed with ntdll!rtlcreateuserthread. for shellcode, you can take a few different paths each with their own upsides and downsides evasion wise. this project is meant to be compiled on win10+ x64 only.

# enclave
1. uses mscoree!GetProcessExecutableHeap, vdsutil!VdsHeapAlloc, and ntdll!LdrCallEnclave
2. memory region of shellcode is RWX by default, as GetProcessExecutableHeap is usually used for JIT stuff

# indirect syscalls
1. uses ntdll!NtAllocateVirtualMemory, ntdll!ProtectVirtualMemory to allocate memory and flip prots (takes PAGE_READWRITE -> PAGE_EXECUTE_READ path
2. uses ntdll!RtlCreateUserThread to execute entry point

# run once
1. uses ntdll!NtAllocateVirtualMemory, ntdll!ProtectVirtualMemory to allocate memory and flip prots (also takes PAGE_READWRITE -> PAGE_EXECUTE_READ path
2. executes entry point with ntdll!RtlRunOnceExecuteOnce which does exactly what it says

## features

### encryption & compression
- **multiple encryption algorithms**: ChaCha20-Poly1305, AES-GCM, Twofish-GCM
- **argon2id key derivation** with configurable parameters for enhanced security
- **automatic compression** using zlib to reduce payload size
- **CBOR serialization** for efficient binary encoding

### capabilities 
- **dual payload support**: handles both raw shellcode and PE executables
- **in-memory PE execution**: Full runpe implementation with proper relocation and import resolution
- **shellcode injection**: direct shellcode execution using some silly injection techniques


### encrypting payloads

```bash
# encrypt shellcode (default, used chacha20) 
go run crypt.go payload.bin

# encrypt PE executable with aesgcm
go run crypt.go payload.exe -alg aesgcm 
```

### available options
- `-alg`: encryption algorithm (chacha20, aesgcm, twofish)

## architecture

1. **crypt**: encrypts and packages payloads into CBOR format with embedded metadata
2. **stub**: self-contained executable that decrypts and executes the embedded payload

## Building

```bash
# build the stub (after encrypting a payload)
cd ../stub && go build -o stub.exe
```

## running
```bash
# after running the crypter tool and building the stub, you can pass some flags to specify how you want to run

./stub.exe -enclave

./stub.exe -indirec

./stub.exe -once

# or 

./stub.exe # with no flags to run an embedded EXE or shellcode with the default methods

```
