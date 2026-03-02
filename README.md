# go-crypter

loader consisting of two parts, an encrypter and a stub. both PEs and shellcode can be encrypted and embedded. PE payloads are mapped in-memory with full relocation and import resolution, entry point executed via ntdll!RtlCreateUserThread. shellcode has a few execution paths. x64 windows only.

no `syscall` or `golang.org/x/windows` imports anywhere in the stub all winapi calls go through [go-wincall](https://github.com/carved4/go-wincall). decryption in the stub uses bcrypt.dll (WinCNG) via go-wincall rather than Go's crypto stdlib.

# key handling

the encryption key is **never stored in the payload**. `crypt` outputs a build command with the hex-encoded password baked in via `-ldflags`. the CBOR blob (salt + nonce + ciphertext) is useless without the stub binary.

# shellcode execution methods

### enclave
1. mscoree!GetProcessExecutableHeap → vdsutil!VdsHeapAlloc → ntdll!LdrCallEnclave
2. shellcode lands in an RWX heap region (GetProcessExecutableHeap is normally used for JIT)

### indirect syscalls
1. NtAllocateVirtualMemory + NtProtectVirtualMemory via indirect syscall (RW → RX)
2. ntdll!RtlCreateUserThread to execute

### run once
1. NtAllocateVirtualMemory + NtProtectVirtualMemory via indirect syscall (RW → RX)
2. ntdll!RtlRunOnceExecuteOnce to execute

## features

- **AES-256-GCM** encryption via WinCNG (bcrypt.dll) in the stub
- **argon2id** key derivation (pure Go, no syscall imports)
- **zlib compression** before encryption
- **CBOR** payload serialization
- **key separation** — password injected at link time, not stored on disk or in the payload
- **runpe** — in-memory PE loading with relocation, import resolution, TLS callbacks, section protections, PE header wipe, command line scrub
- **go-wincall** throughout — hash-based function resolution, indirect syscalls, no direct windows imports

## usage

### 1. encrypt

```
cd crypt
go run crypt.go <payload.bin|payload.exe>
```

output:
```
[+] compression reduced size from X to Y bytes (Z%)
[+] encryption completed successfully!
CBOR payload saved to:
- ..\stub\payload.cbor
[+] build stub with:
    go build -ldflags "-X main.password=<hex>" .
```

use `-type exe` explicitly if the filename doesn't contain `.exe`:
```
go run crypt.go -type exe payload.bin
```

### 2. build stub

copy the printed build command and run it from the stub directory:
```
cd ..\stub
go build -ldflags "-X main.password=<hex>" .
```

### 3. run

```
# PE payload — no flag needed
./stub.exe

# shellcode — pick an execution method
./stub.exe -enclave
./stub.exe -indirect
./stub.exe -once
```
