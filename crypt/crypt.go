package main

import (
	"bytes"
	"compress/zlib"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/fxamacker/cbor/v2"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/twofish"
)

// Default Argon2 parameters
const (
	argonTime    uint32 = 1
	argonMemory  uint32 = 64 * 1024
	argonThreads uint8  = 4
	argonKeyLen  uint32 = chacha20poly1305.KeySize
	saltSize            = 16
	passwordSize        = 32 // Size of the random password
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

func main() {
	algFlag := flag.String("alg", "chacha20", "encryption algorithm: chacha20, aesgcm, twofish")
	typeFlag := flag.String("type", "shellcode", "payload type: exe or shellcode")
	flag.Parse()

	if flag.NArg() < 1 {
		fmt.Printf("Run with %s <inputfile>\n", os.Args[0])
		os.Exit(1)
	}

	fname := flag.Arg(0)
	plaintextBytes, err := os.ReadFile(fname)
	if err != nil {
		log.Fatalf("Failed to read file: %v", err)
	}

	stubDir := filepath.Join("..", "stub")
	payloadPath := filepath.Join(stubDir, "payload.cbor")

	// Generate a random password (instead of using the key directly)
	password := make([]byte, passwordSize)
	if _, err := io.ReadFull(rand.Reader, password); err != nil {
		log.Fatalf("Failed to generate random password: %v", err)
	}

	// Generate a random salt for Argon2
	salt := make([]byte, saltSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		log.Fatalf("Failed to generate random salt: %v", err)
	}

	// Derive the encryption key using Argon2id
	key := argon2.IDKey(password, salt, argonTime, argonMemory, argonThreads, argonKeyLen)

	var aead cipher.AEAD
	alg := strings.ToLower(*algFlag)
	switch alg {
	case "aesgcm", "aes":
		block, err := aes.NewCipher(key)
		if err != nil {
			log.Fatalf("Failed to create AES cipher: %v", err)
		}
		aead, err = cipher.NewGCM(block)
		if err != nil {
			log.Fatalf("Failed to create AES-GCM AEAD: %v", err)
		}
	case "twofish":
		block, err := twofish.NewCipher(key)
		if err != nil {
			log.Fatalf("Failed to create Twofish cipher: %v", err)
		}
		aead, err = cipher.NewGCM(block)
		if err != nil {
			log.Fatalf("Failed to create Twofish-GCM AEAD: %v", err)
		}
	default:
		aead, err = chacha20poly1305.New(key)
		if err != nil {
			log.Fatalf("Failed to create AEAD: %v", err)
		}
		alg = "chacha20"
	}

	// Generate a random nonce appropriate for the algorithm
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		log.Fatalf("Failed to generate random nonce: %v", err)
	}

	// Compress the plaintext data before encryption
	var dataToEncrypt []byte
	compressed := true // Default to attempting compression

	// Try to compress the data using zlib
	var b bytes.Buffer
	zw, err := zlib.NewWriterLevel(&b, zlib.BestCompression)
	if err != nil {
		log.Printf("Warning: Failed to create zlib writer: %v", err)
		compressed = false
		dataToEncrypt = plaintextBytes
	} else {
		// Write data to the compressed buffer
		_, err = zw.Write(plaintextBytes)
		if err != nil {
			log.Printf("Warning: Failed to compress data: %v", err)
			compressed = false
			dataToEncrypt = plaintextBytes
		} else {
			// Close to flush any pending data
			err = zw.Close()
			if err != nil {
				log.Printf("Warning: Failed to finalize compression: %v", err)
				compressed = false
				dataToEncrypt = plaintextBytes
			} else {
				// Get the compressed data
				compressedData := b.Bytes()

				// Only use compression if it actually reduces size
				if len(compressedData) < len(plaintextBytes) {
					dataToEncrypt = compressedData
					fmt.Printf("Compression reduced size from %d to %d bytes (%.2f%%)",
						len(plaintextBytes), len(compressedData),
						float64(len(compressedData))/float64(len(plaintextBytes))*100)
				} else {
					// Compression didn't help, use original data
					compressed = false
					dataToEncrypt = plaintextBytes
					fmt.Println("Compression did not reduce size, using uncompressed data")
				}
			}
		}
	}

	// Encrypt the data with authentication
	encryptedBytes := aead.Seal(nil, nonce, dataToEncrypt, nil)

	// Create the payload structure
	payload := PayloadData{
		EncryptedBytes: encryptedBytes,
		Password:       password,
		Salt:           salt,
		Nonce:          nonce,
		Alg:            alg,
		Compressed:     compressed,
		PayloadType:    strings.ToLower(*typeFlag),
	}

	// Set the Argon2 parameters
	payload.ArgonParams.Time = argonTime
	payload.ArgonParams.Memory = argonMemory
	payload.ArgonParams.Threads = uint8(argonThreads)

	// Create CBOR encoder with compression options
	encOpts := cbor.EncOptions{
		Sort: cbor.SortBytewiseLexical, // Sort map keys for deterministic output
	}

	// Create encoder with options
	encMode, err := encOpts.EncMode()
	if err != nil {
		log.Fatalf("Failed to create CBOR encoder: %v", err)
	}

	// Marshal the payload to CBOR
	cborData, err := encMode.Marshal(payload)
	if err != nil {
		log.Fatalf("Failed to marshal CBOR data: %v", err)
	}

	// Write the CBOR data to file
	if err := os.WriteFile(payloadPath, cborData, 0600); err != nil {
		log.Fatalf("Failed to write CBOR payload: %v", err)
	}

	fmt.Printf("Encryption completed successfully!\nCBOR payload saved to:\n- %s\n", payloadPath)
}