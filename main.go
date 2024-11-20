package main

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"time"

	"main/imaging"

	"github.com/gofrs/uuid"
)

type SignImageHashRequest struct {
	imageHash   [32]byte
	attestation []byte
	// Optional values
	authorID uuid.UUID
}

type SignImageHashResponse struct {
	signature          []byte
	publicKeyUsed      []byte
	signingAuthorityID uuid.UUID
}

const IMAGE_FILE_NAME = "data/image2.png"
const OUTPUT_FILE_NAME = "outputs/test1.png"
const PRIVATE_KEY_FILE_NAME = "private_key.pem"
const PUBLIC_KEY_FILE_NAME = "public_key.pem"

func main() {
	pngCreationInteractor, err := imaging.NewPngInteractor(IMAGE_FILE_NAME)
	if err != nil {
		fmt.Printf("Could not create png interactor: %s\n", err.Error())
		return
	}

	imageBytesBuffer, err := pngCreationInteractor.FlattenImage()
	if err != nil {
		fmt.Printf("Could not read image: %s\n", err.Error())
		return
	}

	imageHash, err := hashImageSha256(imageBytesBuffer)
	if err != nil {
		fmt.Printf("Could not create hash: %s\n", err.Error())
		return
	}

	privateKey, err := LoadPrivateKey(PRIVATE_KEY_FILE_NAME)
	if err != nil {
		fmt.Printf("Could not load RSA private key: %s\n", err.Error())
		return
	}

	signedBytes, err := SignMessage(privateKey, imageHash[:])
	if err != nil {
		fmt.Printf("Could not sign message: %s\n\n", err.Error())
		return
	}

	fmt.Printf("SIGNATURE OF THIS IMAGE: %s\n\n", hex.EncodeToString(imageHash[:]))

	fmt.Printf("SIGNED MESSAGE: %s\n\n", hex.EncodeToString(signedBytes[:]))

	err = pngCreationInteractor.AddTextChunkToData("Signature", hex.EncodeToString(signedBytes[:]), OUTPUT_FILE_NAME)
	if err != nil {
		fmt.Printf("Could not add signature to metadata: %s\n", err.Error())
		return
	}

	fmt.Println("Signature added to file metadata")

	fmt.Println("-----------READING METADATA-----------")

	pngReaderInteractor, err := imaging.NewPngInteractor(OUTPUT_FILE_NAME)
	if err != nil {
		fmt.Printf("Could not create png interactor: %s\n", err.Error())
		return
	}

	pngReaderInteractor.ReadAllMetadata()

	signature, err := pngReaderInteractor.FindSignatureMetadata()
	if err != nil {
		fmt.Printf("Could find signature in metadata: %s\n", err.Error())
		return
	}

	signatureBytes, err := hex.DecodeString(signature)
	if err != nil {
		fmt.Printf("Could not decode signature: %s\n", err.Error())
		return
	}

	publicKey, err := LoadPublicKey(PUBLIC_KEY_FILE_NAME)
	if err != nil {
		fmt.Printf("Could not load RSA public key: %s\n", err.Error())
		return
	}

	// To verify, provide the public key, the hashing algorithm, the original message and the claimed signature
	err = rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, imageHash[:], signatureBytes)
	if err != nil {
		fmt.Printf("Could not verify signature: %s\n", err.Error())
		return
	}

	// If we don't get any error from the `VerifyPKCS1v15` method, that means our signature is valid
	fmt.Println("Signature Verified")
}

// LoadPrivateKey loads an RSA private key from a PEM file
func LoadPrivateKey(filePath string) (*rsa.PrivateKey, error) {
	pemBytes, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("error reading private key file: %w", err)
	}

	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, fmt.Errorf("failed to decode PEM block containing private key")
	}

	privateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("error parsing private key: %w", err)
	}

	rsaPrivateKey, ok := privateKey.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("not an RSA private key")
	}

	return rsaPrivateKey, nil
}

// LoadPublicKey loads an RSA private key from a PEM file
func LoadPublicKey(filePath string) (*rsa.PublicKey, error) {
	pemBytes, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("error reading public key file: %w", err)
	}

	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("failed to decode PEM block containing public key")
	}

	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("error parsing public key: %w", err)
	}

	rsaPublicKey, ok := publicKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not an RSA public key")
	}

	return rsaPublicKey, nil
}

// SignMessage signs a message using the private key
func SignMessage(privateKey *rsa.PrivateKey, message []byte) ([]byte, error) {
	// Sign the hashed message
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, message)
	if err != nil {
		return nil, fmt.Errorf("error signing message: %w", err)
	}

	return signature, nil
}

func measureHashTime(buf bytes.Buffer, count int, hashFunction func(buf bytes.Buffer) ([32]byte, error)) error {
	var finalHash [32]byte

	// Time the hashing of the image
	start := time.Now()
	for i := 0; i < count; i++ {
		hash, err := hashFunction(buf)
		if err != nil {
			fmt.Println("Error hashing the image:", err)
			return err
		}
		finalHash = hash
	}
	elapsed := time.Since(start)

	fmt.Printf("Final hash: %s\n", hex.EncodeToString(finalHash[:]))
	fmt.Printf("Average time per hash over %d attempts: %d microseconds\n", count, elapsed.Microseconds()/50)

	return nil
}

// Simple sha256 hash for now but can change to test other algos
func hashImageSha256(buf bytes.Buffer) ([32]byte, error) {
	hash := sha256.Sum256(buf.Bytes())

	return hash, nil
}
