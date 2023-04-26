package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

func main() {
	// Generate a random private key
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	// Get the public key
	pubKey := privKey.PublicKey

	// Get user input string to be encrypted
	var input string
	fmt.Println("Enter a message:")
	fmt.Scanln(&input)

	inputBytes := []byte(input)

	k, _ := rand.Int(rand.Reader, elliptic.P256().Params().N)

	cipherX, cipherY := elliptic.P256().ScalarMult(privKey.X, privKey.Y, k.Bytes())
	cipherPubKeyBytes := elliptic.Marshal(elliptic.P256(), cipherX, cipherY)

	sharedSecretX, _ := elliptic.P256().ScalarMult(cipherX, cipherY, privKey.D.Bytes())
	sharedSecret := sharedSecretX.Bytes()

	ciphertext := make([]byte, len(inputBytes))
	for i := 0; i < len(inputBytes); i++ {
		ciphertext[i] = inputBytes[i] ^ sharedSecret[i%len(sharedSecret)]
	}

	// Convert keys to byte slices
	encryptionKey := k.Bytes()
	decryptionKey := sharedSecret

	fmt.Printf("private key: 0x%s\n", hex.EncodeToString(privKey.D.Bytes()))
	fmt.Printf("public key: 0x%s\n", hex.EncodeToString(elliptic.Marshal(elliptic.P256(), pubKey.X, pubKey.Y)))
	fmt.Printf("ciphertext pubKey: 0x%s\n", hex.EncodeToString(cipherPubKeyBytes))
	fmt.Printf("encryption key: 0x%s\n", hex.EncodeToString(encryptionKey))
	fmt.Printf("decryption key: 0x%s\n", hex.EncodeToString(decryptionKey))
	fmt.Printf("encrypted message: %s\n", hex.EncodeToString(ciphertext))

	// Decrypt
	decrypted := make([]byte, len(ciphertext))
	for i := 0; i < len(ciphertext); i++ {
		decrypted[i] = ciphertext[i] ^ sharedSecret[i%len(sharedSecret)]
	}

	fmt.Println("Decrypted message:", string(decrypted))
}
