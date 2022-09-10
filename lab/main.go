package main

import (
	"crypto/ed25519"
	"encoding/base32"
	"fmt"
)

func main() {
	publicKey, _, _ := ed25519.GenerateKey(nil)

	fmt.Printf("\n%s\n", base32.StdEncoding.EncodeToString(publicKey))
}
