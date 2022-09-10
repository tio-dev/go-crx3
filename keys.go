package crx3

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"os"
)

// NewPrivateKey returns a new private key.
func NewPrivateKey() (ed25519.PrivateKey, error) {
	_, priv, err := ed25519.GenerateKey(nil)
	return priv, err
}

// SavePrivateKey saves private key to file.
func SavePrivateKey(filename string, key ed25519.PrivateKey) error {
	if key == nil {
		key, _ = NewPrivateKey()
	}
	fd, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer fd.Close()
	bytes, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	block := &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: bytes,
	}
	_, err = fd.Write(pem.EncodeToMemory(block))
	return err
}

// LoadPrivateKey loads the private key from a file into memory.
func LoadPrivateKey(filename string) (ed25519.PrivateKey, error) {
	buf, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(buf)
	if block == nil {
		return nil, ErrPrivateKeyNotFound
	}
	r, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return r.(ed25519.PrivateKey), nil
}

// LoadPublicKey loads the public key from a file into memory.
func LoadPublicKey(filename string) (ed25519.PublicKey, error) {
	buf, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(buf)
	if block == nil {
		return nil, ErrPublicKeyNotFound
	}
	r, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return r.(ed25519.PublicKey), nil
}
