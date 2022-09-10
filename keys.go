package crx3

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"os"
)

// NewPrivateKey returns a new private key.
func NewPrivateKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

// SavePrivateKey saves private key to file.
func SavePrivateKey(filename string, key *ecdsa.PrivateKey) error {
	if key == nil {
		key, _ = NewPrivateKey()
	}
	fd, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer fd.Close()
	bytes, err := x509.MarshalECPrivateKey(key)
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
func LoadPrivateKey(filename string) (*ecdsa.PrivateKey, error) {
	buf, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(buf)
	if block == nil {
		return nil, ErrPrivateKeyNotFound
	}
	r, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return r, nil
}

// LoadPublicKey loads the public key from a file into memory.
func LoadPublicKey(filename string) (*ecdsa.PublicKey, error) {
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
	return r.(*ecdsa.PublicKey), nil
}
