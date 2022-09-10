package crx3

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/tio-dev/go-crx3/pb"

	"github.com/golang/protobuf/proto"
)

// Unpack unpacks chrome extension into some directory.
func Unpack(filename string, out *string, key *string, isPEM bool) error {
	outPath := ""
	if out != nil {
		outInfo, err := os.Stat(*out)
		if err != nil {
			return err

		}
		if !outInfo.IsDir() {
			return ErrPathDoesNotDirectory
		}
		outPath = *out
	}

	if !isCRX(filename) {
		return ErrUnsupportedFileFormat
	}
	crx, err := ioutil.ReadFile(filename)
	if err != nil {
		return err
	}
	var (
		headerSize = binary.LittleEndian.Uint32(crx[8:12])
		metaSize   = uint32(12)
		v          = crx[metaSize : headerSize+metaSize]
		header     pb.CrxFileHeader
		signedData pb.SignedData
	)

	if err := proto.Unmarshal(v, &header); err != nil {
		return err
	}
	if err := proto.Unmarshal(header.SignedHeaderData, &signedData); err != nil {
		return err
	}

	if len(signedData.CrxId) != 16 {
		return ErrUnsupportedFileFormat
	}

	data := crx[len(v)+int(metaSize):]
	reader := bytes.NewReader(data)
	size := int64(len(data))

	unpacked := strings.TrimRight(filename, crxExt)

	if key != nil {
		var permittedPub ed25519.PublicKey
		if isPEM {
			permittedPub, err = LoadPublicKey(*key)
			if err != nil {
				return err
			}
			permittedPubWithSum := makeBase32PublicKeyWithSum(permittedPub)
			permittedPub, err = base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(permittedPubWithSum)
			if err != nil {
				return err
			}
		} else {
			permittedPub, err = base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(*key)
			if err != nil {
				return err
			}
		}

		hashes := header.Sha256WithEd25519
		for i := range hashes {
			pubData := hashes[i].PublicKey
			signature := hashes[i].Signature
			pub, err := x509.ParsePKIXPublicKey(pubData)
			if err != nil {
				return err
			}

			pubKey := makeBase32PublicKeyWithSum(pub.(ed25519.PublicKey))
			fmt.Printf("%d) PUBLIC KEY base32: %s\n", i, pubKey)

			permittedPubKey := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(permittedPub)
			fmt.Printf("%d) PERMITTED PUBLIC KEY base32: %s\n", i, permittedPubKey)

			if pubKey != permittedPubKey {
				return ErrPublicKeyNotPermitted
			}

			ok, err := verifySign(reader, signature, pub.(ed25519.PublicKey))
			if err != nil {
				return err
			}
			if !ok {
				return ErrSignatureDoesNotMatch
			}
		}
	}

	if outPath != "" {
		_, filePath := filepath.Split(unpacked)
		unpacked = path.Join(outPath, filePath)
	}

	return Unzip(reader, size, unpacked)
}

func verifySign(r io.Reader, signature []byte, pub ed25519.PublicKey) (bool, error) {
	pubData, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return false, err
	}
	signedData, err := makeSignedData(pubData)
	if err != nil {
		return false, err
	}

	var buf bytes.Buffer
	w := bufio.NewWriter(&buf)
	w.Write([]byte(CRX3_SIGNED_DATA))
	if err := binary.Write(w, binary.LittleEndian, uint32(len(signedData))); err != nil {
		return false, err
	}
	w.Write(signedData)
	if _, err := io.Copy(w, r); err != nil {
		return false, err
	}
	return ed25519.Verify(pub, buf.Bytes(), signature), nil
}

func makeBase32PublicKeyWithSum(pub ed25519.PublicKey) string {
	fullSumHash := sha512.Sum512_256(pub) // 32 bytes
	sumHash := fullSumHash[28:]           // 4 últimos de 32 -> posições 28, 29, 30 e 31
	data := append(pub, sumHash...)
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(data)
}
