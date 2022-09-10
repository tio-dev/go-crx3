package crx3

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
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
func Unpack(filename string, out *string, pem *string) error {
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

	if pem != nil {
		permittedPub, err := LoadPublicKey(*pem)
		if err != nil {
			return err
		}

		hashes := header.Sha256WithEcdsa
		for i := range hashes {
			pubData := hashes[i].PublicKey
			signature := hashes[i].Signature
			pub, err := x509.ParsePKIXPublicKey(pubData)
			if err != nil {
				return err
			}
			pubData, err = x509.MarshalPKIXPublicKey(pub)
			if err != nil {
				return err
			}
			fmt.Printf("\nPUBLIC KEY base32: %s\n", base32.StdEncoding.EncodeToString(pubData))

			if !permittedPub.Equal(pub.(*ecdsa.PublicKey)) {
				return ErrPublicKeyNotPermitted
			}

			ok, err := verifySign(reader, signature, pub.(*ecdsa.PublicKey))
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

func verifySign(r io.Reader, signature []byte, pub *ecdsa.PublicKey) (bool, error) {
	pubData, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return false, err
	}
	signedData, err := makeSignedData(pubData)
	if err != nil {
		return false, err
	}

	sign := sha256.New()
	sign.Write([]byte(CRX3_SIGNED_DATA))
	if err := binary.Write(sign, binary.LittleEndian, uint32(len(signedData))); err != nil {
		return false, err
	}
	sign.Write(signedData)
	if _, err := io.Copy(sign, r); err != nil {
		return false, err
	}
	return ecdsa.VerifyASN1(pub, sign.Sum(nil), signature), nil
}
