package encryptedcolumn

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
)

var (
	errInvalidKey              = fmt.Errorf("key is not valid")
	errEncryptedStringTooShort = fmt.Errorf("unable to decrypt short string")
	errCiphertextInvalidSize   = fmt.Errorf("ciphertext is not a multiple of the block size")
	errIncorrectPadding        = fmt.Errorf("invalid padding")
)

type EncryptedColumn struct {
	UsePrefix bool
	Disable   bool
	Key       []byte
	Prefix    string
}

func NewEncryptedColumn(key string, usePrefix bool) (*EncryptedColumn, error) {
	keyBytes := []byte(key)[:32]
	return &EncryptedColumn{
		Key:       keyBytes,
		Prefix:    "--ENCR--",
		UsePrefix: usePrefix,
		Disable:   false,
	}, nil
}

func (ec *EncryptedColumn) Load(raw string) (string, error) {
	if raw == "" {
		return "", nil
	}

	if !ec.shouldDecrypt(raw) {
		return raw, nil
	}

	return ec.decrypt(raw)
}

func (ec *EncryptedColumn) Dump(raw string) (string, error) {
	return ec.encrypt(raw)
}

func (ec *EncryptedColumn) shouldDecrypt(raw string) bool {
	return !ec.UsePrefix || strings.HasPrefix(raw, ec.Prefix)
}

func (ec *EncryptedColumn) decrypt(raw string) (string, error) {
	if strings.HasPrefix(raw, ec.Prefix) {
		raw = strings.TrimPrefix(raw, ec.Prefix)
	}
	decoded, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return raw, err
	}

	crypted := []byte(decoded)

	block, err := aes.NewCipher(ec.Key)
	if err != nil {
		return "", err
	}

	iv := crypted[len(crypted)-16:]
	crypted = crypted[:len(crypted)-16]

	mode := cipher.NewCBCDecrypter(block, iv)
	origData := make([]byte, len(crypted))
	mode.CryptBlocks(origData, crypted)
	origData = PKCS5UnPadding(origData)
	return string(origData), nil
}

func (ec *EncryptedColumn) encrypt(raw string) (string, error) {
	origData := []byte(raw)
	block, err := aes.NewCipher(ec.Key)
	if err != nil {
		return "", err
	}

	iv, err := ec.createIV()
	if err != nil {
		return "", err
	}

	blockSize := block.BlockSize()
	origData = PKCS5Padding(origData, blockSize)
	mode := cipher.NewCBCEncrypter(block, iv)
	crypted := make([]byte, len(origData))
	mode.CryptBlocks(crypted, origData)

	crypted = append(crypted, []byte(iv)...)
	outString := base64.StdEncoding.EncodeToString(crypted)
	if ec.UsePrefix {
		outString = ec.Prefix + outString
	}
	return outString, nil
}

func (ec *EncryptedColumn) createIV() ([]byte, error) {
	iv, err := RandBytes(8)
	return []byte(hex.EncodeToString(iv)), err
}
