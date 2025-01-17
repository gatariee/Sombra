package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"fmt"
)

func Pad(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padText...)
}

func Unpad(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("data is empty, cannot unpad")
	}
	paddingLength := int(data[len(data)-1])
	if paddingLength > len(data) || paddingLength == 0 {
		return nil, fmt.Errorf("invalid padding length")
	}

	for _, padByte := range data[len(data)-paddingLength:] {
		if padByte != byte(paddingLength) {
			return nil, fmt.Errorf("invalid padding")
		}
	}

	// Remove padding
	return data[:len(data)-paddingLength], nil
}

func EncryptAES(key []byte, iv []byte, data []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if len(data)%aes.BlockSize != 0 {
		return nil, errors.New("data is not a multiple of the block size")
	}

	if len(iv) != aes.BlockSize {
		return nil, errors.New("IV length must be equal to block size")
	}

	ciphertext := make([]byte, len(data))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, data)

	return ciphertext, nil
}

func DecryptAES(key []byte, iv []byte, data []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if len(data)%aes.BlockSize != 0 {
		return nil, errors.New("ciphertext is not a multiple of the block size")
	}

	if len(iv) != aes.BlockSize {
		return nil, errors.New("IV length must be equal to block size")
	}

	plaintext := make([]byte, len(data))
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(plaintext, data)

	return plaintext, nil
}
