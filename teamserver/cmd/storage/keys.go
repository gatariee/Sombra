package storage

import (
	"bufio"
	"crypto/rsa"
	"os"
	"path/filepath"

	"sombra/cmd/crypto"
)

func SaveServerKeys(dir string, publicKey *rsa.PublicKey, privateKey *rsa.PrivateKey) error {
	if err := os.MkdirAll(filepath.Join(dir, "keys"), 0o755); err != nil {
		return err
	}

	if err := saveRSAKey(filepath.Join(dir, "keys", "rsa.pub"), func() ([]byte, error) {
		return crypto.MarshalPublicKey(publicKey)
	}); err != nil {
		return err
	}

	if err := saveRSAKey(filepath.Join(dir, "keys", "rsa"), func() ([]byte, error) {
		return crypto.MarshalPrivateKey(privateKey)
	}); err != nil {
		return err
	}

	return nil
}

func saveRSAKey(filePath string, marshalFunc func() ([]byte, error)) error {
	file, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	data, err := marshalFunc()
	if err != nil {
		return err
	}

	if _, err = writer.Write(data); err != nil {
		return err
	}

	return writer.Flush()
}
