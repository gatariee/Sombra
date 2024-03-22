package crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
)

type ServerKeys struct {
	PrivateKey *rsa.PrivateKey
	PublicKey  *rsa.PublicKey
}

func GenerateRSAKeys() (*ServerKeys, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	return &ServerKeys{
		PrivateKey: privateKey,
		PublicKey:  &privateKey.PublicKey,
	}, nil
}

func EncryptRSA(pub *rsa.PublicKey, data []byte) ([]byte, error) {
	return rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, data, nil)
}

func DecryptRSA(priv *rsa.PrivateKey, data []byte) ([]byte, error) {
	return rsa.DecryptOAEP(sha256.New(), rand.Reader, priv, data, nil)
}

func MarshalPublicKey(pub *rsa.PublicKey) ([]byte, error) {
	return json.Marshal(pub)
}

func UnmarshalPublicKey(data []byte, pub *rsa.PublicKey) error {
	return json.Unmarshal(data, pub)
}

func MarshalPrivateKey(priv *rsa.PrivateKey) ([]byte, error) {
	return json.Marshal(priv)
}

func UnmarshalPrivateKey(data []byte, priv *rsa.PrivateKey) error {
	return json.Unmarshal(data, priv)
}

func MarshalKey(key interface{}) ([]byte, error) {
	return json.Marshal(key)
}

func UnmarshalKey(data []byte, key interface{}) error {
	return json.Unmarshal(data, key)
}
