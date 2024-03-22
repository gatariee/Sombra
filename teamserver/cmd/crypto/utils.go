package crypto

import (
	"encoding/base64"
	"bytes"
	"fmt"
)

func Base64Encode(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

func Base64Decode(data string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(data)
}

func BytesToString(data []byte) string {
	return string(data)
}

func SplitSessionKey(sessionKey []byte) (nonce []byte, key []byte, err error) {
	separator := []byte{0x00, 0x00, 0x00, 0x00}
	/* This is a hardcoded separator into the implant, for debugging purposes; please read XD */

	index := bytes.Index(sessionKey, separator)
	if index == -1 {
		return nil, nil, fmt.Errorf("separator not found in sessionKey")
	}

	nonce = sessionKey[:index]
	key = sessionKey[index+len(separator):]
	return nonce, key, nil
}
