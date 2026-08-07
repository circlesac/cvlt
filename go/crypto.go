package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"fmt"
)

type AESEnvelope struct {
	Version    int    `json:"version"`
	Algorithm  string `json:"algorithm"`
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}

type ContentEnvelope struct {
	AESEnvelope
	WrappedKey AESEnvelope `json:"wrapped_key"`
}

func decodeBase64(value string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(value)
}

func decryptAES(envelope AESEnvelope, key []byte, context string) ([]byte, error) {
	if envelope.Version != 1 || envelope.Algorithm != "A256GCM" {
		return nil, fmt.Errorf("unsupported encrypted envelope")
	}
	nonce, err := decodeBase64(envelope.Nonce)
	if err != nil {
		return nil, err
	}
	ciphertext, err := decodeBase64(envelope.Ciphertext)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, nonce, ciphertext, []byte(context))
}

func DecryptContent(envelope ContentEnvelope, vaultKey []byte, context string) ([]byte, error) {
	dataKey, err := decryptAES(envelope.WrappedKey, vaultKey, context+":dek:key")
	if err != nil {
		return nil, err
	}
	return decryptAES(envelope.AESEnvelope, dataKey, context+":content")
}

func unwrapKey(envelope AESEnvelope, key []byte, context string) ([]byte, error) {
	return decryptAES(envelope, key, context+":key")
}
