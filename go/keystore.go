package vault

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
)

type DeviceKey struct {
	ClientID   string         `json:"clientId"`
	PublicKey  map[string]any `json:"publicKey"`
	PrivateKey map[string]any `json:"privateKey"`
}

func keychainAccount(origin string) string {
	digest := sha256.Sum256([]byte(origin))
	return base64.RawURLEncoding.EncodeToString(digest[:])[:32]
}

func LoadDeviceKey(origin string) (*DeviceKey, error) {
	value, err := readOSCredential(keychainAccount(origin))
	if err != nil || value == "" {
		return nil, err
	}
	var key DeviceKey
	if err := json.Unmarshal([]byte(value), &key); err != nil {
		return nil, err
	}
	return &key, nil
}
