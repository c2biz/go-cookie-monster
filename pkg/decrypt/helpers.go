package decrypt

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/json"
	"fmt"
)

func decryptAESGCM(key []byte, encryptedData []byte) ([]byte, error) {
	nonce := encryptedData[3:15]
	ciphertext := encryptedData[15 : len(encryptedData)-16]
	tag := encryptedData[len(encryptedData)-16:]

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	plaintext, err := aesGCM.Open(nil, nonce, append(ciphertext, tag...), nil)
	if err != nil {
		return nil, err
	}

	return plaintext[32:], nil
}

func convertTimestamp(expiresUtc int64) int64 {
	return expiresUtc/1000000 - 11644473600
}

func convertSameSite(sameSiteInt int) string {
	switch sameSiteInt {
	case 0:
		return "no_restriction"
	case 1:
		return "lax"
	case 2:
		return "strict"
	default:
		return "no_restriction"
	}
}

func setDefaultValues(c *Cookie) {
	c.HostOnly = false
	c.Session = false
	c.FirstPartyDomain = ""
	c.PartitionKey = nil
	c.StoreID = nil
}

// In pkg/decrypt/helpers.go
func (f *JSONFormatter) Format() (string, error) {
	if len(f.Cookies) > 0 {
		jsonData, err := json.MarshalIndent(f.Cookies, "", "    ")
		if err != nil {
			return "", err
		}
		return string(jsonData), nil
	}

	// Otherwise format login entries
	jsonData, err := json.MarshalIndent(f.LogonEntries, "", "    ")
	if err != nil {
		return "", err
	}
	return string(jsonData), nil
}

// Add this to pkg/decrypt/helpers.go

// decryptLogonData handles decryption of Chrome login data passwords
func decryptLogonData(key []byte, encryptedData []byte) ([]byte, error) {
	// Check for v10 prefix
	if len(encryptedData) >= 3 && bytes.Equal(encryptedData[:3], []byte("v10")) {
		// Remove the v10 prefix
		encryptedData = encryptedData[3:]

		// Not enough data for nonce
		if len(encryptedData) < 12 {
			return nil, fmt.Errorf("encrypted data too short for nonce")
		}

		nonce := encryptedData[:12]
		ciphertext := encryptedData[12:]

		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}

		aesGCM, err := cipher.NewGCM(block)
		if err != nil {
			return nil, err
		}

		plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
		if err != nil {
			return nil, err
		}

		// If plaintext is longer than 32 bytes, remove the padding
		if len(plaintext) > 32 {
			return plaintext[32:], nil
		}
		return plaintext, nil
	}

	// No recognizable prefix, try direct decryption
	if len(encryptedData) < 12 {
		return nil, fmt.Errorf("encrypted data too short for direct decryption")
	}

	nonce := encryptedData[:12]
	ciphertext := encryptedData[12:]

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	if len(plaintext) > 32 {
		return plaintext[32:], nil
	}
	return plaintext, nil
}
