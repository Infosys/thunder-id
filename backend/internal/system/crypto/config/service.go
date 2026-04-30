/*
 * Copyright (c) 2025, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

// Package config provides cryptographic functionality with algorithm agility.
package config

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync"

	"github.com/asgardeo/thunder/internal/system/config"
	"github.com/asgardeo/thunder/internal/system/crypto/hash"
	"github.com/asgardeo/thunder/internal/system/log"
)

// EncryptionService provides cryptographic operations.
type EncryptionService struct {
	DefaultEncryptionKid string
	// Keys stores key material by key id for decrypt-by-kid lookups.
	Keys map[string][]byte
}

var (
	// instance is the singleton instance of EncryptionService
	instance *EncryptionService
	// once ensures the singleton is initialized only once
	once sync.Once
)

// GetEncryptionService creates and returns a singleton instance of the EncryptionService.
func GetEncryptionService() *EncryptionService {
	once.Do(func() {
		var err error
		instance, err = initEncryptionService()
		if err != nil {
			panic(fmt.Sprintf("failed to initialize EncryptionService: %v", err))
		}
	})
	return instance
}

// initEncryptionService initializes the EncryptionService from configuration sources.
func initEncryptionService() (*EncryptionService, error) {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, "EncryptionService"))

	// Try to get key from the application configuration
	encryptionKey := config.GetServerRuntime().Config.Crypto.Encryption.Key

	// Check if encryption key is configured
	if encryptionKey != "" {
		key, err := hex.DecodeString(encryptionKey)
		if err == nil {
			return newEncryptionService(key), nil
		} else {
			logger.Error("failed to decode encryption key from config", log.Error(err))
			return nil, err
		}
	} else {
		return nil, errors.New("encryption key not configured in crypto.encryption.key")
	}
}

// newEncryptionService creates a new instance of EncryptionService with the provided key.
func newEncryptionService(key []byte) *EncryptionService {
	kid := getKeyID(key)
	return &EncryptionService{
		DefaultEncryptionKid: kid,
		Keys:                 map[string][]byte{kid: key},
	}
}

// Encrypt implements ConfigCryptoProvider.Encrypt.
// Encrypts the given plaintext bytes and returns encrypted bytes containing
// the encrypted data with metadata.
func (cs *EncryptionService) Encrypt(ctx context.Context, plaintext []byte) ([]byte, error) {
	encryptedStr, err := cs.encryptInto(plaintext)
	if err != nil {
		return nil, err
	}
	return []byte(encryptedStr), nil
}

// Decrypt implements ConfigCryptoProvider.Decrypt.
// Decrypts the given encrypted bytes and returns the original plaintext bytes.
func (cs *EncryptionService) Decrypt(ctx context.Context, encodedData []byte) ([]byte, error) {
	return cs.decryptFrom(string(encodedData))
}

// encryptInto encrypts the given plaintext and returns a JSON string
// containing the encrypted data.
func (cs *EncryptionService) encryptInto(plaintext []byte) (string, error) {
	encryptionKey := cs.getDefaultEncryptionKey()
	if len(encryptionKey) == 0 {
		return "", errors.New("default encryption key not found")
	}

	// Create AES cipher
	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher: %w", err)
	}

	// Create GCM mode
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM mode: %w", err)
	}

	// Create a nonce
	nonce := make([]byte, aesgcm.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return "", fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt and authenticate plaintext, prepend nonce
	ciphertext := aesgcm.Seal(nonce, nonce, plaintext, nil)

	// Create metadata structure
	encData := EncryptedData{
		Algorithm:  AESGCM,
		Ciphertext: base64.StdEncoding.EncodeToString(ciphertext),
		KeyID:      cs.DefaultEncryptionKid, // Unique identifier for the key
	}

	// Serialize to JSON
	jsonData, err := json.Marshal(encData)
	if err != nil {
		return "", fmt.Errorf("failed to serialize encrypted data: %w", err)
	}

	return string(jsonData), nil
}

// decryptFrom decrypts the given JSON string produced by encryptInto
// and returns the original plaintext.
func (cs *EncryptionService) decryptFrom(encodedData string) ([]byte, error) {
	// Deserialize JSON
	var encData EncryptedData
	if err := json.Unmarshal([]byte(encodedData), &encData); err != nil {
		return nil, fmt.Errorf("invalid data format: %w", err)
	}

	// Verify algorithm
	if encData.Algorithm != AESGCM {
		return nil, fmt.Errorf("unsupported algorithm: %s", encData.Algorithm)
	}

	// Decode the payload
	ciphertext, err := base64.StdEncoding.DecodeString(encData.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("invalid payload encoding: %w", err)
	}

	decryptionKey := cs.getKeyForDecrypt(encData.KeyID)
	if len(decryptionKey) == 0 {
		return nil, errors.New("decryption key not found for kid")
	}

	// Create AES cipher
	block, err := aes.NewCipher(decryptionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	// Create GCM mode
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM mode: %w", err)
	}

	// Verify ciphertext length
	nonceSize := aesGCM.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	// Extract nonce and decrypt
	nonce, encryptedData := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := aesGCM.Open(nil, nonce, encryptedData, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// getDefaultEncryptionKey resolves the configured default encryption key.
func (cs *EncryptionService) getDefaultEncryptionKey() []byte {
	if cs.DefaultEncryptionKid == "" {
		return nil
	}

	if len(cs.Keys) == 0 {
		return nil
	}

	return cs.Keys[cs.DefaultEncryptionKid]
}

// getKeyForDecrypt resolves the key to use for decryption based on the payload kid.
func (cs *EncryptionService) getKeyForDecrypt(kid string) []byte {
	if kid == "" {
		return nil
	}

	if len(cs.Keys) > 0 {
		if key, ok := cs.Keys[kid]; ok {
			return key
		}
	}

	return nil
}

// getKeyID generates a unique identifier for the key.
func getKeyID(key []byte) string {
	return hash.GenerateThumbprint(key)
}
