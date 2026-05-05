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

package config

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"sync"
	"testing"

	"github.com/asgardeo/thunder/internal/system/config"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

type EncryptionTestSuite struct {
	suite.Suite
}

func TestEncryptionTestSuite(t *testing.T) {
	suite.Run(t, new(EncryptionTestSuite))
}

func (suite *EncryptionTestSuite) TearDownTest() {
	resetSingleton()
}

func (suite *EncryptionTestSuite) TestEncryptionService() {
	testConfig := &config.Config{
		Crypto: config.CryptoConfig{
			Encryption: config.EncryptionConfig{
				Key: "2729a7928c79371e5f312167269294a14bb0660fd166b02a408a20fa73271580",
			},
		},
	}
	config.ResetServerRuntime()
	_ = config.InitializeServerRuntime("/test/thunderid/home", testConfig)

	service := GetEncryptionService()

	// Check service not null
	assert.NotEmpty(suite.T(), service, "EncryptionService should not be nil")

	// Test data
	original := "This is a secret message that needs encryption!"

	// Encrypt
	encrypted, err := service.Encrypt(context.Background(), []byte(original))
	assert.NoError(suite.T(), err, "Encryption should not produce an error")

	// Decrypt
	decrypted, err := service.Decrypt(context.Background(), encrypted)
	assert.NoError(suite.T(), err, "Decryption should not produce an error")

	// Verify
	assert.Equal(suite.T(), original, string(decrypted), "Decrypted data should match the original")
}

func (suite *EncryptionTestSuite) TestGetEncryptionService_Singleton() {
	testConfig := &config.Config{
		Crypto: config.CryptoConfig{
			Encryption: config.EncryptionConfig{
				Key: "2729a7928c79371e5f312167269294a14bb0660fd166b02a408a20fa73271580",
			},
		},
	}
	config.ResetServerRuntime()
	_ = config.InitializeServerRuntime("/test/thunderid/home", testConfig)

	service1 := GetEncryptionService()
	service2 := GetEncryptionService()

	assert.Same(suite.T(), service1, service2, "GetEncryptionService should return the same instance")
}

func (suite *EncryptionTestSuite) TestGetEncryptionService_PanicOnInvalidConfig() {
	testConfig := &config.Config{
		Crypto: config.CryptoConfig{
			Encryption: config.EncryptionConfig{
				Key: "invalid-hex",
			},
		},
	}
	config.ResetServerRuntime()
	_ = config.InitializeServerRuntime("/test/thunderid/home", testConfig)

	assert.Panics(suite.T(), func() {
		GetEncryptionService()
	}, "GetEncryptionService should panic on invalid config")
}

func (suite *EncryptionTestSuite) TestGetEncryptionService_PanicOnEmptyConfig() {
	testConfig := &config.Config{
		Crypto: config.CryptoConfig{
			Encryption: config.EncryptionConfig{
				Key: "",
			},
		},
	}
	config.ResetServerRuntime()
	_ = config.InitializeServerRuntime("/test/thunderid/home", testConfig)

	assert.Panics(suite.T(), func() {
		GetEncryptionService()
	}, "GetEncryptionService should panic on invalid config")
}

func (suite *EncryptionTestSuite) TestTampering() {
	// Generate a random key
	key, _ := generateRandomKey(32)
	service := newEncryptionService(key)

	// Encrypt some data
	original := "Protected data"
	encrypted, err := service.Encrypt(context.Background(), []byte(original))
	assert.NoError(suite.T(), err, "Encryption should not produce an error")

	// Parse the JSON to get the encrypted data structure
	var encData EncryptedData
	err = json.Unmarshal(encrypted, &encData)
	assert.NoError(suite.T(), err, "Failed to parse encrypted JSON")

	// Tamper with the ciphertext field
	cipherBytes := []byte(encData.Ciphertext)
	if len(cipherBytes) > 10 {
		cipherBytes[len(cipherBytes)-5] ^= 0x01 // Flip a bit in the base64 encoded ciphertext
	}
	encData.Ciphertext = string(cipherBytes)

	// Re-encode to JSON
	tamperedJSON, err := json.Marshal(encData)
	assert.NoError(suite.T(), err, "Failed to marshal tampered data")

	// Attempt to decrypt tampered data
	_, err = service.Decrypt(context.Background(), tamperedJSON)
	assert.Error(suite.T(), err, "Expected decryption of tampered data to fail")
}

func (suite *EncryptionTestSuite) TestEncryptedObjectFormat() {
	// Generate a random key
	key, _ := generateRandomKey(32)
	service := newEncryptionService(key)

	// Encrypt some data
	original := "Data to encrypt"
	encrypted, err := service.Encrypt(context.Background(), []byte(original))
	assert.NoError(suite.T(), err, "Encryption should not produce an error")

	// Parse the JSON to verify structure
	var encData EncryptedData
	err = json.Unmarshal(encrypted, &encData)
	assert.NoError(suite.T(), err, "Failed to parse encrypted JSON")

	// Verify the structure
	assert.Equal(suite.T(), AESGCM, encData.Algorithm, "Algorithm should be AESGCM")
	assert.NotEmpty(suite.T(), encData.Ciphertext, "Ciphertext should not be empty")
	assert.Equal(suite.T(), getKeyID(key), encData.KeyID, "KeyID should match the expected value")
}

func (suite *EncryptionTestSuite) TestEncryptDecryptCycle() {
	// Generate a key
	key, _ := generateRandomKey(32)
	service := newEncryptionService(key)

	// Test various data types
	testCases := []string{
		"",                               // Empty string
		"Hello World",                    // Simple text
		"特殊文字列",                          // Unicode characters
		"123456789012345678901234567890", // Long string
		`{"name":"John","age":30}`,       // JSON string
	}

	for _, tc := range testCases {
		encrypted, err := service.Encrypt(context.Background(), []byte(tc))
		assert.NoError(suite.T(), err, "Encryption should not produce an error")

		decrypted, err := service.Decrypt(context.Background(), encrypted)
		assert.NoError(suite.T(), err, "Decryption should not produce an error")
		assert.Equal(suite.T(), tc, string(decrypted), "Decrypted data should match the original")
	}
}

func (suite *EncryptionTestSuite) TestDifferentKeysEncryption() {
	// Generate two different keys
	key1, err := generateRandomKey(32)
	assert.NoError(suite.T(), err, "Key generation should not produce an error")
	key2, err := generateRandomKey(32)
	assert.NoError(suite.T(), err, "Key generation should not produce an error")

	service1 := newEncryptionService(key1)
	service2 := newEncryptionService(key2)

	// Encrypt with first service
	original := "Secret message"
	encrypted, err := service1.Encrypt(context.Background(), []byte(original))
	assert.NoError(suite.T(), err, "Encryption with first key should not produce an error")
	// Try to decrypt with second service (should fail)
	_, err = service2.Decrypt(context.Background(), encrypted)
	assert.Error(suite.T(), err, "Expected decryption with different key to fail")
}

func (suite *EncryptionTestSuite) TestEncryptWithInvalidKey() {
	service := &EncryptionService{
		DefaultEncryptionKid: "kid",
		Keys: map[string][]byte{
			"kid": []byte("short"),
		},
	}

	_, err := service.Encrypt(context.Background(), []byte("data"))

	assert.Error(suite.T(), err)
}

func (suite *EncryptionTestSuite) TestDecryptInvalidJSON() {
	key, err := generateRandomKey(32)
	assert.NoError(suite.T(), err, "Key generation should not produce an error")
	service := newEncryptionService(key)

	_, err = service.Decrypt(context.Background(), []byte("not-json"))
	assert.Error(suite.T(), err)
	assert.Contains(suite.T(), err.Error(), "invalid data format")
}

func (suite *EncryptionTestSuite) TestDecryptUnsupportedAlgorithm() {
	key, err := generateRandomKey(32)
	assert.NoError(suite.T(), err, "Key generation should not produce an error")
	service := newEncryptionService(key)

	payload := EncryptedData{
		Algorithm:  "RSA",
		Ciphertext: base64.StdEncoding.EncodeToString([]byte("cipher")),
		KeyID:      service.DefaultEncryptionKid,
	}
	raw, _ := json.Marshal(payload)

	_, err = service.Decrypt(context.Background(), raw)
	assert.Error(suite.T(), err)
	assert.Contains(suite.T(), err.Error(), "unsupported algorithm")
}

func (suite *EncryptionTestSuite) TestDecryptInvalidBase64() {
	key, _ := generateRandomKey(32)
	service := newEncryptionService(key)

	payload := EncryptedData{
		Algorithm:  AESGCM,
		Ciphertext: "###invalid###",
		KeyID:      service.DefaultEncryptionKid,
	}
	raw, _ := json.Marshal(payload)

	_, err := service.Decrypt(context.Background(), raw)
	assert.Error(suite.T(), err)
	assert.Contains(suite.T(), err.Error(), "invalid payload encoding")
}

func (suite *EncryptionTestSuite) TestDecryptCiphertextTooShort() {
	key, err := generateRandomKey(32)
	assert.NoError(suite.T(), err, "Key generation should not produce an error")
	service := newEncryptionService(key)

	payload := EncryptedData{
		Algorithm:  AESGCM,
		Ciphertext: base64.StdEncoding.EncodeToString([]byte("short")),
		KeyID:      service.DefaultEncryptionKid,
	}
	raw, _ := json.Marshal(payload)

	_, err = service.Decrypt(context.Background(), raw)
	assert.Error(suite.T(), err)
}

func (suite *EncryptionTestSuite) TestDecryptWithInvalidKeyLength() {
	service := &EncryptionService{
		DefaultEncryptionKid: "kid",
		Keys: map[string][]byte{
			"kid": []byte("short"),
		},
	}

	payload := EncryptedData{
		Algorithm:  AESGCM,
		Ciphertext: base64.StdEncoding.EncodeToString([]byte("ciphertext-with-nonce")),
		KeyID:      "kid",
	}
	raw, _ := json.Marshal(payload)

	_, err := service.Decrypt(context.Background(), raw)
	assert.Error(suite.T(), err)
}

func (suite *EncryptionTestSuite) TestDecryptUsesKeyFromKidMap() {
	key1, err := generateRandomKey(32)
	assert.NoError(suite.T(), err)
	key2, err := generateRandomKey(32)
	assert.NoError(suite.T(), err)

	primary := newEncryptionService(key1)
	secondary := newEncryptionService(key2)

	// Encrypt with the secondary key so payload kid points to that key.
	encrypted, err := secondary.Encrypt(context.Background(), []byte("rotated-secret"))
	assert.NoError(suite.T(), err)

	// Decrypt using a service whose active key is key1 but key map contains key2.
	service := &EncryptionService{
		DefaultEncryptionKid: primary.DefaultEncryptionKid,
		Keys: map[string][]byte{
			primary.DefaultEncryptionKid:   key1,
			secondary.DefaultEncryptionKid: key2,
		},
	}

	decrypted, err := service.Decrypt(context.Background(), encrypted)
	assert.NoError(suite.T(), err)
	assert.Equal(suite.T(), "rotated-secret", string(decrypted))
}

func (suite *EncryptionTestSuite) TestDecryptFailsWhenKidIsUnknown() {
	key, err := generateRandomKey(32)
	assert.NoError(suite.T(), err)
	service := newEncryptionService(key)

	payload := EncryptedData{
		Algorithm:  AESGCM,
		Ciphertext: base64.StdEncoding.EncodeToString([]byte("ciphertext-with-nonce")),
		KeyID:      "unknown-kid",
	}
	raw, _ := json.Marshal(payload)

	_, err = service.Decrypt(context.Background(), raw)
	assert.Error(suite.T(), err)
	assert.Contains(suite.T(), err.Error(), "decryption key not found")
}

func (suite *EncryptionTestSuite) TestDecryptFailsWhenKidMissing() {
	key, err := generateRandomKey(32)
	assert.NoError(suite.T(), err)
	service := newEncryptionService(key)

	encrypted, err := service.Encrypt(context.Background(), []byte("legacy-secret"))
	assert.NoError(suite.T(), err)

	var payload EncryptedData
	err = json.Unmarshal(encrypted, &payload)
	assert.NoError(suite.T(), err)

	// Simulate older payload without kid.
	payload.KeyID = ""
	raw, _ := json.Marshal(payload)

	_, err = service.Decrypt(context.Background(), raw)
	assert.Error(suite.T(), err)
	assert.Contains(suite.T(), err.Error(), "decryption key not found")
}

func (suite *EncryptionTestSuite) TestNon32() {
	// Test various key sizes
	testCases := []int{16, 24} // 128, 192 bits
	// Test data
	original := "This is a secret message that needs encryption!"
	for _, size := range testCases {
		key, err := generateRandomKey(size)
		assert.NoError(suite.T(), err, "Key generation should not produce an error")
		service := newEncryptionService(key)

		encrypted, err := service.Encrypt(context.Background(), []byte(original))
		assert.NoError(suite.T(), err, "Encryption should not produce an error")

		decrypted, err := service.Decrypt(context.Background(), encrypted)
		assert.NoError(suite.T(), err, "Decryption should not produce an error")

		assert.Equal(suite.T(), original, string(decrypted), "Decrypted data should match the original")
	}
}

func (suite *EncryptionTestSuite) TestWrongKeySize() {
	// Generate a key of incorrect size
	key, _ := generateRandomKey(30)
	service := newEncryptionService(key)
	_, err := service.Encrypt(context.Background(), []byte("Test data"))
	assert.Error(suite.T(), err, "Expected error due to wrong key size")
}

// resetSingleton resets the singleton state for testing purposes
func resetSingleton() {
	instance = nil
	once = sync.Once{}
}

func generateRandomKey(keySize int) ([]byte, error) {
	key := make([]byte, keySize)
	_, err := rand.Read(key)
	if err != nil {
		return nil, err
	}
	return key, nil
}
