/*
 * Copyright (c) 2026, WSO2 LLC. (https://www.wso2.com).
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

package runtime

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"

	"github.com/asgardeo/thunder/internal/system/config"
	"github.com/asgardeo/thunder/internal/system/crypto"
	"github.com/asgardeo/thunder/internal/system/error/serviceerror"
	i18ncore "github.com/asgardeo/thunder/internal/system/i18n/core"
	"github.com/asgardeo/thunder/internal/system/log"
	"github.com/asgardeo/thunder/tests/mocks/crypto/pki/pkimock"
)

// resetSingleton resets the singleton state for testing purposes.
func resetSingleton() {
	runtimeInstance = nil
	runtimeOnce = sync.Once{}
}

type RuntimeCryptoServiceTestSuite struct {
	suite.Suite
	rsaKey  *rsa.PrivateKey
	ecKey   *ecdsa.PrivateKey
	pkiMock *pkimock.PKIServiceInterfaceMock
}

func TestRuntimeCryptoServiceSuite(t *testing.T) {
	suite.Run(t, new(RuntimeCryptoServiceTestSuite))
}

func (suite *RuntimeCryptoServiceTestSuite) SetupSuite() {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NoError(suite.T(), err)
	suite.rsaKey = rsaKey

	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	assert.NoError(suite.T(), err)
	suite.ecKey = ecKey
}

func (suite *RuntimeCryptoServiceTestSuite) SetupTest() {
	resetSingleton()
	config.ResetServerRuntime()
	suite.pkiMock = pkimock.NewPKIServiceInterfaceMock(suite.T())
	testConfig := &config.Config{
		Crypto: config.CryptoConfig{
			Encryption: config.EncryptionConfig{
				Key: "2729a7928c79371e5f312167269294a14bb0660fd166b02a408a20fa73271580",
			},
		},
	}
	err := config.InitializeServerRuntime("/test/thunderid/home", testConfig)
	suite.NoError(err)
}

// selfSignedCert builds a minimal self-signed *x509.Certificate containing the given RSA public key.
func (suite *RuntimeCryptoServiceTestSuite) selfSignedCert() *x509.Certificate {
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &suite.rsaKey.PublicKey, suite.rsaKey)
	suite.NoError(err)
	cert, err := x509.ParseCertificate(certDER)
	suite.NoError(err)
	return cert
}

// ecSelfSignedCert builds a minimal self-signed *x509.Certificate containing the EC public key.
func (suite *RuntimeCryptoServiceTestSuite) ecSelfSignedCert() *x509.Certificate {
	template := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &suite.ecKey.PublicKey, suite.ecKey)
	suite.NoError(err)
	cert, err := x509.ParseCertificate(certDER)
	suite.NoError(err)
	return cert
}

func (suite *RuntimeCryptoServiceTestSuite) newKeyNotFoundErr() *serviceerror.ServiceError {
	return &serviceerror.ServiceError{
		Code: "PKI-60001",
		Error: i18ncore.I18nMessage{
			Key:          "error.key_not_found",
			DefaultValue: "key not found",
		},
	}
}

func (suite *RuntimeCryptoServiceTestSuite) TestAESGCM_EncryptDecrypt_RoundTrip() {
	svc := &runtimeCryptoService{
		pkiService: suite.pkiMock,
		logger:     log.GetLogger(),
	}

	plaintext := []byte("secret flow context data")
	params := crypto.AlgorithmParams{Algorithm: crypto.AlgorithmAESGCM}

	ciphertext, details, err := svc.Encrypt(context.Background(), crypto.KeyRef{}, params, plaintext)
	assert.NoError(suite.T(), err)
	assert.NotNil(suite.T(), ciphertext)
	assert.Nil(suite.T(), details, "AES-GCM should return nil CryptoDetails")
	assert.NotEqual(suite.T(), plaintext, ciphertext)

	recovered, err := svc.Decrypt(context.Background(), crypto.KeyRef{}, params, ciphertext)
	assert.NoError(suite.T(), err)
	assert.Equal(suite.T(), plaintext, recovered)
}

func (suite *RuntimeCryptoServiceTestSuite) TestAESGCM_Encrypt_ProducesUniqueCiphertexts() {
	svc := &runtimeCryptoService{
		pkiService: suite.pkiMock,
		logger:     log.GetLogger(),
	}
	params := crypto.AlgorithmParams{Algorithm: crypto.AlgorithmAESGCM}
	plaintext := []byte("same plaintext")

	ct1, _, err1 := svc.Encrypt(context.Background(), crypto.KeyRef{}, params, plaintext)
	ct2, _, err2 := svc.Encrypt(context.Background(), crypto.KeyRef{}, params, plaintext)
	assert.NoError(suite.T(), err1)
	assert.NoError(suite.T(), err2)
	assert.NotEqual(suite.T(), ct1, ct2, "AES-GCM should produce a unique ciphertext each call (random IV)")
}

func (suite *RuntimeCryptoServiceTestSuite) TestRSAOAEP256_EncryptDecrypt_RoundTrip() {
	cert := suite.selfSignedCert()
	suite.pkiMock.On("GetX509Certificate", "rsa-key-1").Return(cert, nil).Once()
	suite.pkiMock.On("GetPrivateKey", "rsa-key-1").Return(suite.rsaKey, nil).Once()

	svc := &runtimeCryptoService{
		pkiService: suite.pkiMock,
		logger:     log.GetLogger(),
	}

	encParams := crypto.AlgorithmParams{
		Algorithm: crypto.AlgorithmRSAOAEP256,
		RSAOAEP256: crypto.RSAOAEP256Params{
			ContentEncryptionAlgorithm: "A128GCM",
		},
	}
	keyRef := crypto.KeyRef{KeyID: "rsa-key-1"}

	encryptedCEK, details, err := svc.Encrypt(context.Background(), keyRef, encParams, nil)
	assert.NoError(suite.T(), err)
	assert.NotNil(suite.T(), encryptedCEK)
	assert.NotNil(suite.T(), details)
	assert.NotNil(suite.T(), details.CEK)
	assert.Len(suite.T(), details.CEK, 16, "A128GCM CEK should be 16 bytes")

	recoveredCEK, err := svc.Decrypt(context.Background(), keyRef,
		crypto.AlgorithmParams{Algorithm: crypto.AlgorithmRSAOAEP256}, encryptedCEK)
	assert.NoError(suite.T(), err)
	assert.Equal(suite.T(), details.CEK, recoveredCEK)

	suite.pkiMock.AssertExpectations(suite.T())
}

func (suite *RuntimeCryptoServiceTestSuite) TestRSAOAEP256_Encrypt_KeyNotFound() {
	suite.pkiMock.On("GetX509Certificate", "missing-key").Return(nil, suite.newKeyNotFoundErr()).Once()

	svc := &runtimeCryptoService{
		pkiService: suite.pkiMock,
		logger:     log.GetLogger(),
	}

	_, _, err := svc.Encrypt(context.Background(),
		crypto.KeyRef{KeyID: "missing-key"},
		crypto.AlgorithmParams{Algorithm: crypto.AlgorithmRSAOAEP256},
		[]byte("data"))
	assert.Error(suite.T(), err)
	assert.Contains(suite.T(), err.Error(), "missing-key")

	suite.pkiMock.AssertExpectations(suite.T())
}

func (suite *RuntimeCryptoServiceTestSuite) TestRSAOAEP256_Decrypt_PKINotInitialized() {
	svc := &runtimeCryptoService{
		pkiService: nil,
		logger:     log.GetLogger(),
	}

	_, err := svc.Decrypt(context.Background(),
		crypto.KeyRef{KeyID: "any"},
		crypto.AlgorithmParams{Algorithm: crypto.AlgorithmRSAOAEP256},
		[]byte("data"))
	assert.Error(suite.T(), err)
	assert.Contains(suite.T(), err.Error(), "PKI service not initialized")
}

func (suite *RuntimeCryptoServiceTestSuite) TestRSAOAEP256_Decrypt_KeyNotFound() {
	suite.pkiMock.On("GetPrivateKey", "missing-key").Return(nil, suite.newKeyNotFoundErr()).Once()

	svc := &runtimeCryptoService{
		pkiService: suite.pkiMock,
		logger:     log.GetLogger(),
	}

	_, err := svc.Decrypt(context.Background(),
		crypto.KeyRef{KeyID: "missing-key"},
		crypto.AlgorithmParams{Algorithm: crypto.AlgorithmRSAOAEP256},
		[]byte("data"))
	assert.Error(suite.T(), err)
	assert.Contains(suite.T(), err.Error(), "missing-key")

	suite.pkiMock.AssertExpectations(suite.T())
}

func (suite *RuntimeCryptoServiceTestSuite) TestEncrypt_UnsupportedAlgorithm() {
	svc := &runtimeCryptoService{
		pkiService: suite.pkiMock,
		logger:     log.GetLogger(),
	}

	_, _, err := svc.Encrypt(context.Background(),
		crypto.KeyRef{},
		crypto.AlgorithmParams{Algorithm: crypto.Algorithm("UNKNOWN")},
		[]byte("data"))
	assert.Error(suite.T(), err)
	assert.Contains(suite.T(), err.Error(), "unsupported algorithm")
}

func (suite *RuntimeCryptoServiceTestSuite) TestDecrypt_UnsupportedAlgorithm() {
	svc := &runtimeCryptoService{
		pkiService: suite.pkiMock,
		logger:     log.GetLogger(),
	}

	_, err := svc.Decrypt(context.Background(),
		crypto.KeyRef{},
		crypto.AlgorithmParams{Algorithm: crypto.Algorithm("UNKNOWN")},
		[]byte("data"))
	assert.Error(suite.T(), err)
	assert.Contains(suite.T(), err.Error(), "unsupported algorithm")
}

func (suite *RuntimeCryptoServiceTestSuite) TestECDHES_EncryptDecrypt_RoundTrip() {
	cert := suite.ecSelfSignedCert()
	suite.pkiMock.On("GetX509Certificate", "ec-key-1").Return(cert, nil).Once()
	suite.pkiMock.On("GetPrivateKey", "ec-key-1").Return(suite.ecKey, nil).Once()

	svc := &runtimeCryptoService{
		pkiService: suite.pkiMock,
		logger:     log.GetLogger(),
	}

	keyRef := crypto.KeyRef{KeyID: "ec-key-1"}
	params := crypto.AlgorithmParams{
		Algorithm: crypto.AlgorithmECDHES,
		ECDHES: crypto.ECDHESParams{
			ContentEncryptionAlgorithm: "A128GCM",
		},
	}

	encryptedKey, details, err := svc.Encrypt(context.Background(), keyRef, params, nil)
	assert.NoError(suite.T(), err)
	assert.Nil(suite.T(), encryptedKey, "ECDH-ES has no encrypted key")
	assert.NotNil(suite.T(), details)
	assert.NotNil(suite.T(), details.EPK)
	assert.NotNil(suite.T(), details.CEK)
	assert.Len(suite.T(), details.CEK, 16)

	decryptParams := crypto.AlgorithmParams{
		Algorithm: crypto.AlgorithmECDHES,
		ECDHES: crypto.ECDHESParams{
			EPK:                        details.EPK,
			ContentEncryptionAlgorithm: "A128GCM",
		},
	}
	recoveredCEK, err := svc.Decrypt(context.Background(), keyRef, decryptParams, nil)
	assert.NoError(suite.T(), err)
	assert.Equal(suite.T(), details.CEK, recoveredCEK)

	suite.pkiMock.AssertExpectations(suite.T())
}

func (suite *RuntimeCryptoServiceTestSuite) TestECDHESA128KW_EncryptDecrypt_RoundTrip() {
	cert := suite.ecSelfSignedCert()
	suite.pkiMock.On("GetX509Certificate", "ec-key-1").Return(cert, nil).Once()
	suite.pkiMock.On("GetPrivateKey", "ec-key-1").Return(suite.ecKey, nil).Once()

	svc := &runtimeCryptoService{
		pkiService: suite.pkiMock,
		logger:     log.GetLogger(),
	}

	keyRef := crypto.KeyRef{KeyID: "ec-key-1"}
	params := crypto.AlgorithmParams{
		Algorithm: crypto.AlgorithmECDHESA128KW,
		ECDHES: crypto.ECDHESParams{
			ContentEncryptionAlgorithm: "A128GCM",
		},
	}
	wrappedKey, details, err := svc.Encrypt(context.Background(), keyRef, params, nil)
	assert.NoError(suite.T(), err)
	assert.NotNil(suite.T(), wrappedKey)
	assert.NotNil(suite.T(), details)
	assert.NotNil(suite.T(), details.EPK)
	assert.NotNil(suite.T(), details.CEK)
	assert.Len(suite.T(), details.CEK, 16, "A128GCM CEK should be 16 bytes")

	decryptParams := crypto.AlgorithmParams{
		Algorithm: crypto.AlgorithmECDHESA128KW,
		ECDHES: crypto.ECDHESParams{
			EPK: details.EPK,
		},
	}
	recoveredCEK, err := svc.Decrypt(context.Background(), keyRef, decryptParams, wrappedKey)
	assert.NoError(suite.T(), err)
	assert.Equal(suite.T(), details.CEK, recoveredCEK)

	suite.pkiMock.AssertExpectations(suite.T())
}

func (suite *RuntimeCryptoServiceTestSuite) TestECDHES_Encrypt_MissingContentAlgorithm() {
	cert := suite.ecSelfSignedCert()
	suite.pkiMock.On("GetX509Certificate", "ec-key-1").Return(cert, nil).Once()

	svc := &runtimeCryptoService{
		pkiService: suite.pkiMock,
		logger:     log.GetLogger(),
	}

	_, _, err := svc.Encrypt(context.Background(),
		crypto.KeyRef{KeyID: "ec-key-1"},
		crypto.AlgorithmParams{Algorithm: crypto.AlgorithmECDHES},
		make([]byte, 16))
	assert.Error(suite.T(), err)
	assert.Contains(suite.T(), err.Error(), "ContentEncryptionAlgorithm required")

	suite.pkiMock.AssertExpectations(suite.T())
}

func (suite *RuntimeCryptoServiceTestSuite) TestECDHES_Decrypt_MissingEPK() {
	svc := &runtimeCryptoService{
		pkiService: suite.pkiMock,
		logger:     log.GetLogger(),
	}

	_, err := svc.Decrypt(context.Background(),
		crypto.KeyRef{KeyID: "ec-key-1"},
		crypto.AlgorithmParams{
			Algorithm: crypto.AlgorithmECDHES,
			ECDHES: crypto.ECDHESParams{
				ContentEncryptionAlgorithm: "A128GCM",
			},
		},
		nil)
	assert.Error(suite.T(), err)
	assert.Contains(suite.T(), err.Error(), "EPK required")
}
