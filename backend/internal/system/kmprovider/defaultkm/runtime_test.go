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

package defaultkm

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/thunder-id/thunder-id/internal/system/cryptolab"
	"github.com/thunder-id/thunder-id/internal/system/error/serviceerror"
	"github.com/thunder-id/thunder-id/internal/system/i18n/core"
	"github.com/thunder-id/thunder-id/internal/system/kmprovider"
	"github.com/thunder-id/thunder-id/tests/mocks/crypto/pki/pkimock"
)

const testKeyID = "test-key-id"

func newTestSvcErr() *serviceerror.ServiceError {
	return &serviceerror.ServiceError{
		Code:  "TEST-001",
		Error: core.I18nMessage{DefaultValue: "key not found"},
	}
}

func TestEncrypt_RSAOAEP256_SuccessViaConstructor(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	cert := &x509.Certificate{PublicKey: &rsaKey.PublicKey}

	pkiMock := pkimock.NewPKIServiceInterfaceMock(t)
	pkiMock.EXPECT().
		GetX509Certificate(testKeyID).
		Return(cert, nil)

	svc := NewRuntimeCryptoService(pkiMock, nil)

	params := cryptolab.AlgorithmParams{
		Algorithm: cryptolab.AlgorithmRSAOAEP256,
		RSAOAEP256: cryptolab.RSAOAEP256Params{
			ContentEncryptionAlgorithm: "A256GCM",
		},
	}
	wrappedCEK, details, err := svc.Encrypt(
		context.Background(), &kmprovider.KeyRef{KeyID: testKeyID}, params, nil,
	)
	require.NoError(t, err)
	assert.NotEmpty(t, wrappedCEK)
	assert.NotNil(t, details)
}

func TestEncrypt_RSAOAEP256_GetPublicKeyError(t *testing.T) {
	pkiMock := pkimock.NewPKIServiceInterfaceMock(t)
	pkiMock.EXPECT().
		GetX509Certificate(testKeyID).
		Return(nil, newTestSvcErr())

	svc := NewRuntimeCryptoService(pkiMock, nil)

	params := cryptolab.AlgorithmParams{
		Algorithm: cryptolab.AlgorithmRSAOAEP256,
		RSAOAEP256: cryptolab.RSAOAEP256Params{
			ContentEncryptionAlgorithm: "A256GCM",
		},
	}
	_, _, err := svc.Encrypt(context.Background(), &kmprovider.KeyRef{KeyID: testKeyID}, params, []byte("data"))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), testKeyID)
}

func TestEncrypt_ECDHES_Success(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	cert := &x509.Certificate{PublicKey: &ecKey.PublicKey}

	pkiMock := pkimock.NewPKIServiceInterfaceMock(t)
	pkiMock.EXPECT().
		GetX509Certificate(testKeyID).
		Return(cert, nil)

	svc := NewRuntimeCryptoService(pkiMock, nil)

	params := cryptolab.AlgorithmParams{
		Algorithm: cryptolab.AlgorithmECDHES,
		ECDHES: cryptolab.ECDHESParams{
			ContentEncryptionAlgorithm: "A128GCM",
		},
	}
	_, details, err := svc.Encrypt(context.Background(), &kmprovider.KeyRef{KeyID: testKeyID}, params, nil)
	require.NoError(t, err)
	assert.NotNil(t, details)
}

func TestEncrypt_ECDHES_GetPublicKeyError(t *testing.T) {
	pkiMock := pkimock.NewPKIServiceInterfaceMock(t)
	pkiMock.EXPECT().
		GetX509Certificate(testKeyID).
		Return(nil, newTestSvcErr())

	svc := NewRuntimeCryptoService(pkiMock, nil)

	params := cryptolab.AlgorithmParams{
		Algorithm: cryptolab.AlgorithmECDHES,
		ECDHES: cryptolab.ECDHESParams{
			ContentEncryptionAlgorithm: "A128GCM",
		},
	}
	_, _, err := svc.Encrypt(context.Background(), &kmprovider.KeyRef{KeyID: testKeyID}, params, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), testKeyID)
}

func TestEncrypt_UnsupportedAlgorithm(t *testing.T) {
	svc := NewRuntimeCryptoService(nil, nil)

	params := cryptolab.AlgorithmParams{Algorithm: "UNSUPPORTED"}
	_, _, err := svc.Encrypt(context.Background(), &kmprovider.KeyRef{KeyID: testKeyID}, params, []byte("data"))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported algorithm")
}

// Encrypt – RSA-OAEP-256
func TestEncrypt_RSAOAEP256_NilKeyRef(t *testing.T) {
	svc := &runtimeCryptoService{pkiService: pkimock.NewPKIServiceInterfaceMock(t)}
	params := cryptolab.AlgorithmParams{
		Algorithm:  cryptolab.AlgorithmRSAOAEP256,
		RSAOAEP256: cryptolab.RSAOAEP256Params{ContentEncryptionAlgorithm: "A256GCM"},
	}

	_, _, err := svc.Encrypt(context.Background(), nil, params, []byte("data"))
	assert.EqualError(t, err, "keyRef required for RSA-OAEP-256")
}

func TestEncrypt_RSAOAEP256_PKIError(t *testing.T) {
	pki := pkimock.NewPKIServiceInterfaceMock(t)
	pki.EXPECT().GetX509Certificate("key1").Return(nil, &serviceerror.InternalServerError)

	svc := &runtimeCryptoService{pkiService: pki}
	keyRef := &kmprovider.KeyRef{KeyID: "key1"}
	params := cryptolab.AlgorithmParams{
		Algorithm:  cryptolab.AlgorithmRSAOAEP256,
		RSAOAEP256: cryptolab.RSAOAEP256Params{ContentEncryptionAlgorithm: "A256GCM"},
	}

	_, _, err := svc.Encrypt(context.Background(), keyRef, params, []byte("data"))
	assert.Error(t, err)
}

func TestEncrypt_RSAOAEP256_NonRSAPublicKey(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	pki := pkimock.NewPKIServiceInterfaceMock(t)
	pki.EXPECT().GetX509Certificate("key1").Return(
		&x509.Certificate{PublicKey: &ecKey.PublicKey}, nil,
	)

	svc := &runtimeCryptoService{pkiService: pki}
	keyRef := &kmprovider.KeyRef{KeyID: "key1"}
	params := cryptolab.AlgorithmParams{
		Algorithm:  cryptolab.AlgorithmRSAOAEP256,
		RSAOAEP256: cryptolab.RSAOAEP256Params{ContentEncryptionAlgorithm: "A256GCM"},
	}

	_, _, err = svc.Encrypt(context.Background(), keyRef, params, []byte("data"))
	assert.EqualError(t, err, "key is not an RSA public key")
}

func TestEncrypt_RSAOAEP256_Success(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	pki := pkimock.NewPKIServiceInterfaceMock(t)
	pki.EXPECT().GetX509Certificate("key1").Return(
		&x509.Certificate{PublicKey: &rsaKey.PublicKey}, nil,
	)

	svc := &runtimeCryptoService{pkiService: pki}
	keyRef := &kmprovider.KeyRef{KeyID: "key1"}
	params := cryptolab.AlgorithmParams{
		Algorithm:  cryptolab.AlgorithmRSAOAEP256,
		RSAOAEP256: cryptolab.RSAOAEP256Params{ContentEncryptionAlgorithm: "A256GCM"},
	}

	ciphertext, details, err := svc.Encrypt(context.Background(), keyRef, params, nil)
	require.NoError(t, err)
	assert.NotEmpty(t, ciphertext)
	require.NotNil(t, details)
	assert.NotEmpty(t, details.CEK)
}

// Encrypt – ECDH-ES variants
func TestEncrypt_ECDHES_NilKeyRef(t *testing.T) {
	svc := &runtimeCryptoService{pkiService: pkimock.NewPKIServiceInterfaceMock(t)}
	params := cryptolab.AlgorithmParams{
		Algorithm: cryptolab.AlgorithmECDHES,
		ECDHES:    cryptolab.ECDHESParams{ContentEncryptionAlgorithm: "A256GCM"},
	}

	_, _, err := svc.Encrypt(context.Background(), nil, params, []byte("data"))
	assert.EqualError(t, err, "keyRef required for ECDH-ES")
}

func TestEncrypt_ECDHES_PKIError(t *testing.T) {
	pki := pkimock.NewPKIServiceInterfaceMock(t)
	pki.EXPECT().GetX509Certificate("key1").Return(nil, &serviceerror.InternalServerError)

	svc := &runtimeCryptoService{pkiService: pki}
	keyRef := &kmprovider.KeyRef{KeyID: "key1"}
	params := cryptolab.AlgorithmParams{
		Algorithm: cryptolab.AlgorithmECDHES,
		ECDHES:    cryptolab.ECDHESParams{ContentEncryptionAlgorithm: "A256GCM"},
	}

	_, _, err := svc.Encrypt(context.Background(), keyRef, params, []byte("data"))
	assert.Error(t, err)
}

func TestEncrypt_ECDHES_NonECPublicKey(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	pki := pkimock.NewPKIServiceInterfaceMock(t)
	pki.EXPECT().GetX509Certificate("key1").Return(
		&x509.Certificate{PublicKey: &rsaKey.PublicKey}, nil,
	)

	svc := &runtimeCryptoService{pkiService: pki}
	keyRef := &kmprovider.KeyRef{KeyID: "key1"}
	params := cryptolab.AlgorithmParams{
		Algorithm: cryptolab.AlgorithmECDHES,
		ECDHES:    cryptolab.ECDHESParams{ContentEncryptionAlgorithm: "A256GCM"},
	}

	_, _, err = svc.Encrypt(context.Background(), keyRef, params, nil)
	assert.EqualError(t, err, "key is not an EC public key")
}

func TestEncrypt_ECDHESVariants_Success(t *testing.T) {
	algorithms := []cryptolab.Algorithm{
		cryptolab.AlgorithmECDHES,
		cryptolab.AlgorithmECDHESA128KW,
		cryptolab.AlgorithmECDHESA256KW,
	}

	for _, alg := range algorithms {
		t.Run(string(alg), func(t *testing.T) {
			ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			require.NoError(t, err)

			pki := pkimock.NewPKIServiceInterfaceMock(t)
			pki.EXPECT().GetX509Certificate("key1").Return(
				&x509.Certificate{PublicKey: &ecKey.PublicKey}, nil,
			)

			svc := &runtimeCryptoService{pkiService: pki}
			keyRef := &kmprovider.KeyRef{KeyID: "key1"}
			params := cryptolab.AlgorithmParams{
				Algorithm: alg,
				ECDHES:    cryptolab.ECDHESParams{ContentEncryptionAlgorithm: "A256GCM"},
			}

			_, details, err := svc.Encrypt(context.Background(), keyRef, params, nil)
			require.NoError(t, err)
			require.NotNil(t, details)
			assert.NotNil(t, details.EPK)
			assert.NotEmpty(t, details.CEK)
		})
	}
}

// Decrypt – RSA-OAEP-256
func TestDecrypt_RSAOAEP256_NilKeyRef(t *testing.T) {
	svc := &runtimeCryptoService{pkiService: pkimock.NewPKIServiceInterfaceMock(t)}
	params := cryptolab.AlgorithmParams{Algorithm: cryptolab.AlgorithmRSAOAEP256}

	_, err := svc.Decrypt(context.Background(), nil, params, []byte("ciphertext"))
	assert.EqualError(t, err, "keyRef required for RSA-OAEP-256")
}

func TestDecrypt_RSAOAEP256_PKIError(t *testing.T) {
	pki := pkimock.NewPKIServiceInterfaceMock(t)
	pki.EXPECT().GetPrivateKey("key1").Return(nil, &serviceerror.InternalServerError)

	svc := &runtimeCryptoService{pkiService: pki}
	keyRef := &kmprovider.KeyRef{KeyID: "key1"}
	params := cryptolab.AlgorithmParams{Algorithm: cryptolab.AlgorithmRSAOAEP256}

	_, err := svc.Decrypt(context.Background(), keyRef, params, []byte("ciphertext"))
	assert.Error(t, err)
}

func TestDecrypt_RSAOAEP256_NonRSAPrivateKey(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	pki := pkimock.NewPKIServiceInterfaceMock(t)
	pki.EXPECT().GetPrivateKey("key1").Return(ecKey, nil)

	svc := &runtimeCryptoService{pkiService: pki}
	keyRef := &kmprovider.KeyRef{KeyID: "key1"}
	params := cryptolab.AlgorithmParams{Algorithm: cryptolab.AlgorithmRSAOAEP256}

	_, err = svc.Decrypt(context.Background(), keyRef, params, []byte("ciphertext"))
	assert.EqualError(t, err, "key is not an RSA private key")
}

func TestDecrypt_RSAOAEP256_RoundTrip(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	pki := pkimock.NewPKIServiceInterfaceMock(t)
	pki.EXPECT().GetX509Certificate("key1").Return(
		&x509.Certificate{PublicKey: &rsaKey.PublicKey}, nil,
	)
	pki.EXPECT().GetPrivateKey("key1").Return(rsaKey, nil)

	svc := &runtimeCryptoService{pkiService: pki}
	keyRef := &kmprovider.KeyRef{KeyID: "key1"}
	encParams := cryptolab.AlgorithmParams{
		Algorithm:  cryptolab.AlgorithmRSAOAEP256,
		RSAOAEP256: cryptolab.RSAOAEP256Params{ContentEncryptionAlgorithm: "A256GCM"},
	}

	wrappedCEK, details, err := svc.Encrypt(context.Background(), keyRef, encParams, nil)
	require.NoError(t, err)
	require.NotNil(t, details)

	decParams := cryptolab.AlgorithmParams{Algorithm: cryptolab.AlgorithmRSAOAEP256}
	unwrappedCEK, err := svc.Decrypt(context.Background(), keyRef, decParams, wrappedCEK)
	require.NoError(t, err)
	assert.Equal(t, details.CEK, unwrappedCEK)
}

// Decrypt – ECDH-ES variants
func TestDecrypt_ECDHES_NilKeyRef(t *testing.T) {
	svc := &runtimeCryptoService{pkiService: pkimock.NewPKIServiceInterfaceMock(t)}
	params := cryptolab.AlgorithmParams{Algorithm: cryptolab.AlgorithmECDHES}

	_, err := svc.Decrypt(context.Background(), nil, params, nil)
	assert.EqualError(t, err, "keyRef required for ECDH-ES")
}

func TestDecrypt_ECDHES_PKIError(t *testing.T) {
	pki := pkimock.NewPKIServiceInterfaceMock(t)
	pki.EXPECT().GetPrivateKey("key1").Return(nil, &serviceerror.InternalServerError)

	svc := &runtimeCryptoService{pkiService: pki}
	keyRef := &kmprovider.KeyRef{KeyID: "key1"}
	params := cryptolab.AlgorithmParams{Algorithm: cryptolab.AlgorithmECDHES}

	_, err := svc.Decrypt(context.Background(), keyRef, params, nil)
	assert.Error(t, err)
}

func TestDecrypt_ECDHES_NonECPrivateKey(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	pki := pkimock.NewPKIServiceInterfaceMock(t)
	pki.EXPECT().GetPrivateKey("key1").Return(rsaKey, nil)

	svc := &runtimeCryptoService{pkiService: pki}
	keyRef := &kmprovider.KeyRef{KeyID: "key1"}
	params := cryptolab.AlgorithmParams{Algorithm: cryptolab.AlgorithmECDHES}

	_, err = svc.Decrypt(context.Background(), keyRef, params, nil)
	assert.EqualError(t, err, "key is not an EC private key")
}

func TestDecrypt_ECDHESVariants_RoundTrip(t *testing.T) {
	algorithms := []cryptolab.Algorithm{
		cryptolab.AlgorithmECDHES,
		cryptolab.AlgorithmECDHESA128KW,
		cryptolab.AlgorithmECDHESA256KW,
	}

	for _, alg := range algorithms {
		t.Run(string(alg), func(t *testing.T) {
			ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			require.NoError(t, err)

			pki := pkimock.NewPKIServiceInterfaceMock(t)
			pki.EXPECT().GetX509Certificate("key1").Return(
				&x509.Certificate{PublicKey: &ecKey.PublicKey}, nil,
			)
			pki.EXPECT().GetPrivateKey("key1").Return(ecKey, nil)

			svc := &runtimeCryptoService{pkiService: pki}
			keyRef := &kmprovider.KeyRef{KeyID: "key1"}

			encParams := cryptolab.AlgorithmParams{
				Algorithm: alg,
				ECDHES:    cryptolab.ECDHESParams{ContentEncryptionAlgorithm: "A256GCM"},
			}
			ciphertext, encDetails, err := svc.Encrypt(context.Background(), keyRef, encParams, nil)
			require.NoError(t, err)
			require.NotNil(t, encDetails)

			decParams := cryptolab.AlgorithmParams{
				Algorithm: alg,
				ECDHES:    cryptolab.ECDHESParams{EPK: encDetails.EPK, ContentEncryptionAlgorithm: "A256GCM"},
			}
			derivedCEK, err := svc.Decrypt(context.Background(), keyRef, decParams, ciphertext)
			require.NoError(t, err)
			assert.Equal(t, encDetails.CEK, derivedCEK)
		})
	}
}
