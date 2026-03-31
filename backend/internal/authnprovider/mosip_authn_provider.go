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

// Package authnprovider provides authentication provider implementations.
package authnprovider

import (
	"bytes"
	"context"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	systemhttp "github.com/asgardeo/thunder/internal/system/http"

	"software.sslmate.com/src/go-pkcs12"
)

// MOSIPAuthnProvider is an authentication provider that communicates with MOSIP.
type MOSIPAuthnProvider struct {
	httpClient            systemhttp.HTTPClientInterface
	logger                *log.Logger
	otpBaseURL            string
	kycAuthBaseURL        string
	kycExchangeBaseURL    string
	partnerCertificateURL string
	p12FilePath           string
	p12Password           string
	individualIDType      string
	otpChannels           []string
	env                   string
	domainURI             string
	locales               []string
	kycExchangeRespType   string
	idaOtpID              string
	idaOtpVersion         string
	idaKycAuthID          string
	idaKycAuthVersion     string
	idaKycExchangeID      string
	idaKycExchangeVersion string
}

// NewMOSIPAuthnProvider creates a new MOSIP authentication provider.
func NewMOSIPAuthnProvider(
	httpClient systemhttp.HTTPClientInterface,
	otpBaseURL string,
	kycAuthBaseURL string,
	kycExchangeBaseURL string,
	partnerCertificateURL string,
	p12FilePath string,
	p12Password string,
	individualIDType string,
	otpChannels []string,
	env string,
	domainURI string,
	locales []string,
	kycExchangeRespType string,
	idaOtpID string,
	idaOtpVersion string,
	idaKycAuthID string,
	idaKycAuthVersion string,
	idaKycExchangeID string,
	idaKycExchangeVersion string,
) *MOSIPAuthnProvider {
	return &MOSIPAuthnProvider{
		httpClient:            httpClient,
		otpBaseURL:            otpBaseURL,
		kycAuthBaseURL:        kycAuthBaseURL,
		kycExchangeBaseURL:    kycExchangeBaseURL,
		partnerCertificateURL: partnerCertificateURL,
		p12FilePath:           p12FilePath,
		p12Password:           p12Password,
		individualIDType:      individualIDType,
		otpChannels:           otpChannels,
		env:                   env,
		domainURI:             domainURI,
		locales:               locales,
		kycExchangeRespType:   kycExchangeRespType,
		idaOtpID:              idaOtpID,
		idaOtpVersion:         idaOtpVersion,
		idaKycAuthID:          idaKycAuthID,
		idaKycAuthVersion:     idaKycAuthVersion,
		idaKycExchangeID:      idaKycExchangeID,
		idaKycExchangeVersion: idaKycExchangeVersion,
	}
}

//---------------------------------------------------------------------------------------------------------

func (m *MOSIPAuthnProvider) SendOTP(ctx context.Context, identifiers map[string]interface{}, metadata *AuthnMetadata) (*SendOTPResult, *AuthnProviderError) {

	transactionId, _ := metadata.AppMetadata["transaction_id"].(string)
	individualId, ok := identifiers["username"].(string)
	if !ok || individualId == "" {
		return nil, NewError(ErrorCodeMissingOrInvalidIndividualID, "missing or invalid individual_id in identifiers", "missing or invalid individual_id in identifiers")
	}
	req := IdaSendOtpRequest{
		ID:               m.idaOtpID,
		Version:          m.idaOtpVersion,
		IndividualID:     individualId,
		IndividualIDType: m.individualIDType,
		TransactionID:    transactionId,
		RequestTime:      GetUTCDateTime(),
		OtpChannel:       m.otpChannels,
	}

	otpRequestBytes, err := json.Marshal(req)
	if err != nil {
		return nil, NewError(ErrorCodeAuthenticationFailed, "Failed to marshal send OTP request", err.Error())
	}
	authHeaderValue := "Authorization"
	relyingPartyId := metadata.AppMetadata["app_id"].(string)
	clientId := metadata.AppMetadata["client_ids"].([]string)[0]
	requestSignature, err := m.GetRequestSignature(otpRequestBytes)
	if err != nil {
		return nil, NewError(ErrorCodeSystemError, "failed to get request signature", err.Error())
	}
	return m.callSendOtpEndpoint(otpRequestBytes, requestSignature, relyingPartyId, clientId, authHeaderValue)
}

// Authenticate implements [AuthnProviderInterface].
func (m *MOSIPAuthnProvider) Authenticate(ctx context.Context, identifiers map[string]interface{}, credentials map[string]interface{}, metadata *AuthnMetadata) (*AuthnResult, *AuthnProviderError) {
	authHeaderValue := "Authorization"
	relyingPartyId := metadata.AppMetadata["app_id"].(string)
	clientId := metadata.AppMetadata["client_ids"].([]string)[0]

	individualID, ok := identifiers["username"].(string)
	if !ok || individualID == "" {
		return nil, NewError(ErrorCodeMissingOrInvalidIndividualID, "missing or invalid individual_id in identifiers", "missing or invalid individual_id in identifiers")
	}

	claimsMetadataRequired := false
	requestTime := GetUTCDateTime()
	idaKycAuthRequest := &IdaKycAuthRequest{
		ID:                     m.idaKycAuthID,
		Version:                m.idaKycAuthVersion,
		RequestTime:            requestTime,
		DomainURI:              m.domainURI,
		Env:                    m.env,
		ConsentObtained:        true,
		IndividualID:           individualID,
		TransactionID:          metadata.AppMetadata["transaction_id"].(string),
		ClaimsMetadataRequired: &claimsMetadataRequired,
	}

	if len(credentials) == 0 {
		return nil, NewError(ErrorCodeAuthenticationFailed, "missing or invalid credentials", "missing or invalid credentials")
	}
	authRequest := &AuthRequest{
		Timestamp: requestTime,
	}
	if otp, ok := credentials["otp"].(string); ok && otp != "" {
		authRequest.OTP = otp
	} else if password, ok := credentials["password"].(string); ok && password != "" {
		authRequest.Password = password
	}
	authRequestBytes, err := json.Marshal(authRequest)
	if err != nil {
		return nil, NewError(ErrorCodeSystemError, "failed to marshal auth request", err.Error())
	}

	requestHash, err := GenerateHashWithErr(authRequestBytes)
	hexEncodedRequestHash, err := EncodeBytesToHexUpper(requestHash)
	symmetricKey, err := GenerateAESKey()
	if err != nil {
		return nil, NewError(ErrorCodeSystemError, "failed to generate symmetric key", err.Error())
	}
	encryptedRequest, err := SymmetricEncrypt(authRequestBytes, symmetricKey)
	if err != nil {
		return nil, NewError(ErrorCodeSystemError, "failed to encrypt request", err.Error())
	}
	encryptedRequestHash, err := SymmetricEncrypt(hexEncodedRequestHash, symmetricKey)
	if err != nil {
		return nil, NewError(ErrorCodeSystemError, "failed to encrypt request hash", err.Error())
	}
	generatedCert, err := m.fetchIDAPartnerCertificate()
	if err != nil {
		return nil, NewError(ErrorCodeSystemError, "failed to fetch IDA partner certificate", err.Error())
	}
	encryptedSessionKey, err := AsymmetricEncrypt(generatedCert.PublicKey.(*rsa.PublicKey), symmetricKey)
	if err != nil {
		return nil, NewError(ErrorCodeSystemError, "failed to encrypt session key", err.Error())
	}
	certThumbprint, err := GetCertificateThumbprint(generatedCert)
	if err != nil {
		return nil, NewError(ErrorCodeSystemError, "failed to get certificate thumbprint", err.Error())
	}

	idaKycAuthRequest.RequestSessionKey = B64EncodeBytes(encryptedSessionKey)
	idaKycAuthRequest.Request = B64EncodeBytes(encryptedRequest)
	idaKycAuthRequest.RequestHMAC = B64EncodeBytes(encryptedRequestHash)
	idaKycAuthRequest.Thumbprint = B64EncodeBytes(certThumbprint)

	requestBytes, err := json.Marshal(idaKycAuthRequest)
	if err != nil {
		return nil, NewError(ErrorCodeSystemError, "failed to marshal IDA KYC auth request", err.Error())
	}

	requestSignature, err := m.GetRequestSignature(requestBytes)
	if err != nil {
		return nil, NewError(ErrorCodeSystemError, "failed to get request signature", err.Error())
	}

	authResult, authnErr := m.callKycAuthEndpoint(requestBytes, requestSignature, relyingPartyId, clientId, claimsMetadataRequired, authHeaderValue)
	if authnErr != nil {
		return nil, authnErr
	}

	authResult.Token = strings.Join([]string{authResult.Token, individualID}, "||") // Clean up token if needed
	return authResult, nil
}

// GetAttributes implements [AuthnProviderInterface].
func (m *MOSIPAuthnProvider) GetAttributes(ctx context.Context, token string, requestedAttributes *RequestedAttributes, metadata *GetAttributesMetadata) (*GetAttributesResult, *AuthnProviderError) {
	username := strings.Split(token, "||")[1] // Extract username from token (assuming format "kycToken||username")
	kycToken := strings.Split(token, "||")[0] // Extract KYC token from token (assuming format "kycToken||username")
	consentedAttributes := []string{"sub"}

	if requestedAttributes != nil && len(requestedAttributes.Attributes) > 0 {
		for attr := range requestedAttributes.Attributes {
			consentedAttributes = append(consentedAttributes, attr)
		}
	}

	log.Printf("GetAttributes called with requestedAttributes: %v, consentedAttributes: %v", requestedAttributes.Attributes, consentedAttributes)

	idaKycExchangeRequest := &IdaKycExchangeRequest{
		ID:              m.idaKycExchangeID,
		Version:         m.idaKycExchangeVersion,
		RequestTime:     GetUTCDateTime(),
		TransactionID:   metadata.AppMetadata["transaction_id"].(string),
		KycToken:        kycToken,
		ConsentObtained: consentedAttributes,
		Locales:         m.locales,
		RespType:        m.kycExchangeRespType,
		IndividualId:    username,
	}

	requestBytes, err := json.Marshal(idaKycExchangeRequest)
	if err != nil {
		return nil, NewError(ErrorCodeSystemError, "failed to marshal IDA KYC exchange request", err.Error())
	}
	authHeaderValue := "Authorization"
	relyingPartyId := metadata.AppMetadata["app_id"].(string)
	clientId := metadata.AppMetadata["client_ids"].([]string)[0] // Assuming at least one client ID is present; adjust as needed
	requestSignature, err := m.GetRequestSignature(requestBytes)
	if err != nil {
		return nil, NewError(ErrorCodeSystemError, "failed to get request signature", err.Error())
	}
	return m.callKycExchangeEndpoint(requestBytes, requestSignature, relyingPartyId, clientId, authHeaderValue)
}

func (m *MOSIPAuthnProvider) GetRequestSignature(requestBody []byte) (string, error) {
	encodedRequestBody := B64EncodeBytes(requestBody)

	// Load RSA private key and certificate from .p12
	privateKey, signedCertificate, err := LoadRSAPrivateKeyAndCertFromP12(m.p12FilePath, m.p12Password)
	if err != nil {
		return "", NewError(ErrorCodeSystemError, "failed to load RSA private key and certificate from P12", err.Error())
	}

	// Create and sign JWT with x5c header
	jwtWithoutPayload, err := CreateAndSignJWTWithX5C(encodedRequestBody, privateKey, signedCertificate, "")
	if err != nil {
		return "", NewError(ErrorCodeSystemError, "failed to create and sign JWT", err.Error())
	}
	return jwtWithoutPayload, nil
}

// ---------------------------------------------------------------------------------------------------------

var ErrInvalidCertificate = errors.New("invalid or nil certificate")
var ErrCertificateParsing = errors.New("certificate parsing error")

// GetUTCDateTime returns current time in UTC as string in ISO 8601 format
func GetUTCDateTime() string {
	now := time.Now().UTC()
	//Go uses a reference time Mon Jan 2 15:04:05 MST 2006 to define the format pattern
	return now.Format("2006-01-02T15:04:05.000Z")
}

// B64EncodeBytes returns base64url-encoded string (no padding)
func B64EncodeBytes(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

// B64EncodeString encodes UTF-8 string → base64url (no padding)
func B64EncodeString(s string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(s))
}

// B64Decode decodes base64url string (both padded and unpadded accepted)
func B64Decode(s string) ([]byte, error) {
	// RawURLEncoding accepts both padded and unpadded input
	return base64.RawURLEncoding.DecodeString(s)
}

func GenerateHashWithErr(data []byte) ([]byte, error) {
	hash := sha256.Sum256(data)
	return hash[:], nil
}

func EncodeBytesToHexUpper(bytes []byte) ([]byte, error) {
	s := hex.EncodeToString(bytes)
	return []byte(strings.ToUpper(s)), nil
}

// Generate random 256-bit AES key
func GenerateAESKey() ([]byte, error) {
	key := make([]byte, 32) // 256 bits
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("failed to generate random key: %w", err)
	}
	return key, nil
}

// SymmetricEncrypt encrypts data using a fresh random AES-256-GCM key.
// Returns: ciphertext || IV (IV is appended at the end, matching the Java behavior)
// Also returns the raw AES key bytes so the caller can encrypt it separately (e.g. with RSA)
func SymmetricEncrypt(plaintext []byte, key []byte) (encrypted []byte, err error) {
	if len(key) != 32 {
		return nil, errors.New("AES key must be 32 bytes (AES-256)")
	}
	if len(plaintext) == 0 {
		return nil, errors.New("plaintext cannot be empty")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	nonceSize := 16                                          // 16 bytes nonce (IV) for GCM
	gcm, err := cipher.NewGCMWithNonceSize(block, nonceSize) // 16-byte nonce (IV)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM AEAD: %w", err)
	}

	// Generate 16-byte nonce (standard for GCM)
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt (no real AAD during encryption — we add dummy prefix later)
	ciphertext := gcm.Seal(nil, nonce, plaintext, nil) // nil = no AAD used in crypto operation

	// Final output: ciphertext+tag || nonce (IV) appended at the end (matches Java's behavior of appending IV)
	output := append(ciphertext, nonce...)

	return output, nil
}

func (m *MOSIPAuthnProvider) fetchIDAPartnerCertificate() (*x509.Certificate, error) {
	idaPartnerCertificateUrl := m.partnerCertificateURL
	req, err := http.NewRequest(http.MethodGet, idaPartnerCertificateUrl, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/text")

	resp, err := m.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("got %d instead of 200 OK", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// Clean up the input (remove extra whitespace/newlines if any)
	certData := strings.TrimSpace(string(body))

	// Decode PEM
	block, _ := pem.Decode([]byte(certData))
	if block == nil {
		// Log or handle as in your Java code
		log.Printf("Error parsing certificate: no valid PEM block found")
		return nil, fmt.Errorf("%w: no valid PEM block", ErrCertificateParsing)
	}

	// The block.Bytes is the DER-encoded certificate
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		// Append original error message (similar to your Java concatenation)
		return nil, fmt.Errorf("%w: %v", ErrCertificateParsing, err)
	}

	return cert, nil
}

func GetCertificateThumbprint(cert *x509.Certificate) ([]byte, error) {
	if cert == nil {
		return nil, ErrInvalidCertificate
	}

	if len(cert.Raw) == 0 {
		return nil, ErrInvalidCertificate
	}

	hash := sha256.Sum256(cert.Raw)
	return hash[:], nil
}

// AsymmetricEncrypt encrypts data using RSA-OAEP with SHA-256 + MGF1-SHA256
// (equivalent to Java's OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSpecified.DEFAULT))
//
// Parameters:
//   - pubKey: *rsa.PublicKey (parsed from X.509 certificate or JWK)
//   - data:   plaintext to encrypt (must be shorter than key size minus padding overhead)
//
// Returns encrypted ciphertext or error
func AsymmetricEncrypt(pubKey *rsa.PublicKey, data []byte) ([]byte, error) {
	if pubKey == nil {
		return nil, errors.New("invalid key: public key is nil")
	}

	if len(data) == 0 {
		return nil, errors.New("invalid data: empty input")
	}

	// MOSIP typically uses SHA-256 for OAEP (label digest) and MGF1
	hash := sha256.New()

	// EncryptOAEP uses the same hash for OAEP digest and MGF1 by default — matches most secure configs
	// (Java's explicit MGF1-SHA256 is equivalent here when hash=SHA-256)
	ciphertext, err := rsa.EncryptOAEP(
		hash,        // OAEP digest (SHA-256) + MGF1 digest (SHA-256)
		rand.Reader, // secure random source
		pubKey,
		data,
		nil, // label = nil (empty, matches PSpecified.DEFAULT)
	)
	if err != nil {
		return nil, fmt.Errorf("RSA-OAEP encryption failed: %w", err)
	}

	return ciphertext, nil
}

func LoadRSAPrivateKeyAndCertFromP12(
	p12Path string,
	password string,
) (*rsa.PrivateKey, *x509.Certificate, error) {
	pfxData, err := os.ReadFile(p12Path)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read .p12 file: %w", err)
	}

	// Decode → gets private key + the (single) certificate
	privateKeyAny, cert, err := pkcs12.Decode(pfxData, password)
	if err != nil {
		return nil, nil, fmt.Errorf("pkcs12 decode failed (wrong password or corrupt file?): %w", err)
	}

	rsaKey, ok := privateKeyAny.(*rsa.PrivateKey)
	if !ok {
		return nil, nil, errors.New("private key is not RSA")
	}

	if cert == nil {
		return nil, nil, errors.New("no certificate found in .p12")
	}

	return rsaKey, cert, nil
}

// CreateAndSignJWTWithX5C builds and signs JWT with x5c header
func CreateAndSignJWTWithX5C(
	base64Payload string, // pre-encoded base64url payload
	privateKey *rsa.PrivateKey,
	signedCertificate *x509.Certificate, // signed certificate (the leaf)
	kid string,
) (string, error) {
	// Prepare x5c values: base64(der) for each certificate
	x5c := make([]string, 1)
	der := signedCertificate.Raw
	x5c[0] = base64.StdEncoding.EncodeToString(der) // **standard** base64, **not** url-safe

	// Header with x5c
	header := map[string]interface{}{
		"alg": "RS256",
		"typ": "JWT",
		"x5c": x5c,
	}
	if kid != "" {
		header["kid"] = kid
	}

	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)

	payloadB64 := base64Payload

	input := headerB64 + "." + payloadB64

	// RS256 signature
	hash := sha256.Sum256([]byte(input))
	signature, err := rsa.SignPKCS1v15(nil, privateKey, crypto.SHA256, hash[:])
	if err != nil {
		return "", fmt.Errorf("rsa sign failed: %w", err)
	}

	sigB64 := base64.RawURLEncoding.EncodeToString(signature)

	// Final JWT: header.payload.signature
	// Note: the payload is not add in the JWT on return
	return headerB64 + ".." + sigB64, nil
}

func (m *MOSIPAuthnProvider) callSendOtpEndpoint(
	requestBody []byte, // already marshaled JSON of IdaKycAuthRequest
	signature string, // from helperService.getRequestSignature(requestBody)
	relyingPartyID string,
	clientID string,
	authHeaderValue string, // e.g. "Bearer xxx" or whatever you set
) (*SendOTPResult, *AuthnProviderError) {
	// Build full URI: .../relyingPartyId/clientId
	baseUrl := m.otpBaseURL
	u, err := url.Parse(baseUrl)
	if err != nil {
		return nil, NewError(ErrorCodeAuthenticationFailed, err.Error(), err.Error())
	}
	u.Path = strings.TrimRight(u.Path, "/") + "/" + url.PathEscape(relyingPartyID) + "/" + url.PathEscape(clientID)

	// Prepare request
	req, err := http.NewRequest(http.MethodPost, u.String(), bytes.NewReader(requestBody))
	if err != nil {
		return nil, NewError(ErrorCodeAuthenticationFailed, err.Error(), err.Error())
	}

	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	req.Header.Set(signatureHeaderName, signature)
	req.Header.Set(authorizationHeader, authHeaderValue)

	// Send request
	resp, err := m.httpClient.Do(req)
	if err != nil {
		return nil, NewError(ErrorCodeAuthenticationFailed, err.Error(), err.Error())
	}
	defer resp.Body.Close()

	// Read body once
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, NewError(ErrorCodeAuthenticationFailed, err.Error(), err.Error())
	}

	// Check status
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, NewError(ErrorCodeAuthenticationFailed, fmt.Sprintf("unexpected status: %d - %s", resp.StatusCode, string(bodyBytes)), string(bodyBytes))
	}

	// Parse response
	var wrapper IdaSendOtpResponse
	if err := json.Unmarshal(bodyBytes, &wrapper); err != nil {
		return nil, NewError(ErrorCodeAuthenticationFailed, "failed to parse IdaSendOtpResponse", err.Error())
	}

	// Success path
	if wrapper.Response != nil {
		return &SendOTPResult{
			MaskedEmail:  wrapper.Response.MaskedEmail,
			MaskedMobile: wrapper.Response.MaskedMobile,
		}, nil
	}

	log.Printf("Error response from IDA-OTP : %v, Errors: %+v", wrapper.Response, wrapper.Errors)

	// Error path
	if wrapper.Response == nil {
		return nil, NewError(ErrorCodeAuthenticationFailed, "response object is missing in wrapper", "response object is missing in wrapper")
	}

	if len(wrapper.Errors) == 0 {
		return nil, NewError(ErrorCodeAuthenticationFailed, "no errors in response wrapper", "no errors in response wrapper")
	}

	// Take first error (common pattern)
	firstErr := wrapper.Errors[0]
	return nil, NewError(ErrorCodeAuthenticationFailed, firstErr.ErrorCode, firstErr.ErrorMessage)
}

// PerformKycAuth sends the KYC auth request to IDA and processes the response
func (m *MOSIPAuthnProvider) callKycAuthEndpoint(
	requestBody []byte, // already marshaled JSON of IdaKycAuthRequest
	signature string, // from helperService.getRequestSignature(requestBody)
	relyingPartyID string,
	clientID string,
	claimsMetadataRequired bool,
	authHeaderValue string, // e.g. "Bearer xxx" or whatever you set
) (*AuthnResult, *AuthnProviderError) {
	// Build full URI: .../relyingPartyId/clientId
	baseUrl := m.kycAuthBaseURL
	u, err := url.Parse(baseUrl)
	if err != nil {
		return nil, NewError(ErrorCodeAuthenticationFailed, err.Error(), err.Error())
	}
	u.Path = strings.TrimRight(u.Path, "/") + "/" + url.PathEscape(relyingPartyID) + "/" + url.PathEscape(clientID)

	// Prepare request
	req, err := http.NewRequest(http.MethodPost, u.String(), bytes.NewReader(requestBody))
	if err != nil {
		return nil, NewError(ErrorCodeAuthenticationFailed, err.Error(), err.Error())
	}

	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	req.Header.Set(signatureHeaderName, signature)
	req.Header.Set(authorizationHeader, authHeaderValue)

	// Send request
	resp, err := m.httpClient.Do(req)
	if err != nil {
		return nil, NewError(ErrorCodeAuthenticationFailed, err.Error(), err.Error())
	}
	defer resp.Body.Close()

	// Read body once
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, NewError(ErrorCodeAuthenticationFailed, err.Error(), err.Error())
	}

	// Check status
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, NewError(ErrorCodeAuthenticationFailed, fmt.Sprintf("unexpected status: %d - %s", resp.StatusCode, string(bodyBytes)), string(bodyBytes))
	}

	// Parse response
	var wrapper IdaResponseWrapper
	if err := json.Unmarshal(bodyBytes, &wrapper); err != nil {
		return nil, NewError(ErrorCodeAuthenticationFailed, "failed to parse IdaResponseWrapper", err.Error())
	}

	// Success path
	if wrapper.Response != nil && wrapper.Response.KycStatus && wrapper.Response.KycToken != "" {
		return &AuthnResult{
			Token:  wrapper.Response.KycToken,
			UserID: wrapper.Response.AuthToken,
		}, nil
	}

	// Error path
	if wrapper.Response == nil {
		return nil, NewError(ErrorCodeAuthenticationFailed, "response object is missing in wrapper", "response object is missing in wrapper")
	}

	log.Printf("Error response from IDA - KycStatus: %v, Errors: %+v", wrapper.Response.KycStatus, wrapper.Errors)

	if len(wrapper.Errors) == 0 {
		return nil, NewError(ErrorCodeAuthenticationFailed, "no errors in response wrapper", "no errors in response wrapper")
	}

	// Take first error (common pattern)
	firstErr := wrapper.Errors[0]
	return nil, NewError(ErrorCodeAuthenticationFailed, firstErr.ErrorMessage, firstErr.ActionMessage)
}

// PerformKycExchange sends the KYC exchange request to IDA and processes the response
func (m *MOSIPAuthnProvider) callKycExchangeEndpoint(
	requestBody []byte,
	signature string,
	relyingPartyID string,
	clientID string,
	authHeaderValue string,
) (*GetAttributesResult, *AuthnProviderError) {
	// Build full URI: .../relyingPartyId/clientId
	baseUrl := m.kycExchangeBaseURL
	u, err := url.Parse(baseUrl)
	if err != nil {
		return nil, NewError(ErrorCodeAuthenticationFailed, err.Error(), err.Error())
	}
	u.Path = strings.TrimRight(u.Path, "/") + "/" + url.PathEscape(relyingPartyID) + "/" + url.PathEscape(clientID)

	// Prepare request
	req, err := http.NewRequest(http.MethodPost, u.String(), bytes.NewReader(requestBody))
	if err != nil {
		return nil, NewError(ErrorCodeAuthenticationFailed, err.Error(), err.Error())
	}

	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	req.Header.Set(signatureHeaderName, signature)
	req.Header.Set(authorizationHeader, authHeaderValue)

	// Send request
	resp, err := m.httpClient.Do(req)
	if err != nil {
		return nil, NewError(ErrorCodeAuthenticationFailed, err.Error(), err.Error())
	}
	defer resp.Body.Close()

	// Read body once
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, NewError(ErrorCodeAuthenticationFailed, err.Error(), err.Error())
	}

	// Check status
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, NewError(ErrorCodeAuthenticationFailed, fmt.Sprintf("unexpected status: %d - %s", resp.StatusCode, string(bodyBytes)), string(bodyBytes))
	}

	// Parse response
	var wrapper IdaKycExchangeResponseWrapper
	if err := json.Unmarshal(bodyBytes, &wrapper); err != nil {
		return nil, NewError(ErrorCodeAuthenticationFailed, "failed to parse IdaKycExchangeResponseWrapper", err.Error())
	}

	log.Printf("IDA KYC Exchange response wrapper: %+v", wrapper)

	// Success path
	if wrapper.Response != nil && wrapper.Response.EncryptedKyc != "" {
		userattributes, _ := decodeJWTUnsafe(wrapper.Response.EncryptedKyc)
		convertedAttributes := convertToAttributeResponseMap(userattributes)
		return &GetAttributesResult{
			UserID: "",
			AttributesResponse: &AttributesResponse{
				Attributes: convertedAttributes,
			},
		}, nil
	}

	// Error path
	if wrapper.Response == nil {
		return nil, NewError(ErrorCodeAuthenticationFailed, "response object is missing in wrapper", "response object is missing in wrapper")
	}

	log.Printf("Error response from IDA - exchange: %v, Errors: %+v", wrapper.Response, wrapper.Errors)

	if len(wrapper.Errors) == 0 {
		return nil, NewError(ErrorCodeAuthenticationFailed, "no errors in response wrapper", "no errors in response wrapper")
	}

	// Take first error (common pattern)
	firstErr := wrapper.Errors[0]
	return nil, NewError(ErrorCodeAuthenticationFailed, firstErr.ErrorMessage, firstErr.ActionMessage)
}

func decodeJWTUnsafe(token string) (map[string]interface{}, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid JWT format")
	}

	payload := parts[1]
	// Fix padding if needed
	payload += strings.Repeat("=", (4-len(payload)%4)%4)

	decoded, err := base64.URLEncoding.DecodeString(payload)
	if err != nil {
		return nil, err
	}

	var claims map[string]interface{}
	if err := json.Unmarshal(decoded, &claims); err != nil {
		return nil, err
	}

	return claims, nil
}

func convertToAttributeResponseMap(input map[string]interface{}) map[string]*AttributeResponse {
	result := make(map[string]*AttributeResponse)
	for key, value := range input {
		result[key] = &AttributeResponse{
			Value: value,
		}
	}
	return result
}

//---------------------------------------------------------------------------------------------------------

// IdaKycAuthRequest represents the top-level KYC authentication request
type IdaKycAuthRequest struct {
	ID                     string                 `json:"id,omitempty"`
	Version                string                 `json:"version,omitempty"`
	IndividualID           string                 `json:"individualId,omitempty"`
	IndividualIDType       string                 `json:"individualIdType,omitempty"`
	TransactionID          string                 `json:"transactionID,omitempty"`
	RequestTime            string                 `json:"requestTime,omitempty"` // usually ISO8601
	SpecVersion            string                 `json:"specVersion,omitempty"`
	Thumbprint             string                 `json:"thumbprint,omitempty"`
	DomainURI              string                 `json:"domainUri,omitempty"`
	Env                    string                 `json:"env,omitempty"`
	ConsentObtained        bool                   `json:"consentObtained"`
	Request                string                 `json:"request,omitempty"` // usually base64 encoded encrypted payload
	RequestHMAC            string                 `json:"requestHMAC,omitempty"`
	RequestSessionKey      string                 `json:"requestSessionKey,omitempty"`
	Metadata               map[string]interface{} `json:"metadata,omitempty"`
	AllowedKycAttributes   []string               `json:"allowedKycAttributes,omitempty"`
	ClaimsMetadataRequired *bool                  `json:"claimsMetadataRequired,omitempty"` // nullable boolean
}

// AuthRequest is the decrypted / inner authentication payload
type AuthRequest struct {
	OTP             string           `json:"otp,omitempty"`
	StaticPin       string           `json:"staticPin,omitempty"`
	Timestamp       string           `json:"timestamp,omitempty"` // or time.Time if you prefer
	Biometrics      []Biometric      `json:"biometrics,omitempty"`
	KeyBindedTokens []KeyBindedToken `json:"keyBindedTokens,omitempty"`
	Password        string           `json:"password,omitempty"`
}

// Biometric represents one biometric record (usually encoded & encrypted)
type Biometric struct {
	Data        string `json:"data,omitempty"` // base64(FMR / Iris / Face ...)
	Hash        string `json:"hash,omitempty"`
	SessionKey  string `json:"sessionKey,omitempty"`
	SpecVersion string `json:"specVersion,omitempty"`
	Thumbprint  string `json:"thumbprint,omitempty"`
}

// KeyBindedToken
type KeyBindedToken struct {
	Type   string `json:"type,omitempty"`
	Token  string `json:"token,omitempty"`
	Format string `json:"format,omitempty"`
}

// IdaKycAuthResponse represents the core KYC authentication response data
type IdaKycAuthResponse struct {
	KycToken               string `json:"kycToken,omitempty"`
	AuthToken              string `json:"authToken,omitempty"`
	KycStatus              bool   `json:"kycStatus"`
	VerifiedClaimsMetadata string `json:"verifiedClaimsMetadata,omitempty"`
}

// IdaResponseWrapper is the top-level response structure
// (commonly used in MOSIP/IDA style APIs)
type IdaResponseWrapper struct {
	ID            string              `json:"id,omitempty"`
	Version       string              `json:"version,omitempty"`
	TransactionID string              `json:"transactionID,omitempty"`
	ResponseTime  string              `json:"responseTime,omitempty"` // usually ISO8601 / RFC3339
	Response      *IdaKycAuthResponse `json:"response,omitempty"`
	Errors        []IdaError          `json:"errors,omitempty"`
}

// IdaError represents a single error entry in the response
type IdaError struct {
	ActionMessage string `json:"actionMessage,omitempty"`
	ErrorCode     string `json:"errorCode,omitempty"`
	ErrorMessage  string `json:"errorMessage,omitempty"`
}

// Constants (adjust as per your config)
const (
	signatureHeaderName = "signature"     // ← your SIGNATURE_HEADER_NAME
	authorizationHeader = "Authorization" // ← your AUTHORIZATION_HEADER_NAME
)

// SendOTPResult represents the result of an generate and notify OTP attempt.
type SendOTPResult struct {
	MaskedEmail  string `json:"maskedEmail,omitempty"`
	MaskedMobile string `json:"maskedMobile,omitempty"`
}

type IdaSendOtpRequest struct {
	ID               string   `json:"id,omitempty"`
	Version          string   `json:"version,omitempty"`
	IndividualID     string   `json:"individualId,omitempty"`
	IndividualIDType string   `json:"individualIdType,omitempty"`
	TransactionID    string   `json:"transactionID,omitempty"`
	RequestTime      string   `json:"requestTime,omitempty"`
	OtpChannel       []string `json:"otpChannel,omitempty"`
}

type IdaOtpResponse struct {
	MaskedEmail  string `json:"maskedEmail,omitempty"`
	MaskedMobile string `json:"maskedMobile,omitempty"`
}

type IdaSendOtpResponse struct {
	ID            string          `json:"id,omitempty"`
	Version       string          `json:"version,omitempty"`
	TransactionID string          `json:"transactionID,omitempty"`
	ResponseTime  string          `json:"responseTime,omitempty"`
	Errors        []Error         `json:"errors,omitempty"`
	Response      *IdaOtpResponse `json:"response,omitempty"`
}

type Error struct {
	ErrorCode    string `json:"errorCode,omitempty"`
	ErrorMessage string `json:"errorMessage,omitempty"`
}

type IdaKycExchangeRequest struct {
	ID                        string                   `json:"id,omitempty"`
	Version                   string                   `json:"version,omitempty"`
	RequestTime               string                   `json:"requestTime,omitempty"`
	TransactionID             string                   `json:"transactionID,omitempty"`
	KycToken                  string                   `json:"kycToken,omitempty"`
	ConsentObtained           []string                 `json:"consentObtained,omitempty"`
	Locales                   []string                 `json:"locales,omitempty"`
	RespType                  string                   `json:"respType,omitempty"`
	IndividualId              string                   `json:"individualId,omitempty"`
	Metadata                  map[string]interface{}   `json:"metadata,omitempty"`
	VerifiedConsentedClaims   []map[string]interface{} `json:"verifiedConsentedClaims,omitempty"`
	UnVerifiedConsentedClaims map[string]interface{}   `json:"unVerifiedConsentedClaims,omitempty"`
}

type IdaKycExchangeResponse struct {
	EncryptedKyc string `json:"encryptedKyc,omitempty"`
}

type IdaKycExchangeResponseWrapper struct {
	ID            string                  `json:"id,omitempty"`
	Version       string                  `json:"version,omitempty"`
	TransactionID string                  `json:"transactionID,omitempty"`
	ResponseTime  string                  `json:"responseTime,omitempty"`
	Response      *IdaKycExchangeResponse `json:"response,omitempty"`
	Errors        []IdaError              `json:"errors,omitempty"`
}
