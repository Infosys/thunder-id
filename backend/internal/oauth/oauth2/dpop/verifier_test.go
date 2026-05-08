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

package dpop

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/thunder-id/thunder-id/internal/oauth/oauth2/jti"
	"github.com/thunder-id/thunder-id/internal/system/cryptolab"
	"github.com/thunder-id/thunder-id/tests/mocks/oauth/oauth2/jtimock"
)

const testAccessToken = "abc.def.ghi"

type signer struct {
	alg     string
	signAlg cryptolab.SignAlgorithm
	priv    any
	jwk     map[string]any
}

func newPS256Signer(t *testing.T) *signer {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	return &signer{
		alg:     "PS256",
		signAlg: cryptolab.RSAPSSSHA256,
		priv:    priv,
		jwk: map[string]any{
			"kty": "RSA",
			"n":   base64.RawURLEncoding.EncodeToString(priv.N.Bytes()),
			"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(priv.E)).Bytes()),
		},
	}
}

func newRS256Signer(t *testing.T) *signer {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	return &signer{
		alg:     "RS256",
		signAlg: cryptolab.RSASHA256,
		priv:    priv,
		jwk: map[string]any{
			"kty": "RSA",
			"n":   base64.RawURLEncoding.EncodeToString(priv.N.Bytes()),
			"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(priv.E)).Bytes()),
		},
	}
}

func newEdDSASigner(t *testing.T) *signer {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	return &signer{
		alg:     "EdDSA",
		signAlg: cryptolab.ED25519,
		priv:    priv,
		jwk: map[string]any{
			"kty": "OKP",
			"crv": "Ed25519",
			"x":   base64.RawURLEncoding.EncodeToString(pub),
		},
	}
}

// signProof builds a DPoP JWS. Header overrides take precedence over the signer's
// defaults so tests can mutate alg/typ/jwk.
func (s *signer) signProof(t *testing.T, headerOverrides, payload map[string]any) string {
	t.Helper()
	header := map[string]any{
		"typ": dpopJWTType,
		"alg": s.alg,
		"jwk": s.jwk,
	}
	for k, v := range headerOverrides {
		if v == nil {
			delete(header, k)
		} else {
			header[k] = v
		}
	}

	hb, err := json.Marshal(header)
	require.NoError(t, err)
	pb, err := json.Marshal(payload)
	require.NoError(t, err)

	signingInput := base64.RawURLEncoding.EncodeToString(hb) + "." + base64.RawURLEncoding.EncodeToString(pb)
	sig, err := cryptolab.Generate([]byte(signingInput), s.signAlg, s.priv)
	require.NoError(t, err)
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func defaultPayload(now time.Time) map[string]any {
	return map[string]any{
		"jti": "jti-1",
		"htm": "POST",
		"htu": "https://as.example.com/oauth2/token",
		"iat": now.Unix(),
	}
}

func defaultParams() VerifyParams {
	return VerifyParams{
		HTM: "POST",
		HTU: "https://as.example.com/oauth2/token",
	}
}

func newTestVerifier(store jti.StoreInterface, now time.Time) *verifier {
	v := &verifier{
		jtiStore: store,
		allowedAlgs: map[string]struct{}{
			"ES256": {}, "PS256": {}, "EdDSA": {}, "ES384": {}, "ES512": {}, "RS256": {},
		},
		iatWindow:    60 * time.Second,
		leeway:       5 * time.Second,
		maxJTILength: 256,
		now:          func() time.Time { return now },
	}
	return v
}

func expectInsert(m *jtimock.StoreInterfaceMock) {
	m.On("RecordJTI", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(true, nil).Once()
}

func TestVerify_HappyPath_PS256(t *testing.T) {
	now := time.Unix(1700000000, 0)
	store := jtimock.NewStoreInterfaceMock(t)
	expectInsert(store)
	v := newTestVerifier(store, now)
	s := newPS256Signer(t)

	params := defaultParams()
	params.Proof = s.signProof(t, nil, defaultPayload(now))

	res, err := v.Verify(context.Background(), params)
	require.NoError(t, err)
	assert.Equal(t, "PS256", res.Alg)
}

func TestVerify_HappyPath_RS256(t *testing.T) {
	now := time.Unix(1700000000, 0)
	store := jtimock.NewStoreInterfaceMock(t)
	expectInsert(store)
	v := newTestVerifier(store, now)
	s := newRS256Signer(t)

	params := defaultParams()
	params.Proof = s.signProof(t, nil, defaultPayload(now))

	res, err := v.Verify(context.Background(), params)
	require.NoError(t, err)
	assert.Equal(t, "RS256", res.Alg)
}

func TestVerify_HappyPath_EdDSA(t *testing.T) {
	now := time.Unix(1700000000, 0)
	store := jtimock.NewStoreInterfaceMock(t)
	expectInsert(store)
	v := newTestVerifier(store, now)
	s := newEdDSASigner(t)

	params := defaultParams()
	params.Proof = s.signProof(t, nil, defaultPayload(now))

	res, err := v.Verify(context.Background(), params)
	require.NoError(t, err)
	assert.Equal(t, "EdDSA", res.Alg)
}

func TestVerify_ExpectedJktMatch(t *testing.T) {
	now := time.Unix(1700000000, 0)
	store := jtimock.NewStoreInterfaceMock(t)
	expectInsert(store)
	v := newTestVerifier(store, now)
	s := newPS256Signer(t)

	jkt, err := ComputeJKT(s.jwk)
	require.NoError(t, err)

	params := defaultParams()
	params.Proof = s.signProof(t, nil, defaultPayload(now))
	params.ExpectedJkt = jkt

	res, err := v.Verify(context.Background(), params)
	require.NoError(t, err)
	assert.True(t, res.Confirmed)
}

func TestVerify_ExpectedJktMismatch(t *testing.T) {
	now := time.Unix(1700000000, 0)
	// Mismatch is detected before the store is touched, so no expectation is registered.
	store := jtimock.NewStoreInterfaceMock(t)
	v := newTestVerifier(store, now)
	s := newPS256Signer(t)

	params := defaultParams()
	params.Proof = s.signProof(t, nil, defaultPayload(now))
	params.ExpectedJkt = "definitely-not-the-jkt"

	_, err := v.Verify(context.Background(), params)
	assert.ErrorIs(t, err, ErrJktMismatch)
}

func TestVerify_AccessTokenHashMatch(t *testing.T) {
	now := time.Unix(1700000000, 0)
	store := jtimock.NewStoreInterfaceMock(t)
	expectInsert(store)
	v := newTestVerifier(store, now)
	s := newPS256Signer(t)

	at := testAccessToken
	sum := sha256.Sum256([]byte(at))
	ath := base64.RawURLEncoding.EncodeToString(sum[:])

	payload := defaultPayload(now)
	payload["ath"] = ath
	params := defaultParams()
	params.Proof = s.signProof(t, nil, payload)
	params.AccessToken = at

	_, err := v.Verify(context.Background(), params)
	assert.NoError(t, err)
}

func TestVerify_AccessTokenHashMismatch(t *testing.T) {
	now := time.Unix(1700000000, 0)
	store := jtimock.NewStoreInterfaceMock(t)
	v := newTestVerifier(store, now)
	s := newPS256Signer(t)

	payload := defaultPayload(now)
	payload["ath"] = "tampered"
	params := defaultParams()
	params.Proof = s.signProof(t, nil, payload)
	params.AccessToken = testAccessToken

	_, err := v.Verify(context.Background(), params)
	assert.ErrorIs(t, err, ErrInvalidProof)
}

func TestVerify_AccessTokenHashMissingClaim(t *testing.T) {
	now := time.Unix(1700000000, 0)
	store := jtimock.NewStoreInterfaceMock(t)
	v := newTestVerifier(store, now)
	s := newPS256Signer(t)

	params := defaultParams()
	params.Proof = s.signProof(t, nil, defaultPayload(now))
	params.AccessToken = testAccessToken

	_, err := v.Verify(context.Background(), params)
	assert.ErrorIs(t, err, ErrInvalidProof)
}

func TestVerify_Replay(t *testing.T) {
	now := time.Unix(1700000000, 0)
	store := jtimock.NewStoreInterfaceMock(t)
	store.On("RecordJTI", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(true, nil).Once()
	store.On("RecordJTI", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(false, nil).Once()

	v := newTestVerifier(store, now)
	s := newPS256Signer(t)

	proof := s.signProof(t, nil, defaultPayload(now))
	params := defaultParams()
	params.Proof = proof

	_, err := v.Verify(context.Background(), params)
	require.NoError(t, err)

	_, err = v.Verify(context.Background(), params)
	assert.ErrorIs(t, err, ErrReplayedProof)
}

func TestVerify_StoreError(t *testing.T) {
	now := time.Unix(1700000000, 0)
	store := jtimock.NewStoreInterfaceMock(t)
	store.On("RecordJTI", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(false, errors.New("store down")).Once()
	v := newTestVerifier(store, now)
	s := newPS256Signer(t)

	params := defaultParams()
	params.Proof = s.signProof(t, nil, defaultPayload(now))

	_, err := v.Verify(context.Background(), params)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "store down")
}

func TestVerify_FailureModes(t *testing.T) {
	// Each subtest constructs its own verifier and mock so expectations stay isolated and
	// failure modes can't accidentally leak state across cases.
	now := time.Unix(1700000000, 0)

	t.Run("missing typ", func(t *testing.T) {
		v := newTestVerifier(jtimock.NewStoreInterfaceMock(t), now)
		s := newPS256Signer(t)
		proof := s.signProof(t, map[string]any{"typ": "JWT"}, defaultPayload(now))
		params := defaultParams()
		params.Proof = proof
		_, err := v.Verify(context.Background(), params)
		assert.ErrorIs(t, err, ErrInvalidProof)
	})

	t.Run("alg none rejected", func(t *testing.T) {
		v := newTestVerifier(jtimock.NewStoreInterfaceMock(t), now)
		s := newPS256Signer(t)
		header := map[string]any{"typ": dpopJWTType, "alg": "none", "jwk": s.jwk}
		hb, _ := json.Marshal(header)
		pb, _ := json.Marshal(defaultPayload(now))
		token := base64.RawURLEncoding.EncodeToString(hb) + "." +
			base64.RawURLEncoding.EncodeToString(pb) + "."
		params := defaultParams()
		params.Proof = token
		_, err := v.Verify(context.Background(), params)
		assert.ErrorIs(t, err, ErrInvalidProof)
	})

	t.Run("alg HS256 rejected", func(t *testing.T) {
		v := newTestVerifier(jtimock.NewStoreInterfaceMock(t), now)
		s := newPS256Signer(t)
		header := map[string]any{"typ": dpopJWTType, "alg": "HS256", "jwk": s.jwk}
		hb, _ := json.Marshal(header)
		pb, _ := json.Marshal(defaultPayload(now))
		token := base64.RawURLEncoding.EncodeToString(hb) + "." +
			base64.RawURLEncoding.EncodeToString(pb) + ".sig"
		params := defaultParams()
		params.Proof = token
		_, err := v.Verify(context.Background(), params)
		assert.ErrorIs(t, err, ErrInvalidProof)
	})

	t.Run("alg outside allowlist rejected", func(t *testing.T) {
		v := newTestVerifier(jtimock.NewStoreInterfaceMock(t), now)
		v.allowedAlgs = map[string]struct{}{"ES256": {}}
		s := newPS256Signer(t)
		params := defaultParams()
		params.Proof = s.signProof(t, nil, defaultPayload(now))
		_, err := v.Verify(context.Background(), params)
		assert.ErrorIs(t, err, ErrInvalidProof)
	})

	t.Run("missing jwk header", func(t *testing.T) {
		v := newTestVerifier(jtimock.NewStoreInterfaceMock(t), now)
		s := newPS256Signer(t)
		proof := s.signProof(t, map[string]any{"jwk": nil}, defaultPayload(now))
		params := defaultParams()
		params.Proof = proof
		_, err := v.Verify(context.Background(), params)
		assert.ErrorIs(t, err, ErrInvalidProof)
	})

	t.Run("private key in jwk rejected", func(t *testing.T) {
		v := newTestVerifier(jtimock.NewStoreInterfaceMock(t), now)
		s := newPS256Signer(t)
		jwkWithPriv := map[string]any{}
		for k, v := range s.jwk {
			jwkWithPriv[k] = v
		}
		jwkWithPriv["d"] = "NOT-PUBLIC-MATERIAL"
		proof := s.signProof(t, map[string]any{"jwk": jwkWithPriv}, defaultPayload(now))
		params := defaultParams()
		params.Proof = proof
		_, err := v.Verify(context.Background(), params)
		require.ErrorIs(t, err, ErrInvalidProof)
		assert.Contains(t, err.Error(), "private")
	})

	t.Run("htm mismatch", func(t *testing.T) {
		v := newTestVerifier(jtimock.NewStoreInterfaceMock(t), now)
		s := newPS256Signer(t)
		payload := defaultPayload(now)
		payload["htm"] = "GET"
		proof := s.signProof(t, nil, payload)
		params := defaultParams()
		params.Proof = proof
		_, err := v.Verify(context.Background(), params)
		assert.ErrorIs(t, err, ErrInvalidProof)
	})

	t.Run("htu mismatch", func(t *testing.T) {
		v := newTestVerifier(jtimock.NewStoreInterfaceMock(t), now)
		s := newPS256Signer(t)
		payload := defaultPayload(now)
		payload["htu"] = "https://other.example.com/token"
		proof := s.signProof(t, nil, payload)
		params := defaultParams()
		params.Proof = proof
		_, err := v.Verify(context.Background(), params)
		assert.ErrorIs(t, err, ErrInvalidProof)
	})

	t.Run("htu equivalent under canonicalization", func(t *testing.T) {
		// Different surface form, same canonical URL ⇒ accepted, so the store is touched.
		store := jtimock.NewStoreInterfaceMock(t)
		expectInsert(store)
		v := newTestVerifier(store, now)
		s := newPS256Signer(t)
		payload := defaultPayload(now)
		payload["htu"] = "HTTPS://AS.EXAMPLE.COM:443/oauth2/token?ignored=1"
		proof := s.signProof(t, nil, payload)
		params := defaultParams()
		params.Proof = proof
		_, err := v.Verify(context.Background(), params)
		assert.NoError(t, err)
	})

	t.Run("iat too old", func(t *testing.T) {
		v := newTestVerifier(jtimock.NewStoreInterfaceMock(t), now)
		s := newPS256Signer(t)
		old := now.Add(-2 * time.Minute) // outside iatWindow + leeway = 65s
		payload := defaultPayload(old)
		proof := s.signProof(t, nil, payload)
		params := defaultParams()
		params.Proof = proof
		_, err := v.Verify(context.Background(), params)
		assert.ErrorIs(t, err, ErrInvalidProof)
	})

	t.Run("iat in future beyond leeway", func(t *testing.T) {
		v := newTestVerifier(jtimock.NewStoreInterfaceMock(t), now)
		s := newPS256Signer(t)
		future := now.Add(1 * time.Hour)
		payload := defaultPayload(future)
		proof := s.signProof(t, nil, payload)
		params := defaultParams()
		params.Proof = proof
		_, err := v.Verify(context.Background(), params)
		assert.ErrorIs(t, err, ErrInvalidProof)
	})

	t.Run("missing jti", func(t *testing.T) {
		v := newTestVerifier(jtimock.NewStoreInterfaceMock(t), now)
		s := newPS256Signer(t)
		payload := defaultPayload(now)
		delete(payload, "jti")
		proof := s.signProof(t, nil, payload)
		params := defaultParams()
		params.Proof = proof
		_, err := v.Verify(context.Background(), params)
		assert.ErrorIs(t, err, ErrInvalidProof)
	})

	t.Run("jti too long", func(t *testing.T) {
		v := newTestVerifier(jtimock.NewStoreInterfaceMock(t), now)
		s := newPS256Signer(t)
		payload := defaultPayload(now)
		long := make([]byte, 257)
		for i := range long {
			long[i] = 'a'
		}
		payload["jti"] = string(long)
		proof := s.signProof(t, nil, payload)
		params := defaultParams()
		params.Proof = proof
		_, err := v.Verify(context.Background(), params)
		assert.ErrorIs(t, err, ErrInvalidProof)
	})

	t.Run("tampered signature", func(t *testing.T) {
		v := newTestVerifier(jtimock.NewStoreInterfaceMock(t), now)
		s := newPS256Signer(t)
		proof := s.signProof(t, nil, defaultPayload(now))
		// Flip a char in the middle of the signature segment. Tampering only the very last
		// base64 char is unreliable because RawURLEncoding's trailing low-order bits may be
		// unused depending on the signature length.
		idx := len(proof) - 5
		flipped := byte('A')
		if proof[idx] == 'A' {
			flipped = 'B'
		}
		tampered := proof[:idx] + string(flipped) + proof[idx+1:]
		params := defaultParams()
		params.Proof = tampered
		_, err := v.Verify(context.Background(), params)
		assert.ErrorIs(t, err, ErrInvalidProof)
	})

	t.Run("malformed proof", func(t *testing.T) {
		v := newTestVerifier(jtimock.NewStoreInterfaceMock(t), now)
		params := defaultParams()
		params.Proof = "not.a.jwt"
		_, err := v.Verify(context.Background(), params)
		assert.ErrorIs(t, err, ErrInvalidProof)
	})

	t.Run("empty proof", func(t *testing.T) {
		v := newTestVerifier(jtimock.NewStoreInterfaceMock(t), now)
		params := defaultParams()
		params.Proof = ""
		_, err := v.Verify(context.Background(), params)
		assert.ErrorIs(t, err, ErrInvalidProof)
	})
}

func TestVerify_NewVerifierConstruction(t *testing.T) {
	v := newVerifier(jtimock.NewStoreInterfaceMock(t), []string{"ES256", "EdDSA"}, 60, 5, 256)
	require.NotNil(t, v)
	impl, ok := v.(*verifier)
	require.True(t, ok)
	assert.Contains(t, impl.allowedAlgs, "ES256")
	assert.Contains(t, impl.allowedAlgs, "EdDSA")
	assert.Equal(t, 60*time.Second, impl.iatWindow)
	assert.Equal(t, 5*time.Second, impl.leeway)
	assert.Equal(t, 256, impl.maxJTILength)
}

func TestComputeJKT_RFC7638RSAVector(t *testing.T) {
	// Reference test vector.
	jwk := map[string]any{
		"kty": "RSA",
		"n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxu" +
			"hDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN" +
			"5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5" +
			"hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBni" +
			"Iqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
		"e":   "AQAB",
		"alg": "RS256",
		"kid": "2011-04-29",
	}
	jkt, err := ComputeJKT(jwk)
	assert.NoError(t, err)
	assert.Equal(t, "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs", jkt)
}

func TestComputeJKT_ECMembersOnly(t *testing.T) {
	jwk := map[string]any{
		"kty": "EC",
		"crv": "P-256",
		"x":   "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
		"y":   "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
		"use": "sig",
	}
	jkt, err := ComputeJKT(jwk)
	assert.NoError(t, err)
	// Stable across runs; recomputing the canonical JSON gives a deterministic thumbprint.
	assert.NotEmpty(t, jkt)

	jwkExtra := map[string]any{
		"kty":     "EC",
		"crv":     "P-256",
		"x":       "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
		"y":       "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
		"use":     "sig",
		"alg":     "ES256",
		"kid":     "ignored",
		"x5c":     []string{"ignored"},
		"ignored": "value",
	}
	jktExtra, err := ComputeJKT(jwkExtra)
	assert.NoError(t, err)
	assert.Equal(t, jkt, jktExtra, "thumbprint must include only required members")
}

func TestComputeJKT_OKP(t *testing.T) {
	jwk := map[string]any{
		"kty": "OKP",
		"crv": "Ed25519",
		"x":   "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
	}
	jkt, err := ComputeJKT(jwk)
	assert.NoError(t, err)
	assert.NotEmpty(t, jkt)
}

func TestComputeJKT_MissingKty(t *testing.T) {
	_, err := ComputeJKT(map[string]any{"n": "x", "e": "y"})
	assert.Error(t, err)
}

func TestComputeJKT_MissingRequiredMembers(t *testing.T) {
	cases := []map[string]any{
		{"kty": "RSA"},
		{"kty": "RSA", "n": "x"},
		{"kty": "EC", "crv": "P-256"},
		{"kty": "EC", "crv": "P-256", "x": "x"},
		{"kty": "OKP", "crv": "Ed25519"},
	}
	for _, jwk := range cases {
		_, err := ComputeJKT(jwk)
		assert.Error(t, err)
	}
}

func TestComputeJKT_UnsupportedKty(t *testing.T) {
	_, err := ComputeJKT(map[string]any{"kty": "oct", "k": "secret"})
	assert.Error(t, err)
}

func TestCanonicalizeHTU(t *testing.T) {
	cases := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{
			name:  "lowercase scheme and host",
			input: "HTTPS://EXAMPLE.COM/Token",
			want:  "https://example.com/Token",
		},
		{
			name:  "drop default https port",
			input: "https://example.com:443/token",
			want:  "https://example.com/token",
		},
		{
			name:  "drop default http port",
			input: "http://example.com:80/path",
			want:  "http://example.com/path",
		},
		{
			name:  "keep non-default port",
			input: "https://example.com:8443/token",
			want:  "https://example.com:8443/token",
		},
		{
			name:  "remove dot segments",
			input: "https://example.com/a/./b/../c",
			want:  "https://example.com/a/c",
		},
		{
			name:  "preserve trailing slash after dot-segment removal",
			input: "https://example.com/a/b/",
			want:  "https://example.com/a/b/",
		},
		{
			name:  "strip query and fragment",
			input: "https://example.com/token?x=1&y=2#frag",
			want:  "https://example.com/token",
		},
		{
			name:  "empty path becomes slash",
			input: "https://example.com",
			want:  "https://example.com/",
		},
		{
			name:  "uppercase percent-encoding",
			input: "https://example.com/a%2fb",
			want:  "https://example.com/a%2Fb",
		},
		{
			name:  "decode percent-encoded unreserved chars",
			input: "https://example.com/%74oken/%2D%5F%7E",
			want:  "https://example.com/token/-_~",
		},
		{
			name:    "relative URL rejected",
			input:   "/oauth2/token",
			wantErr: true,
		},
		{
			name:    "scheme-only rejected",
			input:   "https://",
			wantErr: true,
		},
		{
			name:    "garbage rejected",
			input:   "://bad",
			wantErr: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := canonicalizeHTU(tc.input)
			if tc.wantErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}
