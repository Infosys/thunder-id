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
	"crypto"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/thunder-id/thunder-id/internal/oauth/oauth2/jti"
	"github.com/thunder-id/thunder-id/internal/system/cryptolab"
	"github.com/thunder-id/thunder-id/internal/system/jose/jws"
	"github.com/thunder-id/thunder-id/internal/system/jose/jwt"
)

// jtiNamespace identifies DPoP proofs in the shared JTI replay store.
const jtiNamespace = "dpop"

// VerifierInterface verifies DPoP proofs.
type VerifierInterface interface {
	Verify(ctx context.Context, params VerifyParams) (*ProofResult, error)
}

type verifier struct {
	jtiStore     jti.StoreInterface
	allowedAlgs  map[string]struct{}
	iatWindow    time.Duration
	leeway       time.Duration
	maxJTILength int
	now          func() time.Time
}

// dpopJWTType is the required value of the DPoP proof JWS "typ" header.
const dpopJWTType = "dpop+jwt"

// privateJWKMembers lists JWK parameter names that indicate private-key material.
// The embedded jwk must contain only public-key components.
var privateJWKMembers = []string{"d", "p", "q", "dp", "dq", "qi", "oth", "k"}

func newVerifier(
	jtiStore jti.StoreInterface,
	allowedAlgs []string,
	iatWindow, leeway int,
	maxJTILength int,
) VerifierInterface {
	algSet := make(map[string]struct{}, len(allowedAlgs))
	for _, a := range allowedAlgs {
		algSet[a] = struct{}{}
	}
	return &verifier{
		jtiStore:     jtiStore,
		allowedAlgs:  algSet,
		iatWindow:    time.Duration(iatWindow) * time.Second,
		leeway:       time.Duration(leeway) * time.Second,
		maxJTILength: maxJTILength,
		now:          time.Now,
	}
}

// Verify validates a single DPoP proof. Validation failures wrap ErrInvalidProof;
// replays return ErrReplayedProof; ExpectedJkt mismatch returns ErrJktMismatch.
func (v *verifier) Verify(ctx context.Context, params VerifyParams) (*ProofResult, error) {
	if strings.TrimSpace(params.Proof) == "" {
		return nil, fmt.Errorf("%w: empty proof", ErrInvalidProof)
	}

	alg, jwk, err := v.validateHeader(params.Proof)
	if err != nil {
		return nil, err
	}

	if err := verifyProofSignature(params.Proof, alg, jwk); err != nil {
		return nil, err
	}

	payload, err := jwt.DecodeJWTPayload(params.Proof)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrInvalidProof, err.Error())
	}

	iat, jti, err := v.validatePayloadClaims(payload, params)
	if err != nil {
		return nil, err
	}

	if err := validateATH(payload, params.AccessToken); err != nil {
		return nil, err
	}

	jkt, err := ComputeJKT(jwk)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrInvalidProof, err.Error())
	}

	confirmed := false
	if params.ExpectedJkt != "" {
		if subtle.ConstantTimeCompare([]byte(jkt), []byte(params.ExpectedJkt)) != 1 {
			return nil, ErrJktMismatch
		}
		confirmed = true
	}

	expiry := iat.Add(v.iatWindow + 2*v.leeway)
	inserted, err := v.jtiStore.RecordJTI(ctx, jtiNamespace, jti, expiry)
	if err != nil {
		return nil, fmt.Errorf("dpop jti store: %w", err)
	}
	if !inserted {
		return nil, ErrReplayedProof
	}

	return &ProofResult{
		JKT:       jkt,
		JWK:       jwk,
		Alg:       alg,
		Confirmed: confirmed,
	}, nil
}

func (v *verifier) validateHeader(proof string) (string, map[string]any, error) {
	header, err := jws.DecodeHeader(proof)
	if err != nil {
		return "", nil, fmt.Errorf("%w: %s", ErrInvalidProof, err.Error())
	}

	typ, _ := header["typ"].(string)
	if typ != dpopJWTType {
		return "", nil, fmt.Errorf("%w: unexpected typ %q", ErrInvalidProof, typ)
	}

	alg, _ := header["alg"].(string)
	if alg == "" {
		return "", nil, fmt.Errorf("%w: missing alg", ErrInvalidProof)
	}
	if _, ok := v.allowedAlgs[alg]; !ok {
		return "", nil, fmt.Errorf("%w: alg %q not allowed", ErrInvalidProof, alg)
	}

	jwkRaw, ok := header["jwk"]
	if !ok {
		return "", nil, fmt.Errorf("%w: missing jwk header", ErrInvalidProof)
	}
	jwk, ok := jwkRaw.(map[string]any)
	if !ok {
		return "", nil, fmt.Errorf("%w: jwk header is not a JSON object", ErrInvalidProof)
	}
	if member, found := containsPrivateMember(jwk); found {
		return "", nil, fmt.Errorf("%w: jwk contains private-key member %q", ErrInvalidProof, member)
	}

	return alg, jwk, nil
}

func verifyProofSignature(proof, alg string, jwk map[string]any) error {
	signAlg, err := jws.MapAlgorithmToSignAlg(jws.Algorithm(alg))
	if err != nil {
		return fmt.Errorf("%w: %s", ErrInvalidProof, err.Error())
	}
	pubKey, err := jws.JWKToPublicKey(jwk)
	if err != nil {
		return fmt.Errorf("%w: %s", ErrInvalidProof, err.Error())
	}
	if err := verifyJWSSignature(proof, signAlg, pubKey); err != nil {
		return fmt.Errorf("%w: %s", ErrInvalidProof, err.Error())
	}
	return nil
}

func (v *verifier) validatePayloadClaims(payload map[string]any, params VerifyParams) (time.Time, string, error) {
	htm, _ := payload["htm"].(string)
	if htm == "" || htm != params.HTM {
		return time.Time{}, "", fmt.Errorf("%w: htm mismatch", ErrInvalidProof)
	}

	proofHTU, _ := payload["htu"].(string)
	if proofHTU == "" {
		return time.Time{}, "", fmt.Errorf("%w: missing htu", ErrInvalidProof)
	}
	canonProof, err := canonicalizeHTU(proofHTU)
	if err != nil {
		return time.Time{}, "", fmt.Errorf("%w: invalid htu in proof: %s", ErrInvalidProof, err.Error())
	}
	canonExpected, err := canonicalizeHTU(params.HTU)
	if err != nil {
		return time.Time{}, "", fmt.Errorf("invalid expected htu: %w", err)
	}
	if canonProof != canonExpected {
		return time.Time{}, "", fmt.Errorf("%w: htu mismatch", ErrInvalidProof)
	}

	iatRaw, ok := payload["iat"]
	if !ok {
		return time.Time{}, "", fmt.Errorf("%w: missing iat", ErrInvalidProof)
	}
	iatSec, err := numericClaim(iatRaw)
	if err != nil {
		return time.Time{}, "", fmt.Errorf("%w: invalid iat: %s", ErrInvalidProof, err.Error())
	}
	iat := time.Unix(iatSec, 0)
	now := v.now()
	earliest := now.Add(-v.iatWindow - v.leeway)
	latest := now.Add(v.leeway)
	if iat.Before(earliest) || iat.After(latest) {
		return time.Time{}, "", fmt.Errorf("%w: iat out of acceptance window", ErrInvalidProof)
	}

	jti, _ := payload["jti"].(string)
	if jti == "" {
		return time.Time{}, "", fmt.Errorf("%w: missing jti", ErrInvalidProof)
	}
	if len(jti) > v.maxJTILength {
		return time.Time{}, "", fmt.Errorf("%w: jti exceeds max length", ErrInvalidProof)
	}

	return iat, jti, nil
}

func validateATH(payload map[string]any, accessToken string) error {
	if accessToken == "" {
		return nil
	}
	athClaim, ok := payload["ath"].(string)
	if !ok || athClaim == "" {
		return fmt.Errorf("%w: missing ath", ErrInvalidProof)
	}
	sum := sha256.Sum256([]byte(accessToken))
	expectedAth := base64.RawURLEncoding.EncodeToString(sum[:])
	if subtle.ConstantTimeCompare([]byte(athClaim), []byte(expectedAth)) != 1 {
		return fmt.Errorf("%w: ath mismatch", ErrInvalidProof)
	}
	return nil
}

func containsPrivateMember(jwk map[string]any) (string, bool) {
	for _, m := range privateJWKMembers {
		if _, ok := jwk[m]; ok {
			return m, true
		}
	}
	return "", false
}

func verifyJWSSignature(token string, alg cryptolab.SignAlgorithm, pub crypto.PublicKey) error {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return errors.New("invalid JWS format")
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return fmt.Errorf("invalid JWS signature encoding: %w", err)
	}
	signingInput := parts[0] + "." + parts[1]
	if err := cryptolab.Verify([]byte(signingInput), signature, alg, pub); err != nil {
		return fmt.Errorf("signature verification failed: %w", err)
	}
	return nil
}

func numericClaim(v any) (int64, error) {
	switch n := v.(type) {
	case float64:
		return int64(n), nil
	case int64:
		return n, nil
	case int:
		return int64(n), nil
	default:
		return 0, fmt.Errorf("unexpected numeric type %T", v)
	}
}

// ComputeJKT computes the SHA-256 JWK thumbprint of a public key JWK.
func ComputeJKT(jwk map[string]any) (string, error) {
	canonical, err := canonicalJWK(jwk)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canonical)
	return base64.RawURLEncoding.EncodeToString(sum[:]), nil
}

func canonicalJWK(jwk map[string]any) ([]byte, error) {
	kty, ok := stringMember(jwk, "kty")
	if !ok {
		return nil, errors.New("JWK missing kty")
	}
	var ordered []struct{ k, v string }
	switch kty {
	case "RSA":
		e, ok1 := stringMember(jwk, "e")
		n, ok2 := stringMember(jwk, "n")
		if !ok1 || !ok2 {
			return nil, errors.New("RSA JWK missing required members e/n")
		}
		ordered = []struct{ k, v string }{{"e", e}, {"kty", "RSA"}, {"n", n}}
	case "EC":
		crv, ok1 := stringMember(jwk, "crv")
		x, ok2 := stringMember(jwk, "x")
		y, ok3 := stringMember(jwk, "y")
		if !ok1 || !ok2 || !ok3 {
			return nil, errors.New("EC JWK missing required members crv/x/y")
		}
		ordered = []struct{ k, v string }{{"crv", crv}, {"kty", "EC"}, {"x", x}, {"y", y}}
	case "OKP":
		crv, ok1 := stringMember(jwk, "crv")
		x, ok2 := stringMember(jwk, "x")
		if !ok1 || !ok2 {
			return nil, errors.New("OKP JWK missing required members crv/x")
		}
		ordered = []struct{ k, v string }{{"crv", crv}, {"kty", "OKP"}, {"x", x}}
	default:
		return nil, fmt.Errorf("unsupported JWK kty for thumbprint: %s", kty)
	}

	buf := make([]byte, 0, 256)
	buf = append(buf, '{')
	for i, m := range ordered {
		if i > 0 {
			buf = append(buf, ',')
		}
		kBytes, err := json.Marshal(m.k)
		if err != nil {
			return nil, err
		}
		vBytes, err := json.Marshal(m.v)
		if err != nil {
			return nil, err
		}
		buf = append(buf, kBytes...)
		buf = append(buf, ':')
		buf = append(buf, vBytes...)
	}
	buf = append(buf, '}')
	return buf, nil
}

func stringMember(jwk map[string]any, key string) (string, bool) {
	v, ok := jwk[key]
	if !ok {
		return "", false
	}
	s, ok := v.(string)
	if !ok || s == "" {
		return "", false
	}
	return s, true
}

// canonicalizeHTU normalizes a URL for htu comparison.
func canonicalizeHTU(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("invalid URL: %w", err)
	}
	if !u.IsAbs() {
		return "", errors.New("htu must be an absolute URI")
	}
	if u.Host == "" {
		return "", errors.New("htu missing host")
	}

	scheme := strings.ToLower(u.Scheme)
	host := strings.ToLower(u.Hostname())
	port := u.Port()
	if (scheme == "http" && port == "80") || (scheme == "https" && port == "443") {
		port = ""
	}

	p := u.EscapedPath()
	if p == "" {
		p = "/"
	}
	p = removeDotSegments(p)
	p = normalizePercentEncoding(p)

	hostPort := host
	if port != "" {
		hostPort = host + ":" + port
	}
	return scheme + "://" + hostPort + p, nil
}

// removeDotSegments removes only "." and ".." segments while preserving repeated
// slashes (path.Clean would collapse "/a//b" to "/a/b", altering URI semantics).
func removeDotSegments(p string) string {
	if p == "" {
		return "/"
	}
	var output strings.Builder
	output.Grow(len(p))
	input := p
	for len(input) > 0 {
		switch {
		case strings.HasPrefix(input, "../"):
			input = input[3:]
		case strings.HasPrefix(input, "./"):
			input = input[2:]
		case strings.HasPrefix(input, "/./"):
			input = input[2:]
		case input == "/.":
			input = "/"
		case strings.HasPrefix(input, "/../"):
			input = input[3:]
			cur := output.String()
			output.Reset()
			if i := strings.LastIndexByte(cur, '/'); i >= 0 {
				output.WriteString(cur[:i])
			}
		case input == "/..":
			input = "/"
			cur := output.String()
			output.Reset()
			if i := strings.LastIndexByte(cur, '/'); i >= 0 {
				output.WriteString(cur[:i])
			}
		case input == "." || input == "..":
			input = ""
		default:
			start := 0
			if input[0] == '/' {
				start = 1
			}
			next := strings.IndexByte(input[start:], '/')
			if next == -1 {
				output.WriteString(input)
				input = ""
			} else {
				output.WriteString(input[:start+next])
				input = input[start+next:]
			}
		}
	}
	result := output.String()
	if !strings.HasPrefix(result, "/") {
		result = "/" + result
	}
	return result
}

func normalizePercentEncoding(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] != '%' || i+2 >= len(s) {
			b.WriteByte(s[i])
			continue
		}
		hi, ok1 := fromHex(s[i+1])
		lo, ok2 := fromHex(s[i+2])
		if !ok1 || !ok2 {
			b.WriteByte(s[i])
			continue
		}
		decoded := hi<<4 | lo
		if isUnreserved(decoded) {
			b.WriteByte(decoded)
		} else {
			b.WriteByte('%')
			b.WriteByte(upperHex(s[i+1]))
			b.WriteByte(upperHex(s[i+2]))
		}
		i += 2
	}
	return b.String()
}

func isUnreserved(c byte) bool {
	switch {
	case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		return true
	case c == '-', c == '.', c == '_', c == '~':
		return true
	}
	return false
}

func fromHex(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

func upperHex(c byte) byte {
	if c >= 'a' && c <= 'f' {
		return c - 32
	}
	return c
}
