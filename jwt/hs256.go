package jwt

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"strings"
)

const algHS256 = "HS256"

// SignHS256 signs claims as an HS256 JWT.
func SignHS256(claims Claims, secret []byte) (string, error) {
	return signToken(claims, algHS256, secret, func(signingInput, secret []byte) ([]byte, error) {
		mac := hmac.New(sha256.New, secret)
		mac.Write(signingInput)
		return mac.Sum(nil), nil
	})
}

// VerifyHS256 verifies an HS256 JWT.
func VerifyHS256(token string, secret []byte) (Claims, error) {
	if len(secret) == 0 {
		return nil, ErrInvalidSecret
	}

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, ErrInvalidToken
	}

	head, payload, signature := parts[0], parts[1], parts[2]
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(head + "." + payload))
	expected := mac.Sum(nil)

	got, err := decode(signature)
	if err != nil || !hmac.Equal(got, expected) {
		return nil, ErrInvalidToken
	}

	headBytes, err := decode(head)
	if err != nil {
		return nil, ErrInvalidToken
	}

	var parsedHeader header
	if err := json.Unmarshal(headBytes, &parsedHeader); err != nil || parsedHeader.Algorithm != algHS256 {
		return nil, ErrInvalidToken
	}

	payloadBytes, err := decode(payload)
	if err != nil {
		return nil, ErrInvalidToken
	}

	var claims Claims
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return nil, ErrInvalidToken
	}

	return claims, nil
}
