package jwt

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"strings"
	"time"
)

const algHS256 = "HS256"

// NewHS256Tokener creates a tokener configured for HS256.
func NewHS256Tokener[C Claimer](secret string, ttl time.Duration) (*tokener[C], error) {
	return NewTokener(secret, ttl, SignHS256[C], VerifyHS256[C])
}

// SignHS256 signs claims as an HS256 JWT.
func SignHS256[C Claimer](claims C, secret []byte) (string, error) {
	return signToken(claims, algHS256, secret, func(signingInput, secret []byte) ([]byte, error) {
		mac := hmac.New(sha256.New, secret)
		mac.Write(signingInput)
		return mac.Sum(nil), nil
	})
}

// VerifyHS256 verifies an HS256 JWT.
func VerifyHS256[C Claimer](token string, secret []byte) (C, error) {
	if len(secret) == 0 {
		var zero C
		return zero, ErrInvalidSecret
	}

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		var zero C
		return zero, ErrInvalidToken
	}

	head, payload, signature := parts[0], parts[1], parts[2]
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(head + "." + payload))
	expected := mac.Sum(nil)

	got, err := decode(signature)
	if err != nil || !hmac.Equal(got, expected) {
		var zero C
		return zero, ErrInvalidToken
	}

	headBytes, err := decode(head)
	if err != nil {
		var zero C
		return zero, ErrInvalidToken
	}

	var parsedHeader header
	if err := json.Unmarshal(headBytes, &parsedHeader); err != nil || parsedHeader.Algorithm != algHS256 {
		var zero C
		return zero, ErrInvalidToken
	}

	payloadBytes, err := decode(payload)
	if err != nil {
		var zero C
		return zero, ErrInvalidToken
	}

	var claims C
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		var zero C
		return zero, ErrInvalidToken
	}

	return claims, nil
}
