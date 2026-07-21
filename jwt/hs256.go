package jwt

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"strings"
	"time"
)

const algHS256 = "HS256"

// NewHS256Tokener creates a Tokener configured for HS256.
func NewHS256Tokener[C Claims](secret string, ttl time.Duration) (*Tokener[C], error) {
	return newTokener(secret, ttl, signHS256[C], verifyHS256[C])
}

func signHS256[C Claims](claims C, secret []byte) (string, error) {
	return signToken(claims, algHS256, secret, func(signingInput, secret []byte) ([]byte, error) {
		mac := hmac.New(sha256.New, secret)
		mac.Write(signingInput)
		return mac.Sum(nil), nil
	})
}

func verifyHS256[C Claims](token string, secret []byte) (C, error) {
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
