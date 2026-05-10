// Package jwt provides minimal JWT signing and verification helpers.
package jwt

import "time"

// Expirer exposes expiration claim accessors.
type Expirer interface {
	ExpiresAt() int64
	SetExpiresAt(int64)
}

// Claimer is implemented by concrete claims types used by token signers and
// verifiers.
type Claimer interface {
	Expirer
}

// SignFunc signs claims with the provided secret.
type SignFunc[C Claimer] func(claims C, secret []byte) (string, error)

// VerifyFunc verifies a token with the provided secret.
type VerifyFunc[C Claimer] func(token string, secret []byte) (C, error)

// tokener signs and verifies JWTs using a shared secret and TTL policy.
type tokener[C Claimer] struct {
	secret []byte
	ttl    time.Duration
	sign   SignFunc[C]
	verify VerifyFunc[C]
}

// NewTokener creates a tokener with the provided secret, TTL policy, and algorithms.
func NewTokener[C Claimer](secret string, ttl time.Duration, sign SignFunc[C], verify VerifyFunc[C]) (*tokener[C], error) {
	if secret == "" {
		return nil, ErrInvalidSecret
	}
	if sign == nil {
		return nil, ErrInvalidSignFunc
	}
	if verify == nil {
		return nil, ErrInvalidVerifyFunc
	}

	return &tokener[C]{
		secret: []byte(secret),
		ttl:    ttl,
		sign:   sign,
		verify: verify,
	}, nil
}

// Sign signs a claim set.
func (t *tokener[C]) Sign(claims C) (string, error) {
	if t.ttl > 0 {
		claims.SetExpiresAt(time.Now().UTC().Add(t.ttl).Unix())
	}

	return t.sign(claims, t.secret)
}

// Verify verifies a token and checks expiration when present.
func (t *tokener[C]) Verify(token string) (C, error) {
	claims, err := t.verify(token, t.secret)
	if err != nil {
		var zero C
		return zero, err
	}

	if claims.ExpiresAt() != 0 && time.Now().UTC().Unix() >= claims.ExpiresAt() {
		var zero C
		return zero, ErrExpiredToken
	}

	return claims, nil
}
