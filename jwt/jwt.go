// Package jwt provides minimal JWT signing and verification helpers.
package jwt

import "time"

// Claims stores the payload claims encoded into a JWT.
type Claims map[string]any

// SignFunc signs claims with the provided secret.
type SignFunc func(claims Claims, secret []byte) (string, error)

// VerifyFunc verifies a token with the provided secret.
type VerifyFunc func(token string, secret []byte) (Claims, error)

// Tokener signs and verifies JWTs using a shared secret and TTL policy.
type Tokener struct {
	secret []byte
	ttl    time.Duration
	sign   SignFunc
	verify VerifyFunc
}

// NewTokener creates a Tokener with the provided secret, TTL policy, and algorithms.
func NewTokener(secret string, ttl time.Duration, sign SignFunc, verify VerifyFunc) (*Tokener, error) {
	if secret == "" {
		return nil, ErrInvalidSecret
	}
	if sign == nil {
		return nil, ErrInvalidSignFunc
	}
	if verify == nil {
		return nil, ErrInvalidVerifyFunc
	}

	return &Tokener{
		secret: []byte(secret),
		ttl:    ttl,
		sign:   sign,
		verify: verify,
	}, nil
}

// NewHS256Tokener creates a Tokener configured for HS256.
func NewHS256Tokener(secret string, ttl time.Duration) (*Tokener, error) {
	return NewTokener(secret, ttl, SignHS256, VerifyHS256)
}

// Sign signs a claim set.
func (t *Tokener) Sign(claims Claims) (string, error) {
	if claims == nil {
		claims = Claims{}
	}

	if t.ttl > 0 {
		claims = cloneClaims(claims)
		claims[claimExp] = time.Now().UTC().Add(t.ttl).Unix()
	}

	return t.sign(claims, t.secret)
}

// Verify verifies a token and checks expiration when present.
func (t *Tokener) Verify(token string) (Claims, error) {
	claims, err := t.verify(token, t.secret)
	if err != nil {
		return nil, err
	}

	exp, ok, err := claimInt64(claims, claimExp)
	if err != nil {
		return nil, err
	}
	if ok && time.Now().UTC().Unix() >= exp {
		return nil, ErrExpiredToken
	}

	return claims, nil
}
