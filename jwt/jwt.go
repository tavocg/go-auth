// Package jwt provides minimal HS256 JWT signing and verification helpers.
package jwt

import "time"

// Claims stores the payload claims encoded into a JWT.
type Claims map[string]any

// Tokener signs and verifies HS256 JWTs using a shared secret and TTL policy.
type Tokener struct {
	secret []byte
	ttl    time.Duration
}

// NewTokener creates a Tokener with the provided secret and TTL policy.
func NewTokener(secret string, ttl time.Duration) (*Tokener, error) {
	if secret == "" {
		return nil, ErrInvalidSecret
	}

	return &Tokener{
		secret: []byte(secret),
		ttl:    ttl,
	}, nil
}

// SignHS256 signs a claim set as an HS256 JWT.
func (t *Tokener) SignHS256(claims Claims) (string, error) {
	if claims == nil {
		claims = Claims{}
	}

	if t.ttl > 0 {
		claims = cloneClaims(claims)
		claims[claimExp] = time.Now().UTC().Add(t.ttl).Unix()
	}

	return signToken(claims, algHS256, t.secret, signHS256)
}

// VerifyHS256 verifies an HS256 JWT and checks expiration when present.
func (t *Tokener) VerifyHS256(token string) (Claims, error) {
	claims, err := verifyHS256Token(token, t.secret)
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
