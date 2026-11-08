// Package jwt provides minimal JWT signing and verification helpers.
package jwt

import (
	"reflect"
	"time"
)

// Claims is implemented by concrete claims types used by token signers and
// verifiers.
//
// ExpiresAt returns a Unix timestamp in seconds. A zero value means the claims
// have no configured expiration.
type Claims interface {
	ExpiresAt() int64
	SetExpiresAt(int64)
}

var (
	ErrInvalidSecret     error = errStr("invalid secret")
	ErrInvalidSignFunc   error = errStr("invalid sign func")
	ErrInvalidVerifyFunc error = errStr("invalid verify func")
	ErrInvalidToken      error = errStr("invalid token")
	ErrInvalidTTL        error = errStr("invalid token TTL")
	ErrExpiredToken      error = errStr("expired token")
)

type signFunc[C Claims] func(claims C, secret []byte) (string, error)

type verifyFunc[C Claims] func(token string, secret []byte) (C, error)

// Tokener signs and verifies JWTs using a shared secret and TTL policy.
type Tokener[C Claims] struct {
	secret []byte
	ttl    time.Duration
	sign   signFunc[C]
	verify verifyFunc[C]
}

func newTokener[C Claims](secret string, ttl time.Duration, sign signFunc[C], verify verifyFunc[C]) (*Tokener[C], error) {
	if ttl < 0 {
		return nil, ErrInvalidTTL
	}
	if sign == nil {
		return nil, ErrInvalidSignFunc
	}
	if verify == nil {
		return nil, ErrInvalidVerifyFunc
	}

	return &Tokener[C]{
		secret: []byte(secret),
		ttl:    ttl,
		sign:   sign,
		verify: verify,
	}, nil
}

// Sign signs a claim set.
//
// When the Tokener has a positive TTL, Sign mutates claims by calling
// SetExpiresAt with the calculated Unix expiration timestamp before signing.
func (t *Tokener[C]) Sign(claims C) (string, error) {
	if nilClaims(claims) {
		return "", ErrInvalidToken
	}
	if t.ttl > 0 {
		claims.SetExpiresAt(time.Now().UTC().Add(t.ttl).Unix())
	}

	return t.sign(claims, t.secret)
}

// Verify verifies a token and checks expiration when present.
//
// Claims with an ExpiresAt value of zero do not expire.
func (t *Tokener[C]) Verify(token string) (C, error) {
	claims, err := t.verify(token, t.secret)
	if err != nil {
		var zero C
		return zero, err
	}

	if nilClaims(claims) {
		var zero C
		return zero, ErrInvalidToken
	}

	if claims.ExpiresAt() != 0 && time.Now().UTC().Unix() >= claims.ExpiresAt() {
		var zero C
		return zero, ErrExpiredToken
	}

	return claims, nil
}

// Claims may be an interface or a named nil-capable type, not only a pointer.
func nilClaims[C Claims](claims C) bool {
	v := reflect.ValueOf(claims)
	if !v.IsValid() {
		return true
	}
	switch v.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return v.IsNil()
	default:
		return false
	}
}
