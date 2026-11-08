// Package memory provides an in-memory auth.Authenticator implementation.
package memory

import (
	"context"
	"sync"
	"time"

	"github.com/tavocg/go-auth"
	"github.com/tavocg/go-auth/jwt"
)

// Claims is the constraint implemented by claim types accepted by Authenticator.
type Claims interface {
	auth.Identifier
	jwt.Claims
}

// Authenticator is an in-memory auth.Authenticator backed by JWT access tokens
// and opaque refresh tokens.
//
// Refresh tokens are stored only in this process. They are lost when the
// authenticator is discarded or the process exits, so this implementation is
// best suited for tests, examples, and single-process applications.
type Authenticator[T Claims] struct {
	tokener    *jwt.Tokener[T]
	refreshTTL time.Duration
	mu         sync.Mutex
	store      map[string]refreshRecord[T]
}

// NewAuthenticator creates an in-memory authenticator using HS256 JWTs for
// access tokens.
func NewAuthenticator[T Claims](secret string, accessTTL, refreshTTL time.Duration) (*Authenticator[T], error) {
	tokener, err := jwt.NewHS256Tokener[T](secret, accessTTL)
	if err != nil {
		return nil, err
	}

	return &Authenticator[T]{
		tokener:    tokener,
		refreshTTL: refreshTTL,
		store:      make(map[string]refreshRecord[T]),
	}, nil
}

// Issue creates a new access/refresh token pair for the provided identity.
func (a *Authenticator[T]) Issue(_ context.Context, identity T) (at, rt *auth.Token, err error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.issue(identity)
}

// issue requires mu to be held through refresh-token storage.
func (a *Authenticator[T]) issue(identity T) (at, rt *auth.Token, err error) {
	if isNil(identity) || identity.Subject() == "" {
		return nil, nil, auth.ErrInvalidIdentity
	}

	claims, err := cloneClaims(identity)
	if err != nil {
		return nil, nil, err
	}

	accessToken, err := a.tokener.Sign(claims)
	if err != nil {
		return nil, nil, err
	}

	refreshToken, err := randomSecret()
	if err != nil {
		return nil, nil, err
	}

	var refreshExpiresAt int64
	if a.refreshTTL > 0 {
		refreshExpiresAt = time.Now().UTC().Add(a.refreshTTL).Unix()
	}

	storedIdentity, err := cloneClaims(identity)
	if err != nil {
		return nil, nil, err
	}

	a.store[hashSecret(refreshToken)] = refreshRecord[T]{
		Identity:  storedIdentity,
		ExpiresAt: refreshExpiresAt,
	}

	return &auth.Token{
			Value:     accessToken,
			ExpiresAt: claims.ExpiresAt(),
		}, &auth.Token{
			Value:     refreshToken,
			ExpiresAt: refreshExpiresAt,
		}, nil
}

// Refresh exchanges a refresh token for a new access/refresh token pair.
func (a *Authenticator[T]) Refresh(_ context.Context, refreshToken string) (at, rt *auth.Token, err error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	key := hashSecret(refreshToken)
	record, ok := a.store[key]
	if !ok {
		return nil, nil, auth.ErrInvalidToken
	}
	delete(a.store, key)
	if record.ExpiresAt != 0 && time.Now().UTC().Unix() >= record.ExpiresAt {
		return nil, nil, auth.ErrExpiredToken
	}

	return a.issue(record.Identity)
}

// Verify validates an access token and returns its claims.
func (a *Authenticator[T]) Verify(_ context.Context, accessToken string) (T, error) {
	claims, err := a.tokener.Verify(accessToken)
	if err != nil {
		switch err {
		case jwt.ErrInvalidToken:
			var zero T
			return zero, auth.ErrInvalidToken
		case jwt.ErrExpiredToken:
			var zero T
			return zero, auth.ErrExpiredToken
		default:
			var zero T
			return zero, err
		}
	}
	if isNil(claims) || claims.Subject() == "" {
		var zero T
		return zero, auth.ErrInvalidToken
	}

	return claims, nil
}

// Revoke invalidates a single refresh token.
func (a *Authenticator[T]) Revoke(_ context.Context, refreshToken string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.store, hashSecret(refreshToken))
	return nil
}

// RevokeAll invalidates every refresh token associated with an identity.
// A concurrent Refresh cannot store a replacement after this method returns.
// A new Issue ordered after revocation creates a valid session. Existing
// access tokens remain valid until expiration.
func (a *Authenticator[T]) RevokeAll(_ context.Context, identity T) error {
	if isNil(identity) || identity.Subject() == "" {
		return auth.ErrInvalidIdentity
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	for key, record := range a.store {
		if record.Identity.Subject() == identity.Subject() {
			delete(a.store, key)
		}
	}

	return nil
}
