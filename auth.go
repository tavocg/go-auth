// Package auth defines small authentication interfaces and credential types.
package auth

import (
	"context"
)

// Token contains a token value and its expiration time.
//
// ExpiresAt is a Unix timestamp in seconds. A zero value means the token has
// no configured expiration.
type Token struct {
	Value     string
	ExpiresAt int64
}

// Identifier exposes the stable subject identifier used in tokens.
type Identifier interface {
	Subject() string
}

var (
	ErrInvalidIdentity error = errStr("invalid identity")
	ErrInvalidToken    error = errStr("invalid token")
	ErrExpiredToken    error = errStr("expired token")
)

// Authenticator issues, verifies, refreshes, and revokes credentials for an
// identity type.
type Authenticator[T Identifier] interface {
	// Issue creates a new token pair for the provided identity.
	Issue(ctx context.Context, identity T) (at, rt *Token, err error)
	// Refresh exchanges a token pair for a new token pair.
	Refresh(ctx context.Context, refreshToken string) (at, rt *Token, err error)
	// Verify validates an access token and returns its identity.
	Verify(ctx context.Context, accessToken string) (identity T, err error)
	// Revoke invalidates a single refresh token.
	Revoke(ctx context.Context, refreshToken string) (err error)
	// RevokeAll invalidates every refresh token associated with an identity.
	RevokeAll(ctx context.Context, identity T) (err error)
}
