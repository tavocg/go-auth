// Package auth defines small authentication interfaces and credential types.
package auth

import (
	"context"
	"time"
)

// Token contains a token value and its expiration time.
type Token struct {
	Value     string
	ExpiresAt time.Time
}

// Tokens contains the access and refresh tokens returned by an Authenticator.
type Tokens struct {
	Access  Token
	Refresh Token
}

// Identifier exposes the stable subject identifier used in tokens.
type Identifier interface {
	Subject() string
}

// Authenticator issues, verifies, refreshes, and revokes credentials for an
// identity type.
type Authenticator[T Identifier] interface {
	// Issue creates a new token pair for the provided identity.
	Issue(ctx context.Context, identity T) (tokens *Tokens, err error)
	// Refresh exchanges a token pair for a new token pair.
	Refresh(ctx context.Context, refreshToken string) (tokens *Tokens, err error)
	// Verify validates an access token and returns its identity.
	Verify(ctx context.Context, accessToken string) (identity T, err error)
	// Revoke invalidates a single refresh token.
	Revoke(ctx context.Context, refreshToken string) (err error)
	// RevokeAll invalidates every refresh token associated with an identity.
	RevokeAll(ctx context.Context, identity T) (err error)
}
