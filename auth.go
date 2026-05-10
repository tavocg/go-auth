// Package auth defines small authentication interfaces and credential types.
package auth

import "context"

// Credentials contains the access and refresh credentials returned by an
// Authenticator.
type Credentials struct {
	AccessToken           string `json:"access_token"`
	ExpiresIn             int64  `json:"expires_in"`
	RefreshToken          string `json:"refresh_token"`
	RefreshTokenExpiresIn int64  `json:"refresh_token_expires_in"`
}

// Identifier exposes the stable subject identifier used in credentials.
type Identifier interface {
	Subject() string
}

// Authenticator issues, verifies, refreshes, and revokes credentials for an
// identity type.
type Authenticator[T Identifier] interface {
	// Issue creates a new credential pair for the provided identity.
	Issue(ctx context.Context, identity T) (creds *Credentials, err error)
	// Refresh exchanges a refresh token for a new credential pair.
	Refresh(ctx context.Context, accessToken, refreshToken string) (creds *Credentials, err error)
	// Verify validates an access token and returns its identity.
	Verify(ctx context.Context, accessToken string) (identity T, err error)
	// Revoke invalidates a single refresh token.
	Revoke(ctx context.Context, refreshToken string) (err error)
	// RevokeAll invalidates every refresh token associated with an identity.
	RevokeAll(ctx context.Context, identity T) (err error)
}
