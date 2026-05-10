// Package auth <SHORT DESCRIPTION HERE>
package auth

import "context"

type Credentials struct {
	AccessToken           string `json:"access_token"`
	ExpiresIn             int64  `json:"expires_in"`
	RefreshToken          string `json:"refresh_token"`
	RefreshTokenExpiresIn int64  `json:"refresh_token_expires_in"`
}

type Identifier interface {
	Subject() string
}

type Authenticator[T Identifier] interface {
	Issue(ctx context.Context, identity T, opts ...IssueOption) (creds *Credentials, err error)
	Refresh(ctx context.Context, refreshToken string) (creds *Credentials, err error)
	Verify(ctx context.Context, accessToken string) (identity T, err error)
	Revoke(ctx context.Context, refreshToken string) (err error)
	RevokeAll(ctx context.Context, identity T) (err error)
}

type IssueOptions map[string]any

type IssueOption func(IssueOptions)

func WithClaims(key string, value any) IssueOption {
	return func(o IssueOptions) {
		o[key] = value
	}
}
