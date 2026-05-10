package examples

import (
	"context"
	"sync"
	"time"

	auth "github.com/tavocg/go-auth"
	"github.com/tavocg/go-auth/jwt"
)

// Claims is a minimal example claims type for JWT-backed authentication.
type Claims struct {
	Expires int64  `json:"expires_at,omitempty"`
	Sub     string `json:"sub"`
	Kind    string `json:"kind,omitempty"`
}

func (c *Claims) ExpiresAt() int64 {
	if c == nil {
		return 0
	}

	return c.Expires
}

func (c *Claims) SetExpiresAt(exp int64) {
	if c == nil {
		return
	}

	c.Expires = exp
}

func (c *Claims) Subject() string {
	if c == nil {
		return ""
	}

	return c.Sub
}

// Authenticator is a minimal JWT-backed auth.Authenticator example.
type Authenticator struct {
	access  *jwt.Tokener[*Claims]
	refresh *jwt.Tokener[*Claims]
	store   sync.Map
}

// NewAuthenticator creates a minimal JWT-backed authenticator example.
func NewAuthenticator(secret string, accessTTL, refreshTTL time.Duration) (*Authenticator, error) {
	if secret == "" {
		return nil, jwt.ErrInvalidSecret
	}

	access, err := jwt.NewHS256Tokener[*Claims](secret, accessTTL)
	if err != nil {
		return nil, err
	}

	refresh, err := jwt.NewHS256Tokener[*Claims](secret, refreshTTL)
	if err != nil {
		return nil, err
	}

	return &Authenticator{
		access:  access,
		refresh: refresh,
	}, nil
}

func (a *Authenticator) Issue(ctx context.Context, identity *Claims) (*auth.Tokens, error) {
	_ = ctx

	if identity == nil || identity.Subject() == "" {
		return nil, auth.ErrInvalidIdentity
	}

	return a.issue(identity.Subject())
}

func (a *Authenticator) Refresh(ctx context.Context, refreshToken string) (*auth.Tokens, error) {
	_ = ctx

	claims, err := a.verify(refreshToken, kindRefresh)
	if err != nil {
		return nil, err
	}

	key := refreshKey(claims.Subject())
	value, ok := a.store.Load(key)
	if !ok {
		return nil, auth.ErrRevokedToken
	}

	exp, ok := value.(int64)
	if !ok || exp != claims.ExpiresAt() {
		return nil, auth.ErrRevokedToken
	}

	return a.issue(claims.Subject())
}

func (a *Authenticator) Verify(ctx context.Context, accessToken string) (*Claims, error) {
	_ = ctx

	return a.verify(accessToken, kindAccess)
}

func (a *Authenticator) Revoke(ctx context.Context, refreshToken string) error {
	_ = ctx

	claims, err := a.verify(refreshToken, kindRefresh)
	if err != nil {
		return err
	}

	a.store.Delete(refreshKey(claims.Subject()))
	return nil
}

func (a *Authenticator) RevokeAll(ctx context.Context, identity *Claims) error {
	_ = ctx

	if identity == nil || identity.Subject() == "" {
		return auth.ErrInvalidIdentity
	}

	a.store.Delete(refreshKey(identity.Subject()))
	return nil
}

func (a *Authenticator) issue(subject string) (*auth.Tokens, error) {
	access, err := a.sign(a.access, subject, kindAccess)
	if err != nil {
		return nil, err
	}

	refresh, err := a.sign(a.refresh, subject, kindRefresh)
	if err != nil {
		return nil, err
	}

	a.store.Store(refreshKey(subject), refresh.ExpiresAt.Unix())

	return &auth.Tokens{
		Access:  access,
		Refresh: refresh,
	}, nil
}

func (a *Authenticator) sign(tokener *jwt.Tokener[*Claims], subject, kind string) (auth.Token, error) {
	claims := &Claims{
		Sub:  subject,
		Kind: kind,
	}

	value, err := tokener.Sign(claims)
	if err != nil {
		return auth.Token{}, err
	}

	return auth.Token{
		Value:     value,
		ExpiresAt: unixTime(claims.ExpiresAt()),
	}, nil
}

func (a *Authenticator) verify(token, kind string) (*Claims, error) {
	var tokener *jwt.Tokener[*Claims]
	if kind == kindRefresh {
		tokener = a.refresh
	} else {
		tokener = a.access
	}

	claims, err := tokener.Verify(token)
	if err != nil {
		return nil, mapJWTError(err)
	}

	if claims == nil || claims.Subject() == "" || claims.Kind != kind {
		return nil, auth.ErrInvalidToken
	}

	return claims, nil
}

func mapJWTError(err error) error {
	switch err {
	case jwt.ErrInvalidToken:
		return auth.ErrInvalidToken
	case jwt.ErrExpiredToken:
		return auth.ErrExpiredToken
	default:
		return err
	}
}

func refreshKey(subject string) string {
	return subject + ":rt"
}

func unixTime(sec int64) time.Time {
	if sec == 0 {
		return time.Time{}
	}

	return time.Unix(sec, 0).UTC()
}

const (
	kindAccess  = "at"
	kindRefresh = "rt"
)

var _ auth.Authenticator[*Claims] = (*Authenticator)(nil)
