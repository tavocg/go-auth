package examples

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"time"

	"github.com/tavocg/go-auth"
	"github.com/tavocg/go-auth/jwt"
)

// Claims is a minimal example claims type for JWT-backed authentication.
type Claims struct {
	Expires int64  `json:"expires_at,omitempty"`
	Sub     string `json:"sub"`
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
	tokener    *jwt.Tokener[*Claims]
	refreshTTL time.Duration
	store      sync.Map
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

	return &Authenticator{
		tokener:    access,
		refreshTTL: refreshTTL,
	}, nil
}

func (a *Authenticator) Issue(ctx context.Context, identity *Claims) (*auth.Tokens, error) {
	_ = ctx

	if identity == nil || identity.Subject() == "" {
		return nil, auth.ErrInvalidIdentity
	}

	claims := &Claims{Sub: identity.Subject()}
	accessValue, err := a.tokener.Sign(claims)
	if err != nil {
		return nil, err
	}

	refreshValue, err := randomSecret()
	if err != nil {
		return nil, err
	}

	var refreshExpiresAt int64
	if a.refreshTTL > 0 {
		refreshExpiresAt = time.Now().UTC().Add(a.refreshTTL).Unix()
	}

	var accessExpiresAt int64
	if claims.ExpiresAt() != 0 {
		accessExpiresAt = claims.ExpiresAt()
	}

	a.store.Store(hashSecret(refreshValue), refreshRecord{
		Subject:   identity.Subject(),
		ExpiresAt: refreshExpiresAt,
	})

	return &auth.Tokens{
		Access: auth.Token{
			Value:     accessValue,
			ExpiresAt: accessExpiresAt,
		},
		Refresh: auth.Token{
			Value:     refreshValue,
			ExpiresAt: refreshExpiresAt,
		},
	}, nil
}

func (a *Authenticator) Refresh(ctx context.Context, refreshToken string) (*auth.Tokens, error) {
	_ = ctx

	key := hashSecret(refreshToken)
	value, ok := a.store.Load(key)
	if !ok {
		return nil, auth.ErrRevokedToken
	}

	record, ok := value.(refreshRecord)
	if !ok {
		return nil, auth.ErrInvalidToken
	}
	if record.ExpiresAt != 0 && time.Now().UTC().Unix() >= record.ExpiresAt {
		a.store.Delete(key)
		return nil, auth.ErrExpiredToken
	}

	a.store.Delete(key)
	return a.Issue(ctx, &Claims{Sub: record.Subject})
}

func (a *Authenticator) Verify(ctx context.Context, accessToken string) (*Claims, error) {
	_ = ctx

	claims, err := a.tokener.Verify(accessToken)
	if err != nil {
		switch err {
		case jwt.ErrInvalidToken:
			return nil, auth.ErrInvalidToken
		case jwt.ErrExpiredToken:
			return nil, auth.ErrExpiredToken
		default:
			return nil, err
		}
	}
	if claims == nil || claims.Subject() == "" {
		return nil, auth.ErrInvalidToken
	}

	return claims, nil
}

func (a *Authenticator) Revoke(ctx context.Context, refreshToken string) error {
	_ = ctx

	key := hashSecret(refreshToken)
	if _, ok := a.store.Load(key); !ok {
		return auth.ErrRevokedToken
	}

	a.store.Delete(key)
	return nil
}

func (a *Authenticator) RevokeAll(ctx context.Context, identity *Claims) error {
	_ = ctx

	if identity == nil || identity.Subject() == "" {
		return auth.ErrInvalidIdentity
	}

	a.store.Range(func(key, value any) bool {
		record, ok := value.(refreshRecord)
		if ok && record.Subject == identity.Subject() {
			a.store.Delete(key)
		}
		return true
	})

	return nil
}

func randomSecret() (string, error) {
	buf := make([]byte, 32)
	_, err := rand.Read(buf)
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(buf), nil
}

func hashSecret(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

type refreshRecord struct {
	Subject   string
	ExpiresAt int64
}

var _ auth.Authenticator[*Claims] = (*Authenticator)(nil)
