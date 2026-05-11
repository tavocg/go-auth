package authenticators

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"sync"
	"time"

	"github.com/tavocg/go-auth"
	"github.com/tavocg/go-auth/jwt"
)

// Claims is the constraint implemented by claim types accepted by
// MemoryAuthenticator.
type Claims interface {
	auth.Identifier
	jwt.Claimer
}

// MemoryAuthenticator is an in-memory auth.Authenticator backed by JWT access
// tokens and opaque refresh tokens.
type MemoryAuthenticator[T Claims] struct {
	tokener    *jwt.Tokener[T]
	refreshTTL time.Duration
	store      sync.Map
}

type refreshRecord[T Claims] struct {
	Identity  T
	ExpiresAt int64
}

// NewMemoryAuthenticator creates an in-memory authenticator using HS256 JWTs
// for access tokens.
func NewMemoryAuthenticator[T Claims](secret string, accessTTL, refreshTTL time.Duration) (*MemoryAuthenticator[T], error) {
	tokener, err := jwt.NewHS256Tokener[T](secret, accessTTL)
	if err != nil {
		return nil, err
	}

	return &MemoryAuthenticator[T]{
		tokener:    tokener,
		refreshTTL: refreshTTL,
	}, nil
}

// Issue creates a new access/refresh token pair for the provided identity.
func (a *MemoryAuthenticator[T]) Issue(_ context.Context, identity T) (*auth.Tokens, error) {
	if isNil(identity) || identity.Subject() == "" {
		return nil, auth.ErrInvalidIdentity
	}

	claims, err := cloneClaims(identity)
	if err != nil {
		return nil, err
	}

	accessToken, err := a.tokener.Sign(claims)
	if err != nil {
		return nil, err
	}

	refreshToken, err := randomSecret()
	if err != nil {
		return nil, err
	}

	var refreshExpiresAt int64
	if a.refreshTTL > 0 {
		refreshExpiresAt = time.Now().UTC().Add(a.refreshTTL).Unix()
	}

	storedIdentity, err := cloneClaims(identity)
	if err != nil {
		return nil, err
	}

	a.store.Store(hashSecret(refreshToken), refreshRecord[T]{
		Identity:  storedIdentity,
		ExpiresAt: refreshExpiresAt,
	})

	return &auth.Tokens{
		Access: auth.Token{
			Value:     accessToken,
			ExpiresAt: claims.ExpiresAt(),
		},
		Refresh: auth.Token{
			Value:     refreshToken,
			ExpiresAt: refreshExpiresAt,
		},
	}, nil
}

// Refresh exchanges a refresh token for a new access/refresh token pair.
func (a *MemoryAuthenticator[T]) Refresh(ctx context.Context, refreshToken string) (*auth.Tokens, error) {
	key := hashSecret(refreshToken)
	recordValue, ok := a.store.Load(key)
	if !ok {
		return nil, auth.ErrRevokedToken
	}

	record, ok := recordValue.(refreshRecord[T])
	if !ok {
		return nil, auth.ErrInvalidToken
	}
	if record.ExpiresAt != 0 && time.Now().UTC().Unix() >= record.ExpiresAt {
		a.store.Delete(key)
		return nil, auth.ErrExpiredToken
	}

	a.store.Delete(key)
	return a.Issue(ctx, record.Identity)
}

// Verify validates an access token and returns its claims.
func (a *MemoryAuthenticator[T]) Verify(_ context.Context, accessToken string) (T, error) {
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
func (a *MemoryAuthenticator[T]) Revoke(_ context.Context, refreshToken string) error {
	key := hashSecret(refreshToken)
	if _, ok := a.store.Load(key); !ok {
		return auth.ErrRevokedToken
	}

	a.store.Delete(key)
	return nil
}

// RevokeAll invalidates every refresh token associated with an identity.
func (a *MemoryAuthenticator[T]) RevokeAll(_ context.Context, identity T) error {
	if isNil(identity) || identity.Subject() == "" {
		return auth.ErrInvalidIdentity
	}

	a.store.Range(func(key, value any) bool {
		record, ok := value.(refreshRecord[T])
		if ok && record.Identity.Subject() == identity.Subject() {
			a.store.Delete(key)
		}
		return true
	})

	return nil
}

func cloneClaims[T Claims](claims T) (T, error) {
	raw, err := json.Marshal(claims)
	if err != nil {
		var zero T
		return zero, err
	}

	var cloned T
	if err := json.Unmarshal(raw, &cloned); err != nil {
		var zero T
		return zero, err
	}

	return cloned, nil
}

func isNil[T any](value T) bool {
	v := reflect.ValueOf(value)
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

func randomSecret() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}

	return hex.EncodeToString(buf), nil
}

func hashSecret(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}
