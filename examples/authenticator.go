package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/tavocg/go-auth"
	"github.com/tavocg/go-auth/authenticators/memory"
)

type Claims struct {
	Expires int64  `json:"expires_at,omitempty"`
	Role    string `json:"role,omitempty"`
	Sub     string `json:"sub"`
}

func (c *Claims) ExpiresAt() int64 {
	if c == nil {
		return 0
	}
	return c.Expires
}

func (c *Claims) SetExpiresAt(exp int64) {
	if c != nil {
		c.Expires = exp
	}
}

func (c *Claims) Subject() string {
	if c == nil {
		return ""
	}
	return c.Sub
}

func main() {
	ctx := context.Background()
	secret := "example-secret"

	memoryAuth, err := memory.NewAuthenticator[*Claims](secret, 15*time.Minute, 24*time.Hour)
	if err != nil {
		log.Fatal(err)
	}

	var authenticator auth.Authenticator[*Claims] = memoryAuth
	identity := &Claims{Sub: "user_123", Role: "admin"}

	at, rt, err := authenticator.Issue(ctx, identity)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("secret=%s\n", secret)
	fmt.Printf("access_token=%s\n", at.Value)
	fmt.Printf("refresh_token=%s\n", rt.Value)

	claims, err := authenticator.Verify(ctx, at.Value)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("verified subject=%s role=%s\n", claims.Subject(), claims.Role)

	at, rt, err = authenticator.Refresh(ctx, rt.Value)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("refreshed access_expires_at=%d refresh_expires_at=%d\n", at.ExpiresAt, rt.ExpiresAt)

	if err := authenticator.Revoke(ctx, rt.Value); err != nil {
		log.Fatal(err)
	}

	_, _, err = authenticator.Refresh(ctx, rt.Value)
	fmt.Println(errors.Is(err, auth.ErrInvalidToken))
}

var _ auth.Authenticator[*Claims] = (*memory.Authenticator[*Claims])(nil)
