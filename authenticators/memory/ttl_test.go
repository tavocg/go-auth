package memory

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/tavocg/go-auth/jwt"
)

func TestNewAuthenticatorRejectsNegativeTTLs(t *testing.T) {
	for _, tt := range []struct {
		name            string
		access, refresh time.Duration
	}{
		{"negative access", -1, time.Hour},
		{"negative refresh", time.Minute, -1},
		{"negative access with zero refresh", -1, 0},
		{"negative refresh with zero access", 0, -1},
		{"both negative", -time.Minute, -time.Hour},
	} {
		t.Run(tt.name, func(t *testing.T) {
			a, err := NewAuthenticator[*testClaims]("", tt.access, tt.refresh)
			if !errors.Is(err, jwt.ErrInvalidTTL) || a != nil {
				t.Fatalf("NewAuthenticator() = %#v, %v, want nil, ErrInvalidTTL", a, err)
			}
		})
	}
}

func TestNewAuthenticatorPreservesNonnegativeTTLPolicies(t *testing.T) {
	for _, tt := range []struct{ access, refresh time.Duration }{
		{0, 0}, {0, time.Hour}, {time.Minute, 0}, {time.Minute, time.Hour},
	} {
		a, err := NewAuthenticator[*testClaims]("", tt.access, tt.refresh)
		if err != nil {
			t.Fatal(err)
		}
		ctx := context.Background()
		access, refresh, err := a.Issue(ctx, &testClaims{Sub: "user"})
		if err != nil {
			t.Fatal(err)
		}
		if (access.ExpiresAt == 0) != (tt.access == 0) || (refresh.ExpiresAt == 0) != (tt.refresh == 0) {
			t.Fatalf("TTL policies %+v produced expirations %d and %d", tt, access.ExpiresAt, refresh.ExpiresAt)
		}
		if _, err := a.Verify(ctx, access.Value); err != nil {
			t.Fatal(err)
		}
		access, refresh, err = a.Refresh(ctx, refresh.Value)
		if err != nil {
			t.Fatal(err)
		}
		if (access.ExpiresAt == 0) != (tt.access == 0) || (refresh.ExpiresAt == 0) != (tt.refresh == 0) {
			t.Fatalf("refresh changed the TTL policies %+v", tt)
		}
	}
}
