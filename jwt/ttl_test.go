package jwt_test

import (
	"errors"
	"testing"
	"time"

	"github.com/tavocg/go-auth/jwt"
)

func TestHS256RejectsNegativeTTL(t *testing.T) {
	for _, ttl := range []time.Duration{-1, -time.Minute, time.Duration(-1 << 63)} {
		tokener, err := jwt.NewHS256Tokener[*testClaims]("", ttl)
		if !errors.Is(err, jwt.ErrInvalidTTL) || tokener != nil {
			t.Fatalf("NewHS256Tokener(%v) = %#v, %v, want nil, ErrInvalidTTL", ttl, tokener, err)
		}
	}
}

func TestHS256ZeroTTLPreservesExpiration(t *testing.T) {
	tokener, err := jwt.NewHS256Tokener[*testClaims]("", 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, expiry := range []int64{0, 4102444800} {
		claims := &testClaims{Sub: "user", Exp: expiry}
		token, err := tokener.Sign(claims)
		if err != nil {
			t.Fatal(err)
		}
		verified, err := tokener.Verify(token)
		if err != nil || verified == nil || verified.Exp != expiry || claims.Exp != expiry {
			t.Fatalf("zero TTL changed expiration %d: claims = %#v, error = %v", expiry, verified, err)
		}
	}
}

func TestHS256PositiveTTLSetsExpiration(t *testing.T) {
	tokener, err := jwt.NewHS256Tokener[*testClaims]("", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	claims := &testClaims{Sub: "user"}
	before := time.Now().Add(time.Minute).Unix()
	if _, err := tokener.Sign(claims); err != nil {
		t.Fatal(err)
	}
	if after := time.Now().Add(time.Minute).Unix(); claims.Exp < before || claims.Exp > after {
		t.Fatalf("expiration = %d, want between %d and %d", claims.Exp, before, after)
	}
}
