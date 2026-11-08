package jwt_test

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/tavocg/go-auth/jwt"
)

type testClaims struct {
	Sub string `json:"sub"`
	Exp int64  `json:"exp"`
}

func (c *testClaims) ExpiresAt() int64       { return c.Exp }
func (c *testClaims) SetExpiresAt(exp int64) { c.Exp = exp }

func TestHS256RejectsUnsupportedHeaderSemantics(t *testing.T) {
	const secret = "test-secret"
	tokener, err := jwt.NewHS256Tokener[*testClaims](secret, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		name, header string
		valid        bool
	}{
		{"minimal", `{"alg":"HS256"}`, true},
		{"typed", `{"alg":"HS256","typ":"JWT"}`, true},
		{"noncritical extensions", `{"alg":"HS256","kid":"key-1","custom":true}`, true},
		{"explicit base64 payload", `{"alg":"HS256","b64":true}`, true},
		{"unsupported critical extension", `{"alg":"HS256","crit":["custom"],"custom":true}`, false},
		{"missing critical value", `{"alg":"HS256","crit":["custom"]}`, false},
		{"registered parameter marked critical", `{"alg":"HS256","crit":["alg"]}`, false},
		{"empty critical list", `{"alg":"HS256","crit":[]}`, false},
		{"null critical list", `{"alg":"HS256","crit":null}`, false},
		{"string critical list", `{"alg":"HS256","crit":"custom"}`, false},
		{"object critical list", `{"alg":"HS256","crit":{}}`, false},
		{"non-string critical entry", `{"alg":"HS256","crit":[42]}`, false},
		{"base64 marked critical", `{"alg":"HS256","crit":["b64"],"b64":true}`, false},
		{"unencoded payload", `{"alg":"HS256","crit":["b64"],"b64":false}`, false},
		{"unencoded payload without crit", `{"alg":"HS256","b64":false}`, false},
		{"null base64 setting", `{"alg":"HS256","b64":null}`, false},
		{"string base64 setting", `{"alg":"HS256","b64":"true"}`, false},
		{"wrong algorithm", `{"alg":"HS384"}`, false},
		{"unsigned algorithm", `{"alg":"none"}`, false},
		{"missing algorithm", `{}`, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			// Every fixture has a genuine MAC, so rejection must come from
			// header policy rather than a malformed signature.
			token := signedToken(tt.header, `{"sub":"user_123","exp":4102444800}`, secret)
			claims, err := tokener.Verify(token)
			if tt.valid {
				if err != nil || claims == nil || claims.Sub != "user_123" {
					t.Fatalf("Verify() = %#v, %v, want valid claims", claims, err)
				}
			} else if !errors.Is(err, jwt.ErrInvalidToken) || claims != nil {
				t.Fatalf("Verify() = %#v, %v, want nil, ErrInvalidToken", claims, err)
			}
		})
	}
}

func TestHS256SignVerifyRoundTrip(t *testing.T) {
	for _, secret := range []string{"", "short", "01234567890123456789012345678901"} {
		tokener, err := jwt.NewHS256Tokener[*testClaims](secret, time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		original := &testClaims{Sub: "user_123"}
		token, err := tokener.Sign(original)
		if err != nil {
			t.Fatal(err)
		}
		got, err := tokener.Verify(token)
		if err != nil || got == nil || *got != *original {
			t.Fatalf("Verify(Sign()) = %#v, %v, want %#v", got, err, original)
		}
	}
}

func signedToken(header, payload, secret string) string {
	encode := base64.RawURLEncoding.EncodeToString
	input := encode([]byte(header)) + "." + encode([]byte(payload))
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(input))
	return input + "." + encode(mac.Sum(nil))
}
