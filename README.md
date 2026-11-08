# go-auth

Small Go authentication interfaces and JWT-backed authenticator helpers.

## Packages

- `auth`: generic token/authenticator interfaces and token value types
- `authenticators`: implementation notes for custom authenticators
- `authenticators/memory`: in-memory authenticator implementation
- `jwt`: minimal JWT signing and verification helpers

## Memory Authenticator

The memory authenticator keeps refresh tokens in process memory only. Refresh
tokens are lost when the authenticator is discarded or the process exits, so use
it for tests, examples, and single-process applications rather than durable
multi-instance deployments.

Refresh-token issuance, rotation, and revocation are serialized within an
authenticator. `RevokeAll` removes replacements from overlapping refreshes;
an `Issue` ordered after revocation can create a new session. Revocation does
not invalidate access tokens, which remain valid until expiration.

When refresh tokens have an expiration, issuing or rotating a token pair also
removes expired refresh records, with at most one scan per minute. Cleanup is
lazy: an idle authenticator retains records until the next issuance. Valid
records and tokens configured without expiration are preserved. A token
already removed by cleanup returns `auth.ErrInvalidToken` on refresh; an expired
record still present returns `auth.ErrExpiredToken` and is deleted immediately.

```go
type Claims struct {
	Expires int64  `json:"expires_at,omitempty"`
	Role    string `json:"role,omitempty"`
	Sub     string `json:"sub"`
}

func (c *Claims) ExpiresAt() int64    { return c.Expires }
func (c *Claims) SetExpiresAt(v int64) { c.Expires = v }
func (c *Claims) Subject() string      { return c.Sub }

ctx := context.Background()

a, err := memory.NewAuthenticator[*Claims]("secret", 15*time.Minute, 24*time.Hour)
if err != nil {
	log.Fatal(err)
}

at, rt, err := a.Issue(ctx, &Claims{Sub: "user_123", Role: "admin"})
if err != nil {
	log.Fatal(err)
}

claims, err := a.Verify(ctx, at.Value)
if err != nil {
	log.Fatal(err)
}

at, rt, err = a.Refresh(ctx, rt.Value)
if err != nil {
	log.Fatal(err)
}

_ = claims
_ = at
_ = a.Revoke(ctx, rt.Value)
```

## Expiration Behavior

`Token.ExpiresAt` and `Claims.ExpiresAt` use Unix timestamps in seconds. A zero
expiration means no expiration is configured.

Constructors reject negative access or refresh TTLs with `jwt.ErrInvalidTTL`.
A zero JWT TTL leaves the provided claims' expiration unchanged; a zero refresh
TTL creates refresh tokens without expiration. Use positive TTLs for automatic
expiration.

`jwt.Tokener.Sign` mutates the provided claims when the tokener has a positive
TTL: it calls `SetExpiresAt` with the calculated Unix expiration timestamp
before signing.

## JWT header policy

HS256 verification does not support critical extensions: a header containing
`crit` is rejected with `jwt.ErrInvalidToken`, including malformed, empty, or
null values. JWT payloads must remain base64url encoded; an explicit `b64` is
accepted only when it is `true`. Ordinary tokens and optional noncritical
headers remain supported.

## Examples

Run the complete example:

```sh
go run ./examples
```

## Signing secret policy

HS256 accepts secrets of any length, including an empty string. Applications
should warn when the secret is shorter than the recommended 32 random bytes.
An empty or guessable secret allows others to forge tokens. The library still
checks token signatures and expiration; it does not generate a replacement key.
