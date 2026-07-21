// Package authenticators documents auth.Authenticator implementation patterns.
//
// A typical implementation uses a jwt.Tokener for short-lived access tokens and
// stores only hashed opaque refresh tokens server-side.
//
// A database-backed authenticator can use a table like:
//
//	refresh_tokens(
//	    token_hash text primary key,
//	    subject text not null,
//	    expires_at bigint not null
//	)
//
// Issue signs an access token, creates a random refresh token, stores its hash,
// and returns both values.
//
// Refresh hashes the provided refresh token, loads the row, rejects missing or
// expired rows, deletes the old row, then issues a new token pair.
//
// Verify validates only the access token. Revoke deletes one refresh-token row.
// RevokeAll deletes every row for the identity subject.
package authenticators
