package auth

type errStr string

func (e errStr) Error() string {
	return string(e)
}

var (
	// ErrInvalidIdentity reports that the supplied identity cannot be used.
	ErrInvalidIdentity error = errStr("invalid identity")
	// ErrInvalidSecret reports that a signing secret is missing or unusable.
	ErrInvalidSecret error = errStr("invalid secret")
	// ErrInvalidToken reports that a token cannot be parsed or trusted.
	ErrInvalidToken error = errStr("invalid token")
	// ErrExpiredToken reports that a token is no longer valid because it expired.
	ErrExpiredToken error = errStr("expired token")
	// ErrRevokedToken reports that a token has already been revoked.
	ErrRevokedToken error = errStr("revoked token")
)
