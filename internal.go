package auth

type errStr string

func (e errStr) Error() string {
	return string(e)
}

var (
	// ErrInvalidIdentity reports that the supplied identity cannot be used.
	ErrInvalidIdentity error = errStr("invalid identity")
	// ErrInvalidToken reports that a token cannot be parsed or trusted.
	ErrInvalidToken error = errStr("invalid token")
	// ErrExpiredToken reports that a token is no longer valid because it expired.
	ErrExpiredToken error = errStr("expired token")
	// ErrRevokedToken reports that a token has already been revoked.
	ErrRevokedToken error = errStr("revoked token")
	// ErrUnsupportedToken reports that a token format or algorithm is not supported.
	ErrUnsupportedToken error = errStr("unsupported token")
)
