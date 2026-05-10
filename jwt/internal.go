package jwt

import (
	"encoding/base64"
	"encoding/json"
)

const (
	jwtType = "JWT"
)

type errStr string

func (e errStr) Error() string {
	return string(e)
}

var (
	ErrInvalidSecret     error = errStr("invalid secret")
	ErrInvalidSignFunc   error = errStr("invalid sign func")
	ErrInvalidVerifyFunc error = errStr("invalid verify func")
	ErrInvalidToken      error = errStr("invalid token")
	ErrExpiredToken      error = errStr("expired token")
)

type signer func(signingInput, secret []byte) ([]byte, error)

type header struct {
	Algorithm string `json:"alg"`
	Type      string `json:"typ,omitempty"`
}

func signToken[C Claimer](claims C, alg string, secret []byte, sign signer) (string, error) {
	if len(secret) == 0 {
		return "", ErrInvalidSecret
	}
	if sign == nil {
		return "", ErrInvalidToken
	}

	header := header{
		Algorithm: alg,
		Type:      jwtType,
	}

	signingInput, err := signingInput(header, claims)
	if err != nil {
		return "", err
	}

	signature, err := sign([]byte(signingInput), secret)
	if err != nil {
		return "", err
	}

	return signingInput + "." + encode(signature), nil
}

func signingInput[C Claimer](header header, claims C) (string, error) {
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", err
	}

	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}

	return encode(headerJSON) + "." + encode(claimsJSON), nil
}

func encode(src []byte) string {
	return base64.RawURLEncoding.EncodeToString(src)
}

func decode(src string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(src)
}
