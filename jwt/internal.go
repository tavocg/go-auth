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

type signer func(signingInput, secret []byte) ([]byte, error)

type header struct {
	Algorithm string          `json:"alg"`
	Type      string          `json:"typ,omitempty"`
	Critical  json.RawMessage `json:"crit,omitempty"`
	Base64    json.RawMessage `json:"b64,omitempty"`
}

func signToken[C Claims](claims C, alg string, secret []byte, sign signer) (string, error) {
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

func signingInput[C Claims](header header, claims C) (string, error) {
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
