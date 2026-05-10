package jwt

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
)

const (
	algHS256 = "HS256"
	jwtType  = "JWT"
	claimExp = "exp"
)

type errStr string

func (e errStr) Error() string {
	return string(e)
}

var (
	ErrInvalidSecret error = errStr("invalid secret")
	ErrInvalidToken  error = errStr("invalid token")
	ErrExpiredToken  error = errStr("expired token")
)

type signer func(signingInput, secret []byte) ([]byte, error)

type header struct {
	Algorithm string `json:"alg"`
	Type      string `json:"typ,omitempty"`
}

func signToken(claims Claims, alg string, secret []byte, sign signer) (string, error) {
	if len(secret) == 0 {
		return "", ErrInvalidSecret
	}
	if sign == nil {
		return "", ErrInvalidToken
	}
	if claims == nil {
		claims = Claims{}
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

func verifyHS256Token(token string, secret []byte) (Claims, error) {
	if len(secret) == 0 {
		return nil, ErrInvalidSecret
	}

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, ErrInvalidToken
	}

	head, payload, signature := parts[0], parts[1], parts[2]
	expected, err := signHS256([]byte(head+"."+payload), secret)
	if err != nil {
		return nil, err
	}

	got, err := decode(signature)
	if err != nil || !hmac.Equal(got, expected) {
		return nil, ErrInvalidToken
	}

	headBytes, err := decode(head)
	if err != nil {
		return nil, ErrInvalidToken
	}

	var parsedHeader header
	if err := json.Unmarshal(headBytes, &parsedHeader); err != nil || parsedHeader.Algorithm != algHS256 {
		return nil, ErrInvalidToken
	}

	payloadBytes, err := decode(payload)
	if err != nil {
		return nil, ErrInvalidToken
	}

	var claims Claims
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return nil, ErrInvalidToken
	}

	return claims, nil
}

func signingInput(header header, claims Claims) (string, error) {
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

func signHS256(signingInput, secret []byte) ([]byte, error) {
	mac := hmac.New(sha256.New, secret)
	mac.Write(signingInput)
	return mac.Sum(nil), nil
}

func cloneClaims(claims Claims) Claims {
	cloned := make(Claims, len(claims))
	for key, value := range claims {
		cloned[key] = value
	}

	return cloned
}

// claimInt64 reads an integer claim value when present.
func claimInt64(claims Claims, key string) (int64, bool, error) {
	value, ok := claims[key]
	if !ok {
		return 0, false, nil
	}

	switch value := value.(type) {
	case float64:
		return int64(value), true, nil
	case float32:
		return int64(value), true, nil
	case int:
		return int64(value), true, nil
	case int64:
		return value, true, nil
	case int32:
		return int64(value), true, nil
	case json.Number:
		n, err := value.Int64()
		if err != nil {
			return 0, false, ErrInvalidToken
		}
		return n, true, nil
	default:
		return 0, false, ErrInvalidToken
	}
}
