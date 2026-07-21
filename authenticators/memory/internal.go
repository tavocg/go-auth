package memory

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"reflect"
)

type refreshRecord[T Claims] struct {
	Identity  T
	ExpiresAt int64
}

func cloneClaims[T Claims](claims T) (T, error) {
	raw, err := json.Marshal(claims)
	if err != nil {
		var zero T
		return zero, err
	}

	var cloned T
	if err := json.Unmarshal(raw, &cloned); err != nil {
		var zero T
		return zero, err
	}

	return cloned, nil
}

func isNil[T any](value T) bool {
	v := reflect.ValueOf(value)
	if !v.IsValid() {
		return true
	}

	switch v.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return v.IsNil()
	default:
		return false
	}
}

func randomSecret() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}

	return hex.EncodeToString(buf), nil
}

func hashSecret(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}
