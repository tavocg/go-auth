package memory

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"time"
)

type refreshRecord[T Claims] struct {
	Identity  T
	ExpiresAt int64
}

// pruneExpired requires mu to be held. Issuance amortizes the scan to at most
// once per minute; an idle authenticator needs no background worker.
func (a *Authenticator[T]) pruneExpired(now time.Time) {
	if a.refreshTTL <= 0 || now.Before(a.nextCleanup) {
		return
	}
	a.nextCleanup = now.Add(time.Minute)
	for key, record := range a.store {
		if record.ExpiresAt != 0 && record.ExpiresAt <= now.Unix() {
			delete(a.store, key)
		}
	}
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
