package memory

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/tavocg/go-auth"
)

func TestIssueRemovesExpiredRefreshRecords(t *testing.T) {
	a, err := NewAuthenticator[*testClaims]("test-secret", time.Minute, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	a.store = map[string]refreshRecord[*testClaims]{
		"expired":   {Identity: &testClaims{Sub: "old"}, ExpiresAt: now - 1},
		"boundary":  {Identity: &testClaims{Sub: "old"}, ExpiresAt: now},
		"valid":     {Identity: &testClaims{Sub: "active"}, ExpiresAt: now + 3600},
		"unlimited": {Identity: &testClaims{Sub: "unlimited"}},
	}
	_, token, err := a.Issue(context.Background(), &testClaims{Sub: "new"})
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"expired", "boundary"} {
		if _, exists := a.store[key]; exists {
			t.Errorf("expired refresh record %q was retained", key)
		}
	}
	for _, key := range []string{"valid", "unlimited", hashSecret(token.Value)} {
		if _, exists := a.store[key]; !exists {
			t.Errorf("active refresh record %q was removed", key)
		}
	}
}

func TestCleanupRunsAtMostOncePerMinute(t *testing.T) {
	a, err := NewAuthenticator[*testClaims]("test-secret", time.Minute, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	now := time.Unix(1800000000, 0)
	a.pruneExpired(now)
	a.store["expired"] = refreshRecord[*testClaims]{ExpiresAt: now.Unix() + 1}
	a.pruneExpired(now.Add(59 * time.Second))
	if _, exists := a.store["expired"]; !exists {
		t.Fatal("cleanup ran again before one minute elapsed")
	}
	a.pruneExpired(now.Add(time.Minute))
	if _, exists := a.store["expired"]; exists {
		t.Fatal("expired record retained when the next cleanup was due")
	}
}

func TestRefreshPrunesOtherExpiredRecords(t *testing.T) {
	a, err := NewAuthenticator[*testClaims]("test-secret", time.Minute, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	_, token, err := a.Issue(ctx, &testClaims{Sub: "active"})
	if err != nil {
		t.Fatal(err)
	}
	a.store["expired"] = refreshRecord[*testClaims]{ExpiresAt: time.Now().Unix() - 1}
	a.nextCleanup = time.Time{}
	_, replacement, err := a.Refresh(ctx, token.Value)
	if err != nil {
		t.Fatal(err)
	}
	if _, exists := a.store["expired"]; exists {
		t.Fatal("refresh rotation retained unrelated expired records")
	}
	if _, _, err := a.Refresh(ctx, replacement.Value); err != nil {
		t.Fatalf("replacement refresh failed: %v", err)
	}
}

func TestRefreshRejectsExpiredRecordBetweenCleanups(t *testing.T) {
	a, err := NewAuthenticator[*testClaims]("test-secret", time.Minute, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	_, token, err := a.Issue(ctx, &testClaims{Sub: "user"})
	if err != nil {
		t.Fatal(err)
	}
	key := hashSecret(token.Value)
	record := a.store[key]
	record.ExpiresAt = time.Now().Unix() - 1
	a.store[key] = record
	if _, _, err := a.Refresh(ctx, token.Value); !errors.Is(err, auth.ErrExpiredToken) {
		t.Fatalf("Refresh() error = %v, want ErrExpiredToken", err)
	}
	if _, exists := a.store[key]; exists {
		t.Fatal("expired refresh record was retained after use")
	}
}
