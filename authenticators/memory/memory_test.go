package memory

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/tavocg/go-auth"
)

type testClaims struct {
	Expires int64  `json:"expires_at,omitempty"`
	Sub     string `json:"sub"`
}

func (c *testClaims) ExpiresAt() int64 {
	if c == nil {
		return 0
	}
	return c.Expires
}

func (c *testClaims) SetExpiresAt(exp int64) {
	if c != nil {
		c.Expires = exp
	}
}

func (c *testClaims) Subject() string {
	if c == nil {
		return ""
	}
	return c.Sub
}

// Only revocationClaims uses this hook; its test joins the worker before
// clearing it, and does not run in parallel.
var revocationMarshalHook func()

type revocationClaims struct{ testClaims }

func (c *revocationClaims) MarshalJSON() ([]byte, error) {
	if revocationMarshalHook != nil {
		revocationMarshalHook()
	}
	return json.Marshal(&c.testClaims)
}

func TestRevokeAllWaitsForRefreshReplacement(t *testing.T) {
	ctx := context.Background()
	a, err := NewAuthenticator[*revocationClaims]("test-secret", time.Minute, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	identity := &revocationClaims{testClaims{Sub: "user_123"}}
	_, original, err := a.Issue(ctx, identity)
	if err != nil {
		t.Fatal(err)
	}

	entered, resume := make(chan struct{}), make(chan struct{})
	var enteredOnce, resumeOnce sync.Once
	release := func() { resumeOnce.Do(func() { close(resume) }) }
	revocationMarshalHook = func() {
		enteredOnce.Do(func() { close(entered) })
		<-resume
	}
	defer func() { revocationMarshalHook = nil }()
	defer release()

	type result struct {
		token *auth.Token
		err   error
	}
	refreshed := make(chan result, 1)
	go func() {
		_, token, err := a.Refresh(ctx, original.Value)
		refreshed <- result{token, err}
	}()
	<-entered // Refresh has consumed the old token and is preparing its replacement.
	// Allow revocation to overlap the paused refresh, then let both finish.
	timer := time.AfterFunc(100*time.Millisecond, release)
	defer timer.Stop()
	revokeErr := a.RevokeAll(ctx, identity)
	release()
	got := <-refreshed
	if revokeErr != nil {
		t.Fatal(revokeErr)
	}
	if got.err != nil {
		t.Fatal(got.err)
	}
	if _, _, err := a.Refresh(ctx, got.token.Value); !errors.Is(err, auth.ErrInvalidToken) {
		t.Fatalf("refresh after revocation returned %v, want ErrInvalidToken", err)
	}
}

func TestRevokeAllPreservesOtherIdentitiesAndAllowsNewSessions(t *testing.T) {
	ctx := context.Background()
	a, err := NewAuthenticator[*testClaims]("test-secret", time.Minute, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	identity := &testClaims{Sub: "user_123"}
	access, first, err := a.Issue(ctx, identity)
	if err != nil {
		t.Fatal(err)
	}
	_, second, err := a.Issue(ctx, identity)
	if err != nil {
		t.Fatal(err)
	}
	_, other, err := a.Issue(ctx, &testClaims{Sub: "user_456"})
	if err != nil {
		t.Fatal(err)
	}
	if err := a.RevokeAll(ctx, identity); err != nil {
		t.Fatal(err)
	}
	for _, token := range []*auth.Token{first, second} {
		if _, _, err := a.Refresh(ctx, token.Value); !errors.Is(err, auth.ErrInvalidToken) {
			t.Fatalf("revoked refresh returned %v, want ErrInvalidToken", err)
		}
	}
	if _, _, err := a.Refresh(ctx, other.Value); err != nil {
		t.Fatalf("other identity's refresh failed: %v", err)
	}
	if _, err := a.Verify(ctx, access.Value); err != nil {
		t.Fatalf("existing access token failed verification: %v", err)
	}
	_, fresh, err := a.Issue(ctx, identity)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := a.Refresh(ctx, fresh.Value); err != nil {
		t.Fatalf("new session after revocation failed: %v", err)
	}
}

func TestRefreshConsumesRefreshTokenOnce(t *testing.T) {
	ctx := context.Background()
	const attempts = 128

	for run := 0; run < 100; run++ {
		a, err := NewAuthenticator[*testClaims]("test-secret", time.Minute, time.Hour)
		if err != nil {
			t.Fatal(err)
		}

		_, refreshToken, err := a.Issue(ctx, &testClaims{Sub: "user_123"})
		if err != nil {
			t.Fatal(err)
		}

		start := make(chan struct{})
		var wg sync.WaitGroup
		errs := make(chan error, attempts)

		for i := 0; i < attempts; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				_, _, err := a.Refresh(ctx, refreshToken.Value)
				errs <- err
			}()
		}

		close(start)
		wg.Wait()
		close(errs)

		successes := 0
		for err := range errs {
			if err == nil {
				successes++
				continue
			}
			if !errors.Is(err, auth.ErrInvalidToken) {
				t.Fatalf("refresh returned %v, want nil or ErrInvalidToken", err)
			}
		}

		if successes != 1 {
			t.Fatalf("refresh succeeded %d times, want 1", successes)
		}
	}
}
