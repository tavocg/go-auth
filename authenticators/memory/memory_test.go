package memory

import (
	"context"
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
