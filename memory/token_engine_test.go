package memory

import (
	"context"
	"testing"
	"time"

	"github.com/ln80/privacy-engine/privacytest"
)

func TestTokenEngine(t *testing.T) {
	ctx := context.Background()

	t.Run("in-memory engine", func(t *testing.T) {
		privacytest.RunTokenEngineTest(t, ctx, NewTokenEngine())
	})

	t.Run("in-memory cache wrapper engine", func(t *testing.T) {
		originEngine := NewTokenEngine()
		privacytest.RunTokenEngineTest(t, ctx, NewTokenCacheWrapper(originEngine, 20*time.Minute))
	})
}
