package memory

import (
	"context"
	"testing"
	"time"

	"github.com/ln80/privacy-engine/privacytest"
)

func TestKeyEngine(t *testing.T) {
	ctx := context.Background()

	t.Run("in-memory engine", func(t *testing.T) {
		eng := NewKeyEngine()

		privacytest.RunKeyEngineTest(t, ctx, eng)
	})

	t.Run("in-memory cache wrapper engine", func(t *testing.T) {
		originEng := NewKeyEngine()

		eng := NewCacheWrapper(originEng, 20*time.Minute)

		privacytest.RunKeyEngineTest(t, ctx, eng)
	})
}
