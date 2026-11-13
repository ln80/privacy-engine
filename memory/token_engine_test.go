package memory

import (
	"context"
	"testing"

	"github.com/ln80/privacy-engine/privacytest"
)

func TestTokenEngine(t *testing.T) {
	eng := NewTokenEngine()
	privacytest.RunTokenEngineTest(t, context.Background(), eng, func(c *privacytest.TokenEngineTestConfig) {
		c.SealedProbe = func(_ context.Context, ns, token string) (bool, error) {
			eng.mu.Lock()
			defer eng.mu.Unlock()
			v, ok := eng.ns[ns]
			if !ok {
				return false, nil
			}
			return len(v.records[token].Sealed) > 0, nil
		}
	})
}
