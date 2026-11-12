package memory

import (
	"context"
	"testing"
	"time"

	"github.com/ln80/privacy-engine/core"
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

// PE-15 regression: as a store, ClearCache never deletes tokens, whether the
// clear is forced or the entries are past the TTL. As a cache it still clears.
func TestTokenStoreSurvivesClearCache(t *testing.T) {
	ctx := context.Background()
	const ns = "tenant-pe15"

	store := NewTokenEngine()
	tokens, err := store.Tokenize(ctx, ns, []core.TokenData{"alice@example.org"})
	if err != nil {
		t.Fatal(err)
	}
	token := tokens.Get("alice@example.org").Token

	// Age every entry past any TTL, as a Monitor tick a while later would see it.
	c := store.cacheOf(ns)
	c.mutex.Lock()
	for k, e := range c.tokenToValue {
		e.At -= 3600
		c.tokenToValue[k] = e
		c.valueToToken[e.Value] = e
	}
	c.mutex.Unlock()

	for _, force := range []bool{false, true} {
		if err := store.ClearCache(ctx, ns, force); err != nil {
			t.Fatal(err)
		}
		values, err := store.Detokenize(ctx, ns, []string{token})
		if err != nil {
			t.Fatal(err)
		}
		if values.Get(token).Value.Reveal() != "alice@example.org" {
			t.Fatalf("force=%v: store lost its token", force)
		}
	}

	// The cache wrapper still clears its own copy; the origin keeps the data.
	wrapper := NewTokenCacheWrapper(store, time.Minute)
	if _, err := wrapper.Detokenize(ctx, ns, []string{token}); err != nil {
		t.Fatal(err)
	}
	if err := wrapper.ClearCache(ctx, ns, true); err != nil {
		t.Fatal(err)
	}
	if _, ok := wrapper.cacheOf(ns).value(token); ok {
		t.Fatal("expect the wrapper cache cleared")
	}
	values, err := wrapper.Detokenize(ctx, ns, []string{token})
	if err != nil || values.Get(token).Value.Reveal() != "alice@example.org" {
		t.Fatalf("expect the value refetched from the origin, got %v", err)
	}
}
