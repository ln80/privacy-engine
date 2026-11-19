package memory

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/ln80/privacy-engine/core"
	"github.com/ln80/privacy-engine/privacytest"
)

func TestKeyEngine(t *testing.T) {
	ctx := context.Background()

	t.Run("in-memory engine", func(t *testing.T) {
		grace := 200 * time.Millisecond
		eng := NewKeyEngine(func(c *core.KeyEngineConfig) { c.GracePeriod = grace })

		privacytest.RunKeyEngineTest(t, ctx, eng, func(c *privacytest.KeyEngineTestConfig) {
			c.GracePeriod = grace
			c.KeyMaterialProbe = func(_ context.Context, ns, keyID string) (bool, error) {
				e := eng.(*engine)
				e.mu.Lock()
				defer e.mu.Unlock()
				return len(e.cache[ns][keyID].Key) > 0, nil
			}
		})
	})

	t.Run("in-memory cache wrapper engine", func(t *testing.T) {
		originEng := NewKeyEngine()

		eng := NewCacheWrapper(originEng, 20*time.Minute)

		privacytest.RunKeyEngineTest(t, ctx, eng)
	})
}

func TestKeyCopiesStayIntactWhenCacheIsCleared(t *testing.T) {
	ctx := context.Background()
	namespace := "ns-pe01"
	keyID := "subject-1"

	origin := NewKeyEngine()
	wrapper := NewCacheWrapper(origin, time.Minute)
	cache := wrapper.(core.KeyEngineCache)

	created, err := wrapper.GetOrCreateKeys(ctx, namespace, []string{keyID}, nil)
	if err != nil {
		t.Fatal(err)
	}
	held := created[keyID]
	heldSnap := bytes.Clone(held)

	originKeys, _, err := origin.GetKeys(ctx, namespace, []string{keyID})
	if err != nil {
		t.Fatal(err)
	}
	originSnap := bytes.Clone(originKeys[keyID])
	if len(originSnap) == 0 || bytes.Equal(originSnap, make([]byte, len(originSnap))) {
		t.Fatal("origin key is empty")
	}

	if err := cache.ClearCache(ctx, namespace, true); err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(held, heldSnap) {
		t.Fatal("ClearCache rewrote a key the caller still holds")
	}
	originAfter, _, err := origin.GetKeys(ctx, namespace, []string{keyID})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(originAfter[keyID], originSnap) {
		t.Fatal("cache eviction rewrote the origin key")
	}

	held[0] ^= 0xff
	reloaded, _, err := wrapper.GetKeys(ctx, namespace, []string{keyID})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(reloaded[keyID], held) {
		t.Fatal("caller and cache still share a key slice")
	}
	if !bytes.Equal(reloaded[keyID], originSnap) {
		t.Fatal("reloaded key does not match the origin key")
	}
}

func TestDeleteAndPurgeDoNotZeroReturnedKeys(t *testing.T) {
	ctx := context.Background()
	namespace := "ns-pe01-store"

	eng := NewKeyEngine()
	created, err := eng.GetOrCreateKeys(ctx, namespace, []string{"a", "b"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	heldA := bytes.Clone(created["a"])
	heldB := created["b"]
	snapB := bytes.Clone(heldB)

	if err := eng.DeleteKey(ctx, namespace, "a"); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(created["a"], heldA) {
		t.Fatal("DeleteKey rewrote a key the caller still holds")
	}

	if err := eng.PurgeNamespace(ctx, namespace); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(heldB, snapB) {
		t.Fatal("PurgeNamespace rewrote a key the caller still holds")
	}
}

func TestConcurrentClearDoesNotRaceWithHeldKey(t *testing.T) {
	ctx := context.Background()
	namespace := "ns-pe01-race"
	keyID := "subject-1"

	origin := NewKeyEngine()
	wrapper := NewCacheWrapper(origin, time.Millisecond)
	cache := wrapper.(core.KeyEngineCache)

	created, err := wrapper.GetOrCreateKeys(ctx, namespace, []string{keyID}, nil)
	if err != nil {
		t.Fatal(err)
	}
	held := created[keyID]
	snap := bytes.Clone(held)

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 200; i++ {
			_ = held[i%len(held)]
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 200; i++ {
			if err := cache.ClearCache(ctx, namespace, true); err != nil {
				t.Error(err)
				return
			}
			if _, _, err := wrapper.GetKeys(ctx, namespace, []string{keyID}); err != nil {
				t.Error(err)
				return
			}
		}
	}()
	wg.Wait()

	if !bytes.Equal(held, snap) {
		t.Fatal("held key changed while the cache was cleared")
	}
	originKeys, _, err := origin.GetKeys(ctx, namespace, []string{keyID})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(originKeys[keyID], snap) {
		t.Fatal("origin key changed while the cache was cleared")
	}
}

// A cache that has never seen a key reports the origin's state for it, so a
// subject forgotten by another instance reads as disabled, not unknown.
func TestCacheWrapperReportsOriginStates(t *testing.T) {
	ctx := context.Background()
	const namespace = "tenant-states"

	origin := NewKeyEngine()
	if _, err := origin.GetOrCreateKeys(ctx, namespace, []string{"active", "disabled", "deleted"}, nil); err != nil {
		t.Fatal(err)
	}
	if err := origin.DisableKey(ctx, namespace, "disabled"); err != nil {
		t.Fatal(err)
	}
	if err := origin.DeleteKey(ctx, namespace, "deleted"); err != nil {
		t.Fatal(err)
	}

	wrapper := NewCacheWrapper(origin, time.Minute)
	keys, missing, err := wrapper.GetKeys(ctx, namespace, []string{"active", "disabled", "deleted", "never"})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := keys["active"]; !ok || len(keys) != 1 {
		t.Fatalf("expect only the active key, got %v", keys.KeyIDs())
	}
	want := core.KeyStates{
		"disabled": core.StateDisabled,
		"deleted":  core.StateDeleted,
		"never":    core.StateUnknown,
	}
	if len(missing) != len(want) {
		t.Fatalf("expect %v, got %v", want, missing)
	}
	for id, state := range want {
		if missing[id] != state {
			t.Fatalf("%s: expect %s, got %s", id, state, missing[id])
		}
	}
}

// PE-04 regression: once the origin succeeds, the cache wrapper reports
// success whether or not it holds the key, and never serves a stale state.
func TestCacheWrapperDisableReEnableFollowOrigin(t *testing.T) {
	ctx := context.Background()
	const namespace, keyID = "tenant-pe04", "u1"

	origin := NewKeyEngine()
	wrapper := NewCacheWrapper(origin, time.Minute).(core.KeyEngineCache)

	created, err := wrapper.GetOrCreateKeys(ctx, namespace, []string{keyID}, nil)
	if err != nil {
		t.Fatal(err)
	}
	original := bytes.Clone(created[keyID])

	stateOf := func(eng core.KeyEngine) core.KeyState {
		t.Helper()
		keys, missing, err := eng.GetKeys(ctx, namespace, []string{keyID})
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := keys[keyID]; ok {
			return core.StateActive
		}
		return missing[keyID]
	}

	// Evicted, then forgotten: success, and the origin is disabled.
	if err := wrapper.ClearCache(ctx, namespace, true); err != nil {
		t.Fatal(err)
	}
	if err := wrapper.DisableKey(ctx, namespace, keyID); err != nil {
		t.Fatalf("DisableKey after eviction: %v", err)
	}
	if got := stateOf(origin); got != core.StateDisabled {
		t.Fatalf("origin state %s, want DISABLED", got)
	}
	if got := stateOf(wrapper); got != core.StateDisabled {
		t.Fatalf("wrapper state %s, want DISABLED", got)
	}

	// Evicted, then recovered: success, and the same key comes back.
	if err := wrapper.ClearCache(ctx, namespace, true); err != nil {
		t.Fatal(err)
	}
	if err := wrapper.ReEnableKey(ctx, namespace, keyID); err != nil {
		t.Fatalf("ReEnableKey after eviction: %v", err)
	}
	keys, _, err := wrapper.GetKeys(ctx, namespace, []string{keyID})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(keys[keyID], original) {
		t.Fatal("recovered key differs from the original")
	}

	// Disabled while cached: the wrapper stops holding the key at once.
	if err := wrapper.DisableKey(ctx, namespace, keyID); err != nil {
		t.Fatal(err)
	}
	if got := stateOf(wrapper); got != core.StateDisabled {
		t.Fatalf("wrapper state %s, want DISABLED", got)
	}

	// Origin errors still come through.
	if err := origin.DeleteKey(ctx, namespace, keyID); err != nil {
		t.Fatal(err)
	}
	if err := wrapper.ReEnableKey(ctx, namespace, keyID); !errors.Is(err, core.ErrKeyNotFound) {
		t.Fatalf("ReEnableKey of a deleted key: expect ErrKeyNotFound, got %v", err)
	}
}

// A key forgotten through another instance must stop being served once the
// cache TTL has passed, without anyone calling ClearCache: the TTL is the
// erasure latency bound across instances.
func TestCacheWrapperDoesNotServeExpiredKeys(t *testing.T) {
	ctx := context.Background()
	origin := NewKeyEngine()
	if _, err := origin.GetOrCreateKeys(ctx, "ns", []string{"s"}, nil); err != nil {
		t.Fatal(err)
	}
	ttl := 50 * time.Millisecond
	cache := NewCacheWrapper(origin, ttl)
	keys, _, err := cache.GetKeys(ctx, "ns", []string{"s"})
	if err != nil || keys["s"] == nil {
		t.Fatalf("expect a cached key, got %v, %v", keys, err)
	}

	// Another instance forgets the subject in the origin.
	if err := origin.DisableKey(ctx, "ns", "s"); err != nil {
		t.Fatal(err)
	}
	time.Sleep(2 * ttl)

	keys, missing, err := cache.GetKeys(ctx, "ns", []string{"s"})
	if err != nil {
		t.Fatal(err)
	}
	if keys["s"] != nil || missing["s"] != core.StateDisabled {
		t.Fatalf("expect DISABLED after TTL, got keys=%v missing=%v", keys.KeyIDs(), missing)
	}
}

// Concurrent GetOrCreateKeys calls for a fresh subject must all return the
// same key: a caller that lost the race used to get no key, which the
// protector reads as a forgotten subject.
func TestStoreGetOrCreateKeysConcurrentFreshSubject(t *testing.T) {
	ctx := context.Background()
	for range 200 {
		eng := NewKeyEngine()
		var wg sync.WaitGroup
		got := make([]core.Key, 8)
		for i := range got {
			wg.Add(1)
			go func() {
				defer wg.Done()
				keys, err := eng.GetOrCreateKeys(ctx, "ns", []string{"s"}, nil)
				if err != nil {
					t.Error(err)
					return
				}
				got[i] = keys["s"]
			}()
		}
		wg.Wait()
		for i, k := range got {
			if len(k) == 0 {
				t.Fatalf("caller %d got no key for a fresh subject", i)
			}
			if !bytes.Equal(k, got[0]) {
				t.Fatalf("caller %d got a different key", i)
			}
		}
	}
}

// The store reports a key disabled longer than the grace period as DELETED
// and refuses to re-enable it even before DeleteUnusedKeys runs, keeps the
// first disable time, and keeps a key recoverable within the period.
func TestStoreGracePeriodWithoutJanitor(t *testing.T) {
	ctx := context.Background()
	grace := 100 * time.Millisecond
	eng := NewKeyEngine(func(c *core.KeyEngineConfig) { c.GracePeriod = grace })
	if _, err := eng.GetOrCreateKeys(ctx, "ns", []string{"a", "b"}, nil); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"a", "b"} {
		if err := eng.DisableKey(ctx, "ns", id); err != nil {
			t.Fatal(err)
		}
	}
	// Within the period: recoverable.
	if err := eng.ReEnableKey(ctx, "ns", "a"); err != nil {
		t.Fatalf("expect re-enable within grace period, got %v", err)
	}

	time.Sleep(grace / 2)
	// A second disable must not restart the period.
	if err := eng.DisableKey(ctx, "ns", "b"); err != nil {
		t.Fatal(err)
	}
	time.Sleep(grace/2 + 10*time.Millisecond)

	_, missing, err := eng.GetKeys(ctx, "ns", []string{"b"})
	if err != nil {
		t.Fatal(err)
	}
	if missing["b"] != core.StateDeleted {
		t.Fatalf("expect DELETED past grace period, got %v", missing["b"])
	}
	if err := eng.ReEnableKey(ctx, "ns", "b"); !errors.Is(err, core.ErrKeyNotFound) {
		t.Fatalf("expect ErrKeyNotFound past grace period, got %v", err)
	}
}

func TestStoreDefaultGracePeriod(t *testing.T) {
	e := NewKeyEngine(func(c *core.KeyEngineConfig) { c.GracePeriod = 0 }).(*engine)
	if want := core.NewKeyEngineConfig().GracePeriod; e.gracePeriod != want {
		t.Fatalf("expect default grace period %v, got %v", want, e.gracePeriod)
	}
}
