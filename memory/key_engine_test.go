package memory

import (
	"bytes"
	"context"
	"sync"
	"testing"
	"time"

	"github.com/ln80/privacy-engine/core"
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
