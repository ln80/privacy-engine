package privacytest

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ln80/privacy-engine/core"
)

type KeyEngineTestConfig struct {
	GracePeriod          time.Duration
	AutoDeleteUnusedHook func()
	Namespace            string
}

func RunKeyEngineTest(t *testing.T, ctx context.Context, eng core.KeyEngine, opts ...func(*KeyEngineTestConfig)) {
	t.Helper()

	cfg := &KeyEngineTestConfig{}

	for _, opt := range opts {
		if opt == nil {
			continue
		}
		opt(cfg)
	}

	namespace := "tenant-kal34p"
	if cfg.Namespace != "" {
		namespace = cfg.Namespace
	}

	keys, missing, err := eng.GetKeys(ctx, namespace, nil)
	if err != nil {
		t.Fatalf("expect err be nil, got: %v", err)
	}
	assertMissing(t, missing, core.KeyStates{})
	if len(keys) != 0 {
		t.Fatalf("expect keys map be empty, got: %v", keys)
	}

	// A key ID the engine has never seen is reported as unknown, not forgotten.
	neverSeen := randomID()
	keys, missing, err = eng.GetKeys(ctx, namespace, []string{neverSeen})
	if err != nil {
		t.Fatalf("expect err be nil, got: %v", err)
	}
	if len(keys) != 0 {
		t.Fatalf("expect keys map be empty, got: %v", keys)
	}
	assertMissing(t, missing, core.KeyStates{neverSeen: core.StateUnknown})

	keyIDs := []string{
		randomID(),
		randomID(),
		randomID(),
	}

	nilErr := error(nil)
	empty := []string{}

	// Test GetOrCreate

	// First, a create a new key and return it
	keys, err = eng.GetOrCreateKeys(ctx, namespace, keyIDs[:1], nil)
	if err != nil {
		t.Fatalf("expect err be nil, got: %v", err)
	}
	if want, got := keyIDs[:1], keys.KeyIDs(); !keysEqual(want, got) {
		t.Fatalf("expect %v, %v be equals", want, got)
	}

	// Second, make sure to return an existing key while creating others.
	keys, err = eng.GetOrCreateKeys(ctx, namespace, keyIDs, nil)
	if err != nil {
		t.Fatalf("expect err be nil, got: %v", err)
	}
	if want, got := keyIDs, keys.KeyIDs(); !keysEqual(want, got) {
		t.Fatalf("expect %v, %v be equals", want, got)
	}

	// Test get a sub set of keys
	partial := keyIDs[1:]
	keys, missing, err = eng.GetKeys(ctx, namespace, partial)
	if err != nil {
		t.Fatalf("expect err be nil, got: %v", err)
	}
	assertMissing(t, missing, core.KeyStates{})
	if want, got := partial, keys.KeyIDs(); !keysEqual(want, got) {
		t.Fatalf("expect %v, %v be equals", want, got)
	}

	// Test disable key
	if want, err := nilErr, eng.DisableKey(ctx, namespace, keyIDs[0]); !errors.Is(err, want) {
		t.Fatalf("expect err be %v, got: %v", want, err)
	}
	// assert disable key idempotency
	if want, err := nilErr, eng.DisableKey(ctx, namespace, keyIDs[0]); !errors.Is(err, want) {
		t.Fatalf("expect err be %v, got: %v", want, err)
	}

	keys, missing, err = eng.GetKeys(ctx, namespace, keyIDs[0:1])
	if err != nil {
		t.Fatalf("expect err be nil, got: %v", err)
	}
	assertMissing(t, missing, core.KeyStates{keyIDs[0]: core.StateDisabled})
	if want, got := empty, keys.KeyIDs(); !keysEqual(want, got) {
		t.Fatalf("expect %v, %v be equals", want, got)
	}

	// Test renable key
	if want, err := nilErr, eng.ReEnableKey(ctx, namespace, keyIDs[0]); !errors.Is(err, want) {
		t.Fatalf("expect err be %v, got: %v", want, err)
	}
	// assert renable key idempotency
	if want, err := nilErr, eng.ReEnableKey(ctx, namespace, keyIDs[0]); !errors.Is(err, want) {
		t.Fatalf("expect err be %v, got: %v", want, err)
	}

	keys, missing, err = eng.GetKeys(ctx, namespace, keyIDs[0:1])
	if err != nil {
		t.Fatalf("expect err be nil, got: %v", err)
	}
	assertMissing(t, missing, core.KeyStates{})
	if want, got := keyIDs[:1], keys.KeyIDs(); !keysEqual(want, got) {
		t.Fatalf("expect %v, %v be equals", want, got)
	}

	// Disable key again
	if want, err := nilErr, eng.DisableKey(ctx, namespace, keyIDs[0]); !errors.Is(err, want) {
		t.Fatalf("expect err be %v, got: %v", want, err)
	}

	// Test delete key
	if want, err := nilErr, eng.DeleteKey(ctx, namespace, keyIDs[0]); !errors.Is(err, want) {
		t.Fatalf("expect err be %v, got: %v", want, err)
	}
	// Assert delete key idempotency
	if want, err := nilErr, eng.DeleteKey(ctx, namespace, keyIDs[0]); !errors.Is(err, want) {
		t.Fatalf("expect err be %v, got: %v", want, err)
	}
	keys, missing, err = eng.GetKeys(ctx, namespace, keyIDs[0:1])
	if err != nil {
		t.Fatalf("expect err be nil, got: %v", err)
	}
	assertMissing(t, missing, core.KeyStates{keyIDs[0]: core.StateDeleted})
	if want, got := empty, keys.KeyIDs(); !keysEqual(want, got) {
		t.Fatalf("expect %v, %v be equals", want, got)
	}
	// Test renable key after a hard delete
	if want, err := core.ErrKeyNotFound, eng.ReEnableKey(ctx, namespace, keyIDs[0]); !errors.Is(err, want) {
		t.Fatalf("expect err be %v, got: %v", want, err)
	}
	// Test disable key after a hard delete
	if want, err := core.ErrKeyNotFound, eng.DisableKey(ctx, namespace, keyIDs[0]); !errors.Is(err, want) {
		t.Fatalf("expect err be %v, got: %v", want, err)
	}

	// Test delete unused keys
	if cfg.GracePeriod != 0 {
		// Disable a key, we pick the second in the list
		if want, err := nilErr, eng.DisableKey(ctx, namespace, keyIDs[1]); !errors.Is(err, want) {
			t.Fatalf("expect err be %v, got: %v", want, err)
		}
		// Honore the grace Period which supposed to be short
		time.Sleep(cfg.GracePeriod)

		if cfg.AutoDeleteUnusedHook != nil {
			cfg.AutoDeleteUnusedHook()
		} else {
			// Assert the action runs with success
			if want, err := nilErr, eng.DeleteUnusedKeys(ctx, namespace); !errors.Is(err, want) {
				t.Fatalf("expect err be %v, got: %v", want, err)
			}
			// Assert Idempotency
			if want, err := nilErr, eng.DeleteUnusedKeys(ctx, namespace); !errors.Is(err, want) {
				t.Fatalf("expect err be %v, got: %v", want, err)
			}
		}

		// Assert picked key can't be recovered and no longer exist
		if want, err := core.ErrKeyNotFound, eng.ReEnableKey(ctx, namespace, keyIDs[1]); !errors.Is(err, want) {
			t.Fatalf("expect err be %v, got: %v", want, err)
		}
		_, missing, err = eng.GetKeys(ctx, namespace, keyIDs[1:2])
		if err != nil {
			t.Fatalf("expect err be nil, got: %v", err)
		}
		assertMissing(t, missing, core.KeyStates{keyIDs[1]: core.StateDeleted})
	}

	// Test PurgeNamespace: create keys in two namespaces, purge one, assert
	// the other is intact, purged IDs can be recreated, and purge is idempotent.
	otherNS := namespace + "-other"
	otherKeys, err := eng.GetOrCreateKeys(ctx, otherNS, keyIDs, nil)
	if err != nil {
		t.Fatalf("expect err be nil, got: %v", err)
	}
	if want, got := keyIDs, otherKeys.KeyIDs(); !keysEqual(want, got) {
		t.Fatalf("expect %v, %v be equals", want, got)
	}

	// Ensure the primary namespace has at least one active key for the purge assert.
	_, err = eng.GetOrCreateKeys(ctx, namespace, keyIDs[2:], nil)
	if err != nil {
		t.Fatalf("expect err be nil, got: %v", err)
	}

	if want, err := nilErr, eng.PurgeNamespace(ctx, namespace); !errors.Is(err, want) {
		t.Fatalf("expect err be %v, got: %v", want, err)
	}
	// Idempotent
	if want, err := nilErr, eng.PurgeNamespace(ctx, namespace); !errors.Is(err, want) {
		t.Fatalf("expect err be %v, got: %v", want, err)
	}

	keys, missing, err = eng.GetKeys(ctx, namespace, keyIDs)
	if err != nil {
		t.Fatalf("expect err be nil, got: %v", err)
	}
	assertMissing(t, missing, core.KeyStates{keyIDs[0]: core.StateUnknown, keyIDs[1]: core.StateUnknown, keyIDs[2]: core.StateUnknown})
	if want, got := empty, keys.KeyIDs(); !keysEqual(want, got) {
		t.Fatalf("expect %v, %v be equals", want, got)
	}

	// Sibling namespace untouched
	keys, missing, err = eng.GetKeys(ctx, otherNS, keyIDs)
	if err != nil {
		t.Fatalf("expect err be nil, got: %v", err)
	}
	assertMissing(t, missing, core.KeyStates{})
	if want, got := keyIDs, keys.KeyIDs(); !keysEqual(want, got) {
		t.Fatalf("expect %v, %v be equals", want, got)
	}

	// Purged key IDs may be recreated (hard delete, unlike soft DeleteKey)
	keys, err = eng.GetOrCreateKeys(ctx, namespace, keyIDs[:1], nil)
	if err != nil {
		t.Fatalf("expect err be nil, got: %v", err)
	}
	if want, got := keyIDs[:1], keys.KeyIDs(); !keysEqual(want, got) {
		t.Fatalf("expect %v, %v be equals", want, got)
	}

	// Cache engines (PE-04): once the cache no longer holds a key, DisableKey
	// and ReEnableKey still report the origin's result, and reads follow it.
	if cache, ok := eng.(core.KeyEngineCache); ok && cache.Origin() != nil {
		cacheNS := namespace + "-cache"
		id := randomID()
		if _, err := eng.GetOrCreateKeys(ctx, cacheNS, []string{id}, nil); err != nil {
			t.Fatalf("expect err be nil, got: %v", err)
		}
		if err := cache.ClearCache(ctx, cacheNS, true); err != nil {
			t.Fatalf("expect err be nil, got: %v", err)
		}
		if err := eng.DisableKey(ctx, cacheNS, id); err != nil {
			t.Fatalf("DisableKey after cache clear: expect nil, got: %v", err)
		}
		_, missing, err = eng.GetKeys(ctx, cacheNS, []string{id})
		if err != nil {
			t.Fatalf("expect err be nil, got: %v", err)
		}
		assertMissing(t, missing, core.KeyStates{id: core.StateDisabled})

		if err := cache.ClearCache(ctx, cacheNS, true); err != nil {
			t.Fatalf("expect err be nil, got: %v", err)
		}
		if err := eng.ReEnableKey(ctx, cacheNS, id); err != nil {
			t.Fatalf("ReEnableKey after cache clear: expect nil, got: %v", err)
		}
		keys, missing, err = eng.GetKeys(ctx, cacheNS, []string{id})
		if err != nil {
			t.Fatalf("expect err be nil, got: %v", err)
		}
		if want, got := []string{id}, keys.KeyIDs(); !keysEqual(want, got) {
			t.Fatalf("expect %v, %v be equals", want, got)
		}
		assertMissing(t, missing, core.KeyStates{})
	}
}

// assertMissing checks the states GetKeys reports for IDs with no active key.
func assertMissing(t *testing.T, got, want core.KeyStates) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("expect missing states %v, got %v", want, got)
	}
	for id, state := range want {
		if got[id] != state {
			t.Fatalf("expect state of %s be %s, got %s (all: %v)", id, state, got[id], got)
		}
	}
}
