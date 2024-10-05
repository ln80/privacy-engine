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

	keys, err := eng.GetKeys(ctx, namespace, nil)
	if err != nil {
		t.Fatalf("expect err be nil, got: %v", err)
	}
	if len(keys) != 0 {
		t.Fatalf("expect keys map be empty, got: %v", keys)
	}

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
	keys, err = eng.GetKeys(ctx, namespace, partial)
	if err != nil {
		t.Fatalf("expect err be nil, got: %v", err)
	}
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

	keys, err = eng.GetKeys(ctx, namespace, keyIDs[0:1])
	if err != nil {
		t.Fatalf("expect err be nil, got: %v", err)
	}
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

	keys, err = eng.GetKeys(ctx, namespace, keyIDs[0:1])
	if err != nil {
		t.Fatalf("expect err be nil, got: %v", err)
	}
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
	keys, err = eng.GetKeys(ctx, namespace, keyIDs[0:1])
	if err != nil {
		t.Fatalf("expect err be nil, got: %v", err)
	}
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
	}
}
