package privacytest

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/ln80/privacy-engine/core"
)

// KeyEngineTestConfig configures TestKeyEngine.
type KeyEngineTestConfig struct {
	// GracePeriod is the engine's grace period. Keep it short (seconds): the
	// suite waits for it. Zero skips R-KE-6, R-KE-11 and the janitor part of
	// R-KE-7.
	GracePeriod time.Duration

	// ErasesWithoutJanitor declares an engine that removes keys past the
	// grace period by itself, for example through a storage TTL. The suite
	// then never runs the janitor, and does not probe for material after the
	// grace period: a TTL removes it later.
	ErasesWithoutJanitor bool

	// Janitor completes erasure after the grace period. It defaults to the
	// engine's DeleteUnusedKeys; set it to trigger your scheduled job instead.
	Janitor func(ctx context.Context, namespace string) error

	// KeyMaterialProbe reads the backend's storage directly, bypassing the
	// engine, and reports whether key material is still stored for keyID.
	// Without it R-KE-7 is skipped.
	KeyMaterialProbe func(ctx context.Context, namespace, keyID string) (stored bool, err error)

	// Namespace prefixes the namespaces the suite creates, one per subtest.
	// Default "privacytest".
	Namespace string
}

// TestKeyEngine is the conformance suite of core.KeyEngine. It runs one
// subtest per requirement of docs/implementing-backends.md, named after its
// ID (run one with -run 'TestX/R-KE-3'), each in a namespace of its own.
//
// Run it against real storage, or an emulator, for every composition you
// deploy: the store alone, and a wrapper over the store.
func TestKeyEngine(t *testing.T, eng core.KeyEngine, opts ...func(*KeyEngineTestConfig)) {
	t.Helper()
	cfg := &KeyEngineTestConfig{}
	for _, opt := range opts {
		if opt != nil {
			opt(cfg)
		}
	}
	if cfg.Namespace == "" {
		cfg.Namespace = "privacytest"
	}
	if cfg.Janitor == nil {
		cfg.Janitor = eng.DeleteUnusedKeys
	}
	run := func(name string, f func(k *keyCheck)) {
		t.Helper()
		t.Run(name, func(t *testing.T) {
			f(&keyCheck{t: t, ctx: t.Context(), eng: eng, cfg: cfg, ns: newNamespace(cfg.Namespace)})
		})
	}

	run("R-KE-1 GetKeys reports each ID once, as a key or a state", func(k *keyCheck) {
		a, b, c, d := randomID(), randomID(), randomID(), randomID()
		k.create(a, b, c)
		k.must(k.eng.DisableKey(k.ctx, k.ns, b), "DisableKey")
		k.must(k.eng.DeleteKey(k.ctx, k.ns, c), "DeleteKey")

		k.expect(nil, nil)
		keys := k.expect([]string{a}, core.KeyStates{b: core.StateDisabled, c: core.StateDeleted, d: core.StateUnknown}, a, b, c, d)

		// Returned keys are copies the caller may zero.
		orig := bytes.Clone(keys[a])
		core.ZeroKey(keys[a])
		if again := k.expect([]string{a}, nil, a); !bytes.Equal(again[a], orig) {
			k.t.Fatal("zeroing a returned key changed the stored one")
		}
	})

	run("R-KE-2 an ID without a record is UNKNOWN and stays so", func(k *keyCheck) {
		id := randomID()
		k.expect(nil, core.KeyStates{id: core.StateUnknown}, id)
		k.notFound(k.eng.DisableKey(k.ctx, k.ns, id), "DisableKey of an unknown ID")
		k.notFound(k.eng.ReEnableKey(k.ctx, k.ns, id), "ReEnableKey of an unknown ID")
		k.expect(nil, core.KeyStates{id: core.StateUnknown}, id)
	})

	run("R-KE-3 GetOrCreateKeys creates a key once, also concurrently", func(k *keyCheck) {
		a, b, c := randomID(), randomID(), randomID()
		first := k.create(a)
		second := k.create(a, b)
		if len(second) != 2 || !bytes.Equal(first[a], second[a]) {
			k.t.Fatalf("expect the existing key of %s returned with a new one for %s", a, b)
		}
		stored := k.expect([]string{a, b}, nil, a, b)
		if !bytes.Equal(stored[b], second[b]) {
			k.t.Fatal("GetKeys returns another key than GetOrCreateKeys created")
		}

		// Concurrent creations of one ID all return the key that was stored.
		const callers = 16
		got := make([]core.Key, callers)
		errs := make([]error, callers)
		var wg sync.WaitGroup
		for i := range callers {
			wg.Go(func() {
				keys, err := k.eng.GetOrCreateKeys(k.ctx, k.ns, []string{c}, randomKeyGen)
				got[i], errs[i] = keys[c], err
			})
		}
		wg.Wait()
		final := k.expect([]string{c}, nil, c)
		for i := range callers {
			k.must(errs[i], "concurrent GetOrCreateKeys")
			if !bytes.Equal(got[i], final[c]) {
				k.t.Fatalf("concurrent caller %d got a key that was not stored", i)
			}
		}
	})

	run("R-KE-4 GetOrCreateKeys never recreates a forgotten key", func(k *keyCheck) {
		a, b, c := randomID(), randomID(), randomID()
		k.create(a, b)
		k.must(k.eng.DisableKey(k.ctx, k.ns, a), "DisableKey")
		k.must(k.eng.DeleteKey(k.ctx, k.ns, b), "DeleteKey")
		keys, err := k.eng.GetOrCreateKeys(k.ctx, k.ns, []string{a, b, c}, nil)
		k.must(err, "GetOrCreateKeys")
		if want, got := []string{c}, keys.KeyIDs(); !keysEqual(want, got) {
			k.t.Fatalf("expect keys for %v only, got %v", want, got)
		}
		k.expect([]string{c}, core.KeyStates{a: core.StateDisabled, b: core.StateDeleted}, a, b, c)
	})

	run("R-KE-5 DisableKey and ReEnableKey follow the key's state", func(k *keyCheck) {
		a := randomID()
		orig := k.create(a)
		for range 2 {
			k.must(k.eng.DisableKey(k.ctx, k.ns, a), "DisableKey")
		}
		k.expect(nil, core.KeyStates{a: core.StateDisabled}, a)
		for range 2 {
			k.must(k.eng.ReEnableKey(k.ctx, k.ns, a), "ReEnableKey")
		}
		if keys := k.expect([]string{a}, nil, a); !bytes.Equal(keys[a], orig[a]) {
			k.t.Fatal("ReEnableKey restored another key")
		}

		for range 2 {
			k.must(k.eng.DeleteKey(k.ctx, k.ns, a), "DeleteKey")
		}
		k.notFound(k.eng.DisableKey(k.ctx, k.ns, a), "DisableKey of a deleted key")
		k.notFound(k.eng.ReEnableKey(k.ctx, k.ns, a), "ReEnableKey of a deleted key")
		k.expect(nil, core.KeyStates{a: core.StateDeleted}, a)
	})

	run("R-KE-6 a key disabled past the grace period reads DELETED", func(k *keyCheck) {
		g := k.cfg.GracePeriod
		if g == 0 {
			k.t.Skip("set GracePeriod to check it")
		}
		a := randomID()
		k.create(a)
		k.must(k.eng.DisableKey(k.ctx, k.ns, a), "DisableKey")
		time.Sleep(g / 2)
		// A second disable must not restart the period.
		k.must(k.eng.DisableKey(k.ctx, k.ns, a), "DisableKey again")
		time.Sleep(g/2 + margin(g))

		// No janitor ran: the deadline is enforced on read.
		k.expect(nil, core.KeyStates{a: core.StateDeleted}, a)
		k.notFound(k.eng.ReEnableKey(k.ctx, k.ns, a), "ReEnableKey past the grace period")
		keys, err := k.eng.GetOrCreateKeys(k.ctx, k.ns, []string{a}, nil)
		k.must(err, "GetOrCreateKeys")
		if len(keys) != 0 {
			k.t.Fatal("GetOrCreateKeys recreated a key past the grace period")
		}
	})

	run("R-KE-7 deletion removes key material", func(k *keyCheck) {
		if k.cfg.KeyMaterialProbe == nil {
			k.t.Skip("set KeyMaterialProbe to check it")
		}
		a, b, c := randomID(), randomID(), randomID()
		k.create(a, b, c)

		k.must(k.eng.DeleteKey(k.ctx, k.ns, a), "DeleteKey")
		k.expect(nil, core.KeyStates{a: core.StateDeleted}, a)
		k.noMaterial(a, "DeleteKey")

		if g := k.cfg.GracePeriod; g > 0 && !k.cfg.ErasesWithoutJanitor {
			k.must(k.eng.DisableKey(k.ctx, k.ns, b), "DisableKey")
			time.Sleep(g + margin(g))
			for range 2 {
				k.must(k.cfg.Janitor(k.ctx, k.ns), "janitor")
			}
			k.expect(nil, core.KeyStates{b: core.StateDeleted}, b)
			k.noMaterial(b, "the janitor")
		}

		k.must(k.eng.PurgeNamespace(k.ctx, k.ns), "PurgeNamespace")
		for _, id := range []string{a, b, c} {
			k.noMaterial(id, "PurgeNamespace")
		}
	})

	run("R-KE-8 PurgeNamespace removes every record", func(k *keyCheck) {
		a, b, c := randomID(), randomID(), randomID()
		before := k.create(a, b, c)
		k.must(k.eng.DisableKey(k.ctx, k.ns, b), "DisableKey")
		k.must(k.eng.DeleteKey(k.ctx, k.ns, c), "DeleteKey")

		for range 2 {
			k.must(k.eng.PurgeNamespace(k.ctx, k.ns), "PurgeNamespace")
		}
		k.expect(nil, core.KeyStates{a: core.StateUnknown, b: core.StateUnknown, c: core.StateUnknown}, a, b, c)

		after := k.create(a, b, c)
		for _, id := range []string{a, b, c} {
			if bytes.Equal(after[id], before[id]) {
				k.t.Fatalf("a key recreated after the purge equals the purged one")
			}
		}
	})

	run("R-KE-9 DeleteKey of an unknown ID writes nothing", func(k *keyCheck) {
		id := randomID()
		k.must(k.eng.DeleteKey(k.ctx, k.ns, id), "DeleteKey of an unknown ID")
		k.expect(nil, core.KeyStates{id: core.StateUnknown}, id)
		k.must(k.eng.PurgeNamespace(k.ctx, newNamespace(k.cfg.Namespace)), "PurgeNamespace of an empty namespace")
	})

	run("R-KE-10 namespaces are isolated", func(k *keyCheck) {
		a := randomID()
		other := k.in(newNamespace(k.cfg.Namespace))
		mine, theirs := k.create(a), other.create(a)
		if bytes.Equal(mine[a], theirs[a]) {
			k.t.Fatal("one key ID in two namespaces got the same key")
		}
		k.must(k.eng.DisableKey(k.ctx, k.ns, a), "DisableKey")
		other.expect([]string{a}, nil, a)
		k.must(k.eng.PurgeNamespace(k.ctx, k.ns), "PurgeNamespace")
		if got := other.expect([]string{a}, nil, a); !bytes.Equal(got[a], theirs[a]) {
			k.t.Fatal("a purge changed another namespace")
		}
	})

	run("R-KE-11 the engine reports its grace period", func(k *keyCheck) {
		if k.cfg.GracePeriod == 0 {
			k.t.Skip("set GracePeriod to check it")
		}
		if got := core.GracePeriodOf(k.eng); got != k.cfg.GracePeriod {
			k.t.Fatalf("core.GracePeriodOf: expect %v, got %v", k.cfg.GracePeriod, got)
		}
	})

	if cache, ok := eng.(core.KeyEngineCache); ok && cache.Origin() != nil {
		run("cache follows its origin after ClearCache", func(k *keyCheck) {
			id := randomID()
			k.create(id)
			k.must(cache.ClearCache(k.ctx, k.ns, true), "ClearCache")
			k.must(k.eng.DisableKey(k.ctx, k.ns, id), "DisableKey after ClearCache")
			k.expect(nil, core.KeyStates{id: core.StateDisabled}, id)
			k.must(cache.ClearCache(k.ctx, k.ns, true), "ClearCache")
			k.must(k.eng.ReEnableKey(k.ctx, k.ns, id), "ReEnableKey after ClearCache")
			k.expect([]string{id}, nil, id)
		})
	}
}

type keyCheck struct {
	t   *testing.T
	ctx context.Context
	eng core.KeyEngine
	cfg *KeyEngineTestConfig
	ns  string
}

// in returns a check on another namespace.
func (k *keyCheck) in(ns string) *keyCheck {
	c := *k
	c.ns = ns
	return &c
}

func (k *keyCheck) must(err error, what string) {
	k.t.Helper()
	if err != nil {
		k.t.Fatalf("%s: %v", what, err)
	}
}

func (k *keyCheck) notFound(err error, what string) {
	k.t.Helper()
	if !errors.Is(err, core.ErrKeyNotFound) {
		k.t.Fatalf("%s: expect core.ErrKeyNotFound, got %v", what, err)
	}
}

func (k *keyCheck) create(ids ...string) core.KeyMap {
	k.t.Helper()
	keys, err := k.eng.GetOrCreateKeys(k.ctx, k.ns, ids, nil)
	k.must(err, "GetOrCreateKeys")
	if !keysEqual(ids, keys.KeyIDs()) {
		k.t.Fatalf("GetOrCreateKeys: expect keys for %v, got %v", ids, keys.KeyIDs())
	}
	return keys
}

// expect reads ids and checks which are active and the states of the others.
func (k *keyCheck) expect(active []string, missing core.KeyStates, ids ...string) core.KeyMap {
	k.t.Helper()
	keys, gotMissing, err := k.eng.GetKeys(k.ctx, k.ns, ids)
	k.must(err, "GetKeys")
	if active == nil {
		active = []string{}
	}
	if got := keys.KeyIDs(); !keysEqual(active, got) {
		k.t.Fatalf("GetKeys: expect keys for %v, got %v (missing %v)", active, got, gotMissing)
	}
	if len(gotMissing) != len(missing) {
		k.t.Fatalf("GetKeys: expect missing %v, got %v", missing, gotMissing)
	}
	for id, state := range missing {
		if gotMissing[id] != state {
			k.t.Fatalf("GetKeys: expect %s for %s, got %q", state, id, gotMissing[id])
		}
	}
	return keys
}

func (k *keyCheck) noMaterial(keyID, after string) {
	k.t.Helper()
	stored, err := k.cfg.KeyMaterialProbe(k.ctx, k.ns, keyID)
	k.must(err, "KeyMaterialProbe")
	if stored {
		k.t.Fatalf("key material of %s is still stored after %s", keyID, after)
	}
}
