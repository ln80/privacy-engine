package envelope_test

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ln80/privacy-engine/core"
	"github.com/ln80/privacy-engine/envelope"
	"github.com/ln80/privacy-engine/memory"
	"github.com/ln80/privacy-engine/privacytest"
)

func TestKeyEngineConformance(t *testing.T) {
	const grace = 200 * time.Millisecond
	newEngine := func() core.KeyEngine {
		return envelope.NewKeyEngine(memory.NewKeyWrapper(), memory.NewKeyEngine(memory.WithGracePeriod(grace)))
	}
	t.Run("envelope over store", func(t *testing.T) {
		privacytest.TestKeyEngine(t, newEngine(), func(c *privacytest.KeyEngineTestConfig) {
			c.GracePeriod = grace
		})
	})
	t.Run("cache over envelope over store", func(t *testing.T) {
		privacytest.TestKeyEngine(t, memory.NewCacheWrapper(newEngine(), time.Minute), func(c *privacytest.KeyEngineTestConfig) {
			c.GracePeriod = grace
		})
	})
}

func TestKeyEngineStoresWrappedKeysOnly(t *testing.T) {
	ctx := t.Context()
	store := memory.NewKeyEngine()
	eng := envelope.NewKeyEngine(memory.NewKeyWrapper(), store)

	keys, err := eng.GetOrCreateKeys(ctx, "ns", []string{"a"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	stored, _, err := store.GetKeys(ctx, "ns", []string{"a"})
	if err != nil {
		t.Fatal(err)
	}
	if len(keys["a"]) != 32 || bytes.Contains(stored["a"], keys["a"]) {
		t.Fatal("expect a 32-byte data key, stored only in wrapped form")
	}
}

// losingStore creates keys as a store that lost a concurrent creation: it
// calls keyGen, as a conditional write would, then returns the winner's blob.
type losingStore struct {
	core.KeyEngine
	winner []byte
}

func (s *losingStore) GetOrCreateKeys(ctx context.Context, ns string, keyIDs []string, keyGen core.KeyGen) (core.KeyMap, error) {
	keys := core.NewKeyMap()
	for _, id := range keyIDs {
		if _, err := keyGen(ctx, ns, id); err != nil {
			return nil, err
		}
		keys[id] = bytes.Clone(s.winner)
	}
	return keys, nil
}

// R-KW-6: the loser of a concurrent creation uses the stored key, not the
// one it generated.
func TestKeyEngineLosingCreationUsesStoredKey(t *testing.T) {
	ctx := t.Context()
	w := memory.NewKeyWrapper()
	winnerKey, winnerBlob, err := w.GenerateKey(ctx, "ns", "a")
	if err != nil {
		t.Fatal(err)
	}
	eng := envelope.NewKeyEngine(w, &losingStore{KeyEngine: memory.NewKeyEngine(), winner: winnerBlob})

	keys, err := eng.GetOrCreateKeys(ctx, "ns", []string{"a"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(keys["a"], winnerKey) {
		t.Fatal("expect the stored key, got the one this process generated")
	}
}

type badWrapper struct {
	core.KeyWrapper
	size      int
	unwrapErr error
}

func (w badWrapper) GenerateKey(context.Context, string, string) (core.Key, []byte, error) {
	return make(core.Key, w.size), []byte("blob"), nil
}

func (w badWrapper) UnwrapKey(context.Context, string, string, []byte) (core.Key, error) {
	if w.unwrapErr != nil {
		return nil, w.unwrapErr
	}
	return make(core.Key, w.size), nil
}

func TestKeyEngineRefusesBadWrappers(t *testing.T) {
	ctx := t.Context()

	short := envelope.NewKeyEngine(badWrapper{size: 16}, memory.NewKeyEngine())
	if _, err := short.GetOrCreateKeys(ctx, "ns", []string{"a"}, nil); err == nil {
		t.Fatal("expect a 16-byte data key refused")
	}

	store := memory.NewKeyEngine()
	if _, err := envelope.NewKeyEngine(badWrapper{size: 32}, store).GetOrCreateKeys(ctx, "ns", []string{"a", "b"}, nil); err != nil {
		t.Fatal(err)
	}
	failing := envelope.NewKeyEngine(badWrapper{unwrapErr: errors.New("kms down")}, store)
	keys, missing, err := failing.GetKeys(ctx, "ns", []string{"a", "b"})
	if !errors.Is(err, core.ErrGetKeyFailure) || keys != nil || missing != nil {
		t.Fatalf("expect core.ErrGetKeyFailure and no keys, got %v, %v, %v", keys, missing, err)
	}
}
