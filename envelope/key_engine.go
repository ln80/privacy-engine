// Package envelope turns a core.KeyWrapper and a key store into a
// core.KeyEngine: the store holds wrapped data keys, the wrapper's KMS or HSM
// holds the key that unwraps them.
package envelope

import (
	"bytes"
	"context"
	"fmt"

	"github.com/ln80/privacy-engine/core"
)

const dataKeySize = 32

// KeyEngine stores data keys wrapped by a core.KeyWrapper. It implements
// core.KeyEngineWrapper; its Origin is the store.
type KeyEngine struct {
	wrapper core.KeyWrapper
	store   core.KeyEngine
}

var _ core.KeyEngineWrapper = (*KeyEngine)(nil)

// NewKeyEngine returns a key engine that generates data keys with wrapper,
// stores them wrapped in store, and unwraps them on every read. Put a cache
// in front (the Protector adds one) to limit calls to the KMS.
func NewKeyEngine(wrapper core.KeyWrapper, store core.KeyEngine) *KeyEngine {
	if wrapper == nil || store == nil {
		panic("envelope: nil key wrapper or key store")
	}
	return &KeyEngine{wrapper: wrapper, store: store}
}

// Origin implements core.KeyEngineWrapper.
func (e *KeyEngine) Origin() core.KeyEngine { return e.store }

// GetKeys implements core.KeyEngine. It unwraps the store's active keys and
// passes its states for the others through.
func (e *KeyEngine) GetKeys(ctx context.Context, namespace string, keyIDs []string) (core.KeyMap, core.KeyStates, error) {
	blobs, missing, err := e.store.GetKeys(ctx, namespace, keyIDs)
	if err != nil {
		return nil, nil, err
	}
	keys, err := e.unwrap(ctx, namespace, blobs, nil)
	if err != nil {
		return nil, nil, err
	}
	return keys, missing, nil
}

// GetOrCreateKeys implements core.KeyEngine. New data keys come from the
// wrapper; the keyGen argument is not used.
//
// When several processes create one key at once, the store keeps one blob.
// A process uses the data key it generated only if the store returns its own
// blob; otherwise it unwraps the stored one (R-KW-6). Using its own would
// encrypt data under a key nobody can find again.
func (e *KeyEngine) GetOrCreateKeys(ctx context.Context, namespace string, keyIDs []string, _ core.KeyGen) (core.KeyMap, error) {
	type generated struct {
		plain core.Key
		blob  []byte
	}
	gen := map[string]generated{}
	defer func() {
		for _, g := range gen {
			core.ZeroKey(g.plain)
		}
	}()

	keyGen := func(ctx context.Context, namespace, keyID string) ([]byte, error) {
		plain, wrapped, err := e.wrapper.GenerateKey(ctx, namespace, keyID)
		if err != nil {
			return nil, err
		}
		if len(plain) != dataKeySize {
			core.ZeroKey(plain)
			return nil, fmt.Errorf("key wrapper generated a %d-byte data key, want %d", len(plain), dataKeySize)
		}
		if prev, ok := gen[keyID]; ok {
			core.ZeroKey(prev.plain)
		}
		// Keep our own copy of the blob: the store may wipe the slice it is
		// given once stored.
		gen[keyID] = generated{plain: plain, blob: bytes.Clone(wrapped)}
		return wrapped, nil
	}

	blobs, err := e.store.GetOrCreateKeys(ctx, namespace, keyIDs, keyGen)
	if err != nil {
		return nil, err
	}
	return e.unwrap(ctx, namespace, blobs, func(keyID string, blob []byte) core.Key {
		if g, ok := gen[keyID]; ok && bytes.Equal(g.blob, blob) {
			return core.Key(bytes.Clone(g.plain))
		}
		return nil
	})
}

// unwrap returns the data keys of blobs. own, when set, may supply a key
// without a call to the wrapper. On error every key returned so far is zeroed.
func (e *KeyEngine) unwrap(ctx context.Context, namespace string, blobs core.KeyMap, own func(string, []byte) core.Key) (core.KeyMap, error) {
	keys := core.NewKeyMap()
	for keyID, blob := range blobs {
		if own != nil {
			if k := own(keyID, blob); k != nil {
				keys[keyID] = k
				continue
			}
		}
		k, err := e.wrapper.UnwrapKey(ctx, namespace, keyID, blob)
		if err == nil && len(k) != dataKeySize {
			core.ZeroKey(k)
			err = fmt.Errorf("key wrapper unwrapped a %d-byte data key, want %d", len(k), dataKeySize)
		}
		if err != nil {
			for _, k := range keys {
				core.ZeroKey(k)
			}
			return nil, fmt.Errorf("%w: %w", core.ErrGetKeyFailure, err)
		}
		keys[keyID] = k
	}
	return keys, nil
}

// DisableKey implements core.KeyEngine.
func (e *KeyEngine) DisableKey(ctx context.Context, namespace, keyID string) error {
	return e.store.DisableKey(ctx, namespace, keyID)
}

// ReEnableKey implements core.KeyEngine.
func (e *KeyEngine) ReEnableKey(ctx context.Context, namespace, keyID string) error {
	return e.store.ReEnableKey(ctx, namespace, keyID)
}

// DeleteKey implements core.KeyEngine.
func (e *KeyEngine) DeleteKey(ctx context.Context, namespace, keyID string) error {
	return e.store.DeleteKey(ctx, namespace, keyID)
}

// DeleteUnusedKeys implements core.KeyEngine.
func (e *KeyEngine) DeleteUnusedKeys(ctx context.Context, namespace string) error {
	return e.store.DeleteUnusedKeys(ctx, namespace)
}

// PurgeNamespace implements core.KeyEngine.
func (e *KeyEngine) PurgeNamespace(ctx context.Context, namespace string) error {
	return e.store.PurgeNamespace(ctx, namespace)
}
