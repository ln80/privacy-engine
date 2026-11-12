package memory

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/ln80/privacy-engine/aes"
	"github.com/ln80/privacy-engine/core"
)

const (
	cacheTTLDefault = 20 * time.Second
)

type keyCache struct {
	ID    string
	Key   core.Key
	At    int64
	State core.KeyState
}

func newKeyCache(id string, key core.Key) keyCache {
	return keyCache{
		ID:    id,
		Key:   key,
		At:    time.Now().Unix(),
		State: core.StateActive,
	}
}

// cloneKey returns a copy with its own backing array.
// Nil stays nil. Callers and the cache must not share a key slice:
// ZeroKey writes through the slice header into whatever array it points at.
func cloneKey(k core.Key) core.Key {
	return bytes.Clone(k)
}

// putCachedKey stores a key the cache owns, wiping the previous cache copy.
// Caller must hold e.mu. owned must already be a private slice.
func putCachedKey(cache map[string]keyCache, keyID string, owned core.Key) {
	if prev, ok := cache[keyID]; ok {
		core.ZeroKey(prev.Key)
	}
	cache[keyID] = newKeyCache(keyID, owned)
}

type engine struct {
	origin core.KeyEngine

	cache map[string]map[string]keyCache
	mu    sync.RWMutex

	ttl time.Duration
}

var _ core.KeyEngine = &engine{}
var _ core.KeyEngineCache = &engine{}

// NewKeyEngine returns an in-memory core.KeyEngine implementation,
// and is mainly used for tests.
func NewKeyEngine() core.KeyEngine {
	return &engine{
		cache: make(map[string]map[string]keyCache),
	}
}

// NewCacheWrapper returns an in-memory cache wrapper on top of a given core.KeyEngine.
//
// It requires time-to-live duration for caching purpose,
// and it will use a default TTL duration value if the given one is Zero.
//
// Encryption Keys are sensitive information and should not be kept in memory for a long period.
// However, caching may significantly reduce costs and network overhead.
func NewCacheWrapper(origin core.KeyEngine, ttl time.Duration) core.KeyEngine {
	if origin == nil {
		panic("invalid origin Key Engine, nil value found")
	}
	if ttl == 0 {
		ttl = cacheTTLDefault
	}

	return &engine{
		cache:  make(map[string]map[string]keyCache),
		origin: origin,
		ttl:    ttl,
	}
}

func (e *engine) cacheOf(namespace string) map[string]keyCache {
	e.mu.RLock()
	if c, ok := e.cache[namespace]; ok {
		e.mu.RUnlock()
		return c
	}
	e.mu.RUnlock()

	e.mu.Lock()
	defer e.mu.Unlock()
	if _, ok := e.cache[namespace]; !ok {
		e.cache[namespace] = make(map[string]keyCache)
	}
	return e.cache[namespace]
}

// GetKeys implements core.KeyEngine
//
// As a store, an ID with no entry is StateUnknown. As a cache, a cached
// disabled or deleted entry reports its state, and the origin decides for IDs
// not in the cache; states are passed through, never cached.
func (e *engine) GetKeys(ctx context.Context, namespace string, keyIDs []string) (core.KeyMap, core.KeyStates, error) {
	cache := e.cacheOf(namespace)

	foundKeys := core.NewKeyMap()
	missing := core.KeyStates{}
	missedKeys := []string{}

	e.mu.RLock()
	for _, keyID := range keyIDs {
		key, ok := cache[keyID]
		switch {
		case ok && key.State == core.StateActive:
			foundKeys[keyID] = cloneKey(key.Key)
		case ok:
			missing[keyID] = key.State
		case e.origin != nil:
			missedKeys = append(missedKeys, keyID)
		default:
			missing[keyID] = core.StateUnknown
		}
	}
	e.mu.RUnlock()

	if e.origin != nil && len(missedKeys) > 0 {
		keys, originMissing, err := e.origin.GetKeys(ctx, namespace, missedKeys)
		if err != nil {
			return nil, nil, err
		}
		e.mu.Lock()
		for keyID, k := range keys {
			// k may be the origin's own slice. Keep two clones and leave k untouched.
			owned := cloneKey(k)
			putCachedKey(cache, keyID, owned)
			foundKeys[keyID] = cloneKey(owned)
		}
		e.mu.Unlock()
		for keyID, state := range originMissing {
			missing[keyID] = state
		}
		// An origin that omits an ID reports nothing about it: treat it as unknown.
		for _, keyID := range missedKeys {
			if _, ok := foundKeys[keyID]; !ok {
				if _, ok := missing[keyID]; !ok {
					missing[keyID] = core.StateUnknown
				}
			}
		}
	}

	return foundKeys, missing, nil
}

// GetOrCreateKeys implements core.KeyEngine
func (e *engine) GetOrCreateKeys(ctx context.Context, namespace string, keyIDs []string, keyGen core.KeyGen) (core.KeyMap, error) {
	if keyGen == nil {
		keyGen = aes.Key256GenFn
	}

	cache := e.cacheOf(namespace)

	if e.origin != nil {
		return func() (core.KeyMap, error) {
			e.mu.Lock()
			defer e.mu.Unlock()

			keys, err := e.origin.GetOrCreateKeys(ctx, namespace, keyIDs, keyGen)
			if err != nil {
				return nil, err
			}
			out := core.NewKeyMap()
			for keyID, k := range keys {
				owned := cloneKey(k)
				putCachedKey(cache, keyID, owned)
				out[keyID] = cloneKey(owned)
			}
			return out, nil
		}()
	}

	keys, _, err := e.GetKeys(ctx, namespace, keyIDs)
	if err != nil {
		return nil, err
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	for _, keyID := range keyIDs {
		if _, ok := keys[keyID]; !ok {
			// only add new entry if key is a fresh new one.
			// it may be disabled/deleted and still have record
			if _, ok := cache[keyID]; ok {
				continue
			}

			newKey, err := keyGen(ctx, namespace, keyID)
			if err != nil {
				return nil, errors.Join(core.ErrPersistKeyFailure, err)
			}
			k := core.Key(newKey)
			putCachedKey(cache, keyID, cloneKey(k))
			keys[keyID] = cloneKey(k)
			core.ZeroKey(k)
		}
	}

	return keys, nil
}

// invalidate drops a cached entry and wipes its key. Used by the cache after
// the origin changed a key's state: the origin is the source of truth, and the
// next read refetches it. Dropping a disabled key also stops keeping it in memory.
func (e *engine) invalidate(namespace, keyID string) {
	cache := e.cacheOf(namespace)

	e.mu.Lock()
	defer e.mu.Unlock()
	if k, ok := cache[keyID]; ok {
		core.ZeroKey(k.Key)
		delete(cache, keyID)
	}
}

// DisableKey implements core.KeyEngine
//
// As a cache, the result is the origin's: once the origin succeeds, the cached
// entry, present or not, cannot turn that success into an error (PE-04).
func (e *engine) DisableKey(ctx context.Context, namespace, keyID string) error {
	if e.origin != nil {
		if err := e.origin.DisableKey(ctx, namespace, keyID); err != nil {
			// There is no need to wrap error; origin is also an infra adapter
			// and supposed not to propagate infra error
			return err
		}
		e.invalidate(namespace, keyID)
		return nil
	}

	cache := e.cacheOf(namespace)

	e.mu.Lock()
	defer e.mu.Unlock()

	keyCache, ok := cache[keyID]
	if !ok {
		return core.ErrKeyNotFound
	}

	if keyCache.State == core.StateDeleted {
		return fmt.Errorf("%w: hard deleted key", core.ErrKeyNotFound)
	}

	keyCache.State = core.StateDisabled
	cache[keyID] = keyCache

	return nil
}

// ReEnableKey implements core.KeyEngine
//
// As a cache, the result is the origin's, as for DisableKey.
func (e *engine) ReEnableKey(ctx context.Context, namespace, keyID string) error {
	if e.origin != nil {
		if err := e.origin.ReEnableKey(ctx, namespace, keyID); err != nil {
			return err
		}
		e.invalidate(namespace, keyID)
		return nil
	}

	cache := e.cacheOf(namespace)

	e.mu.Lock()
	defer e.mu.Unlock()

	keyCache, ok := cache[keyID]
	if !ok {
		return core.ErrKeyNotFound
	}

	if keyCache.State == core.StateDeleted {
		return fmt.Errorf("%w: hard deleted key", core.ErrKeyNotFound)
	}

	keyCache.State = core.StateActive
	cache[keyID] = keyCache

	return nil
}

// DeleteKey implements core.KeyEngine
func (e *engine) DeleteKey(ctx context.Context, namespace, keyID string) error {
	if e.origin != nil {
		if err := e.origin.DeleteKey(ctx, namespace, keyID); err != nil {
			return err
		}
	}

	cache := e.cacheOf(namespace)

	e.mu.Lock()
	defer e.mu.Unlock()

	keyCache, ok := cache[keyID]
	if !ok {
		return nil
	}

	core.ZeroKey(keyCache.Key)
	keyCache.Key = nil
	keyCache.State = core.StateDeleted
	cache[keyID] = keyCache

	return nil
}

// DeleteKey implements core.KeyEngineCache
func (e *engine) ClearCache(ctx context.Context, namespace string, force bool) error {
	// if origin is empty then the engine acts as a store aka basic key engine.
	// therefore silently ignore clear cache operation.
	if e.origin == nil {
		return nil
	}

	cache := e.cacheOf(namespace)

	e.mu.Lock()
	defer e.mu.Unlock()

	if len(cache) == 0 {
		return nil
	}

	for keyID, k := range cache {
		if expired := k.At+int64(e.ttl.Seconds()) < time.Now().Unix(); expired || force {
			core.ZeroKey(k.Key)
			delete(cache, keyID)
		}
	}

	return nil
}

// DeleteUnusedKeys implements core.KeyEngine
func (e *engine) DeleteUnusedKeys(ctx context.Context, namespace string) error {
	if e.origin != nil {
		return e.origin.DeleteUnusedKeys(ctx, namespace)
	}
	return nil
}

// PurgeNamespace implements core.KeyEngine
func (e *engine) PurgeNamespace(ctx context.Context, namespace string) error {
	if e.origin != nil {
		if err := e.origin.PurgeNamespace(ctx, namespace); err != nil {
			return err
		}
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	cache, ok := e.cache[namespace]
	if !ok {
		return nil
	}
	for keyID, k := range cache {
		core.ZeroKey(k.Key)
		delete(cache, keyID)
	}
	delete(e.cache, namespace)
	return nil
}

// Origin implements core.KeyEngineCache
func (e *engine) Origin() core.KeyEngine {
	return e.origin
}
