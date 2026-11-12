// Package core contains the encryption logic model and service interfaces.
package core

import (
	"context"
	"errors"
	"time"
)

// Errors returned by KeyEngine implementations
var (
	ErrPersistKeyFailure  = errors.New("failed to persist encryption key(s)")
	ErrGetKeyFailure      = errors.New("failed to get encryption key(s)")
	ErrReEnableKeyFailure = errors.New("failed to renable encryption key(s)")
	ErrDisableKeyFailure  = errors.New("failed to disable encryption key")
	ErrDeleteKeyFailure   = errors.New("failed to delete encryption key")
	ErrPurgeKeyFailure    = errors.New("failed to purge encryption keys")
	ErrKeyNotFound        = errors.New("encryption key not found")
)

// Encryption key lifecycle states.
const (
	StateActive   KeyState = "ACTIVE"
	StateDisabled KeyState = "DISABLED"
	StateDeleted  KeyState = "DELETED"

	// StateUnknown is reported for a key ID the engine has no record of in the
	// namespace: never created, or removed by PurgeNamespace. It is never stored.
	StateUnknown KeyState = "UNKNOWN"
)

// KeyState presents encryption key lifecycle states
type KeyState string

// Key presents the plain text value of an encryption key.
// It is a []byte so the backing memory can be zeroed after use.
//
// Key redacts itself in fmt (every verb), log/slog, encoding/json and
// encoding text (see redact.go). Use []byte(key) where the bytes are needed.
type Key []byte

// ZeroKey overwrites the key's backing memory with zeros.
func ZeroKey(k Key) {
	for i := range k {
		k[i] = 0
	}
}

// KeyStates maps key IDs to their lifecycle state.
type KeyStates map[string]KeyState

// KeyMap presents a map of Keys indexed by keyID.
type KeyMap map[string]Key

// NewKeyMap returns a new empty KeyMap.
func NewKeyMap() KeyMap {
	return make(map[string]Key)
}

// KeyIDs returns Key IDs.
func (km KeyMap) KeyIDs() []string {
	subIDs := []string{}
	for subID := range km {
		subIDs = append(subIDs, subID)
	}
	return subIDs
}

// IDKey presents a pair to combine a Key and its ID.
type IDKey struct {
	id  string
	key Key
}

// NewIDKey returns new IdKey value of the given Key and ID.
func NewIDKey(id string, key []byte) IDKey {
	return IDKey{
		id, Key(key),
	}
}

func (ik IDKey) ID() string {
	return ik.id
}

func (ik IDKey) Key() Key {
	return ik.key
}

// KeyGen presents a function used by Key engines to generate keys
type KeyGen func(ctx context.Context, namespace, keyID string) ([]byte, error)

// KeyEngineConfig presents the basic configuration of KeyEngine
// Implementations may extend it and add specific configuration.
type KeyEngineConfig struct {
	GracePeriod time.Duration
}

// NewKeyEngineConfig returns a default KeyEngineConfig
// mainly to avoid an empty GracePeriod configuration which seems to be critical.
func NewKeyEngineConfig() KeyEngineConfig {
	return KeyEngineConfig{
		GracePeriod: 7 * 24 * time.Hour,
	}
}

// KeyEngine presents the service responsible for managing encryption keys.
type KeyEngine interface {

	// GetKeys returns the active keys for the given keyIDs within the given namespace,
	// and the state of every requested keyID that has no active key.
	//
	// Each requested keyID appears in exactly one of the two maps. missing holds
	// StateDisabled, StateDeleted or StateUnknown (no record in the namespace,
	// including after PurgeNamespace), so callers can tell a forgotten subject
	// from one that never existed. Both maps are indexed by keyID.
	//
	// Each key is a copy the caller owns and may pass to ZeroKey.
	// The engine keeps a separate copy and may zero that copy on delete, eviction, or purge.
	GetKeys(ctx context.Context, namespace string, keyIDs []string) (keys KeyMap, missing KeyStates, err error)

	// GetOrCreateKeys returns the existing keys for the given keyIDs
	// within the given namespace and creates new ones for the fresh new keyIDs.
	//
	// Note that it will not create a new key for a deleted keyID.
	// Returned keys follow the same copy rule as GetKeys.
	GetOrCreateKeys(ctx context.Context, namespace string, keyIDs []string, keyGen KeyGen) (KeyMap, error)

	// DisableKey disables the associated key of the given keyID.
	// It returns ErrKeyNotFound error if the key is already deleted.
	DisableKey(ctx context.Context, namespace, keyID string) error

	// ReEnableKey reenables the associated key of the given keyID.
	// It returns ErrKeyNotFound error if the key is already deleted.
	ReEnableKey(ctx context.Context, namespace, keyID string) error

	// DeleteKey deletes the associated key of the given keyID.
	DeleteKey(ctx context.Context, namespace, keyID string) error

	// DeleteUnusedKeys delete unused keys which were disabled
	// for longer or equal to the configured grace period.
	DeleteUnusedKeys(ctx context.Context, namespace string) error

	// PurgeNamespace hard-deletes every encryption key in the namespace
	// (active, disabled, and logically deleted). Idempotent — a second
	// call on an empty namespace is a no-op. Unlike DeleteKey, purged
	// key IDs may be recreated by a subsequent GetOrCreateKeys.
	PurgeNamespace(ctx context.Context, namespace string) error
}

// KeyEngineWrapper presents a wrapper on top of an existing Key engine.
// It overrides and enhances behaviors such as caching and
// client-side encryption of keys' values.
type KeyEngineWrapper interface {
	KeyEngine

	// Origin returns the wrapped Key engine.
	Origin() KeyEngine
}

// KeyEngineCache is a KetEngine wrapper used for cache purpose.
type KeyEngineCache interface {
	KeyEngineWrapper

	// ClearCache invalidates the cache of encryption keys based on a time-to-live configuration.
	// 'force' parameter allows to bypass the TTL check and immediately invalidates the cache.
	ClearCache(ctx context.Context, namespace string, force bool) error
}
