package core

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
)

// KeyWrapper protects data keys with a key encryption key (KEK) held in a KMS
// or an HSM: envelope encryption. The key store then holds wrapped keys only,
// and reading it is not enough to decrypt anything.
//
// The KEK must be symmetric (R-KW-7): with a public-key KEK, anyone holding
// the public key and write access to the key store could plant a data key of
// their choosing.
//
// envelope.NewKeyEngine combines a KeyWrapper with a key store into a
// KeyEngine; privacytest.TestKeyWrapper checks an implementation. The
// requirements (R-KW) are in docs/implementing-backends.md.
type KeyWrapper interface {
	// GenerateKey returns a new 32-byte data key and its wrapped form, bound
	// to namespace and keyID. The caller owns plain and may zero it.
	GenerateKey(ctx context.Context, namespace, keyID string) (plain Key, wrapped []byte, err error)

	// UnwrapKey returns the data key of wrapped. It fails unless wrapped was
	// generated for the same namespace and keyID, and was not altered.
	UnwrapKey(ctx context.Context, namespace, keyID string, wrapped []byte) (Key, error)
}

// ErrKeyBinding is returned by UnbindDataKey when a payload was not bound to
// the given namespace and key ID, or is malformed.
var ErrKeyBinding = errors.New("data key is not bound to this namespace and key ID")

const (
	bindingVersion = 0x01
	bindingLabel   = "privacy-engine/key-binding/v1"
	bindingDigest  = 31 // bytes of SHA-256 kept, so that the payload is 64 bytes
	dataKeySize    = 32

	// BoundDataKeySize is the size of a BindDataKey payload: a multiple of 8
	// bytes, as AES key wrap (RFC 3394) requires.
	BoundDataKeySize = 1 + bindingDigest + dataKeySize
)

// BindDataKey returns the payload a KeyWrapper wraps when its KMS's wrap
// operation takes no associated data, such as AES key wrap (R-KW-1):
//
//	version (1) = 0x01 | SHA-256(label | len16(namespace) | namespace | len16(keyID) | keyID)[:31] | dek (32)
//
// Wrap the payload instead of the data key, with an authenticated mode (AES
// key wrap, AES-GCM), and open it on unwrap with UnbindDataKey. The payload
// holds the data key: zero it once wrapped.
func BindDataKey(dek Key, namespace, keyID string) ([]byte, error) {
	if len(dek) != dataKeySize {
		return nil, fmt.Errorf("data key is %d bytes, want %d", len(dek), dataKeySize)
	}
	digest, err := bindingDigestOf(namespace, keyID)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, BoundDataKeySize)
	out = append(out, bindingVersion)
	out = append(out, digest[:bindingDigest]...)
	return append(out, dek...), nil
}

// UnbindDataKey checks that payload, produced by BindDataKey and unwrapped by
// the KMS, was bound to namespace and keyID, and returns a copy of its data
// key. It returns ErrKeyBinding otherwise.
func UnbindDataKey(payload []byte, namespace, keyID string) (Key, error) {
	if len(payload) != BoundDataKeySize || payload[0] != bindingVersion {
		return nil, ErrKeyBinding
	}
	digest, err := bindingDigestOf(namespace, keyID)
	if err != nil {
		return nil, err
	}
	if subtle.ConstantTimeCompare(payload[1:1+bindingDigest], digest[:bindingDigest]) != 1 {
		return nil, ErrKeyBinding
	}
	return Key(bytes.Clone(payload[1+bindingDigest:])), nil
}

// bindingDigestOf hashes the binding, length-prefixed so that no two
// (namespace, keyID) pairs encode alike.
func bindingDigestOf(namespace, keyID string) ([sha256.Size]byte, error) {
	if len(namespace) > 0xFFFF || len(keyID) > 0xFFFF {
		return [sha256.Size]byte{}, fmt.Errorf("namespace or key ID longer than %d bytes", 0xFFFF)
	}
	b := make([]byte, 0, len(bindingLabel)+4+len(namespace)+len(keyID))
	b = append(b, bindingLabel...)
	b = binary.BigEndian.AppendUint16(b, uint16(len(namespace))) // #nosec G115 -- bounded above
	b = append(b, namespace...)
	b = binary.BigEndian.AppendUint16(b, uint16(len(keyID))) // #nosec G115 -- bounded above
	b = append(b, keyID...)
	return sha256.Sum256(b), nil
}
