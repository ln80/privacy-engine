package memory

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/ln80/privacy-engine/core"
)

const wrapLabel = "privacy-engine/memory-wrap/v1"

var errWrappedKey = errors.New("wrapped key does not authenticate for this namespace and key ID")

// KeyWrapper is a core.KeyWrapper whose key encryption key lives in process
// memory: data keys are sealed with AES-256-GCM, bound to their namespace and
// key ID. It is for tests and examples. Its KEK dies with the process, and so
// does every key it wrapped. In production, use a KMS or an HSM.
type KeyWrapper struct {
	kek cipher.AEAD
}

var _ core.KeyWrapper = (*KeyWrapper)(nil)

// NewKeyWrapper returns a KeyWrapper with a random key encryption key.
func NewKeyWrapper() *KeyWrapper {
	kek := make([]byte, 32)
	if _, err := rand.Read(kek); err != nil {
		panic(err)
	}
	block, err := aes.NewCipher(kek)
	if err != nil {
		panic(err)
	}
	core.ZeroKey(kek)
	aead, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}
	return &KeyWrapper{kek: aead}
}

// GenerateKey implements core.KeyWrapper.
func (w *KeyWrapper) GenerateKey(_ context.Context, namespace, keyID string) (core.Key, []byte, error) {
	aad, err := wrapAAD(namespace, keyID)
	if err != nil {
		return nil, nil, err
	}
	plain := make([]byte, 32)
	nonce := make([]byte, w.kek.NonceSize())
	if _, err := rand.Read(plain); err != nil {
		return nil, nil, err
	}
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, err
	}
	return plain, w.kek.Seal(nonce, nonce, plain, aad), nil
}

// UnwrapKey implements core.KeyWrapper.
func (w *KeyWrapper) UnwrapKey(_ context.Context, namespace, keyID string, wrapped []byte) (core.Key, error) {
	aad, err := wrapAAD(namespace, keyID)
	if err != nil {
		return nil, err
	}
	n := w.kek.NonceSize()
	if len(wrapped) < n+w.kek.Overhead() {
		return nil, errWrappedKey
	}
	plain, err := w.kek.Open(nil, wrapped[:n], wrapped[n:], aad)
	if err != nil {
		return nil, errWrappedKey
	}
	return plain, nil
}

// wrapAAD binds a wrapped key to its namespace and key ID, length-prefixed so
// no two pairs encode alike.
func wrapAAD(namespace, keyID string) ([]byte, error) {
	if len(namespace) > 0xFFFF || len(keyID) > 0xFFFF {
		return nil, fmt.Errorf("namespace or key ID longer than %d bytes", 0xFFFF)
	}
	aad := make([]byte, 0, len(wrapLabel)+4+len(namespace)+len(keyID))
	aad = append(aad, wrapLabel...)
	aad = binary.BigEndian.AppendUint16(aad, uint16(len(namespace)))
	aad = append(aad, namespace...)
	aad = binary.BigEndian.AppendUint16(aad, uint16(len(keyID)))
	return append(aad, keyID...), nil
}
