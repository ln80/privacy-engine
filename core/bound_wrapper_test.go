package core_test

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"testing"

	"github.com/ln80/privacy-engine/core"
	"github.com/ln80/privacy-engine/envelope"
	"github.com/ln80/privacy-engine/memory"
	"github.com/ln80/privacy-engine/privacytest"
)

// noAADWrapper stands for a KMS whose wrap operation takes no associated
// data: it seals with AES-GCM and an empty AAD. Binding comes from
// BindDataKey alone.
type noAADWrapper struct{ kek cipher.AEAD }

func newNoAADWrapper(t *testing.T) *noAADWrapper {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	return &noAADWrapper{kek: aead}
}

func (w *noAADWrapper) GenerateKey(_ context.Context, ns, keyID string) (core.Key, []byte, error) {
	dek := make(core.Key, 32)
	if _, err := rand.Read(dek); err != nil {
		return nil, nil, err
	}
	payload, err := core.BindDataKey(dek, ns, keyID)
	if err != nil {
		return nil, nil, err
	}
	defer core.ZeroKey(payload)
	nonce := make([]byte, w.kek.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, err
	}
	return dek, w.kek.Seal(nonce, nonce, payload, nil), nil // the "KMS" call
}

func (w *noAADWrapper) UnwrapKey(_ context.Context, ns, keyID string, wrapped []byte) (core.Key, error) {
	n := w.kek.NonceSize()
	if len(wrapped) < n {
		return nil, core.ErrKeyBinding
	}
	payload, err := w.kek.Open(nil, wrapped[:n], wrapped[n:], nil) // the "KMS" call
	if err != nil {
		return nil, err
	}
	defer core.ZeroKey(payload)
	return core.UnbindDataKey(payload, ns, keyID)
}

// A wrapper whose KMS has no associated data meets R-KW-1 to 4 through
// BindDataKey, and composes with envelope like any other.
func TestBoundWrapperConformance(t *testing.T) {
	w := newNoAADWrapper(t)
	privacytest.TestKeyWrapper(t, w)
	privacytest.TestKeyEngine(t, envelope.NewKeyEngine(w, memory.NewKeyEngine()))
}
