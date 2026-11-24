package core

import "context"

// KeyWrapper protects data keys with a key encryption key (KEK) held in a KMS
// or an HSM: envelope encryption. The key store then holds wrapped keys only,
// and reading it is not enough to decrypt anything.
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
