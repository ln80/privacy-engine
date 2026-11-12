package core

import (
	"errors"
	"io"
)

// Errors returned by Encryptor implementations
var (
	ErrEncryptionFailure = errors.New("failed to encrypt data")
	ErrDecryptionFailure = errors.New("failed to decrypt data")
)

// Binding is what a ciphertext is bound to, besides its key. An Encryptor
// authenticates every field of it, so a ciphertext only decrypts under the
// same Binding it was produced with.
//
// It is not the KMS encryption context: that one binds a wrapped DEK inside
// the key store, while Binding binds data encrypted under the DEK.
type Binding struct {
	// Namespace is the protector's namespace (tenant).
	Namespace string

	// KeyVersion is the version of the subject's key used. 1 is the first
	// version; 0 means a caller-managed key (the *WithKey stream methods).
	KeyVersion uint32
}

// Encryptor presents a service responsible for implementing encryption logic
// based on a specific algorithm.
type Encryptor interface {

	// Algorithm returns the identifier recorded in field values next to the key
	// version, and authenticated with them. Each identifier names one exact
	// construction; it never changes meaning.
	Algorithm() uint8

	// Encrypt encrypts plaintext under key and binding.
	// The result holds everything Decrypt needs but the key and the binding.
	Encrypt(binding Binding, key Key, plaintext []byte) (ciphertext []byte, err error)

	// Decrypt decrypts a ciphertext produced by Encrypt with the same key and binding.
	// The caller owns the returned plaintext and may wipe it.
	Decrypt(binding Binding, key Key, ciphertext []byte) (plaintext []byte, err error)

	// EncryptStream encrypts plaintext read from r and returns a reader of ciphertext.
	EncryptStream(binding Binding, key Key, r io.Reader) (io.Reader, error)

	// DecryptStream decrypts ciphertext read from r and returns a reader of plaintext.
	DecryptStream(binding Binding, key Key, r io.Reader) (io.Reader, error)

	// KeyGen returns a function that generates a valid key
	// according to the implemented algorithm.
	KeyGen() KeyGen
}
