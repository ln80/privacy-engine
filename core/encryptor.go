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

// Encryptor presents a service responsible for implementing encryption logic
// based on a specific algorithm.
type Encryptor interface {

	// Encrypt encrypts the given plain text values and returns a cipher text.
	Encrypt(namespace string, key Key, plainTxt string) (cipher []byte, err error)

	// Decrypt decrypts the given cipher text and return the original value.
	Decrypt(namespace string, key Key, cipher []byte) (plainTxt string, err error)

	// EncryptStream encrypts plaintext read from r and returns a reader of ciphertext.
	EncryptStream(namespace string, key Key, r io.Reader) (io.Reader, error)

	// DecryptStream decrypts ciphertext read from r and returns a reader of plaintext.
	DecryptStream(namespace string, key Key, r io.Reader) (io.Reader, error)

	// KeyGen returns a function that generates a valid key
	// according to the implemented algorithm.
	KeyGen() KeyGen
}
