package core

import "errors"

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

	// KeyGen returns a function that generates a valid key
	// according to the implemented algorithm.
	KeyGen() KeyGen
}
