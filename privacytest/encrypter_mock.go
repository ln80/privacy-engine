package privacytest

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/ln80/privacy-engine/core"
)

var (
	ErrEncryptionMock = errors.New("encryption errors mock")
)

var _ core.Encryptor = &UnstableEncryptorMock{}

type UnstableEncryptorMock struct {
	PointOfFailure, counter int
	mu                      sync.RWMutex
}

func (e *UnstableEncryptorMock) ResetCounter() {
	e.counter = 0
}

// Decrypt implements core.Encryptor
func (e *UnstableEncryptorMock) Decrypt(binding core.Binding, key core.Key, cipherTxt []byte) (plaintext []byte, err error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.counter >= e.PointOfFailure {
		return nil, fmt.Errorf("%w: %v", core.ErrDecryptionFailure, ErrEncryptionMock)
	}
	e.counter++

	return bytes.Clone(cipherTxt[len("mock"):]), nil
}

// Encrypt implements core.Encryptor
func (e *UnstableEncryptorMock) Encrypt(binding core.Binding, key core.Key, plaintext []byte) (cipherTxt []byte, err error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.counter >= e.PointOfFailure {
		return nil, fmt.Errorf("%w: %v", core.ErrEncryptionFailure, ErrEncryptionMock)
	}
	e.counter++

	return append([]byte("mock"), plaintext...), nil
}

// EncryptStream implements core.Encryptor
func (e *UnstableEncryptorMock) EncryptStream(binding core.Binding, key core.Key, r io.Reader) (io.Reader, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.counter >= e.PointOfFailure {
		return nil, fmt.Errorf("%w: %v", core.ErrEncryptionFailure, ErrEncryptionMock)
	}
	e.counter++

	plain, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	return bytes.NewReader([]byte("mock" + string(plain))), nil
}

// DecryptStream implements core.Encryptor
func (e *UnstableEncryptorMock) DecryptStream(binding core.Binding, key core.Key, r io.Reader) (io.Reader, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.counter >= e.PointOfFailure {
		return nil, fmt.Errorf("%w: %v", core.ErrDecryptionFailure, ErrEncryptionMock)
	}
	e.counter++

	cipherTxt, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	return bytes.NewReader(cipherTxt[len("mock"):]), nil
}

// Algorithm implements core.Encryptor. 0xFF is reserved for test doubles.
func (*UnstableEncryptorMock) Algorithm() uint8 {
	return 0xFF
}

// KeyGen implements core.Encryptor
func (*UnstableEncryptorMock) KeyGen() core.KeyGen {
	return nil
}
