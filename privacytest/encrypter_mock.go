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
func (e *UnstableEncryptorMock) Decrypt(namespace string, key core.Key, cipherTxt []byte) (plainTxt string, err error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.counter >= e.PointOfFailure {
		return "", fmt.Errorf("%w: %v", core.ErrDecryptionFailure, ErrEncryptionMock)
	}
	e.counter++

	return string(cipherTxt[len("mock"):]), nil
}

// Encrypt implements core.Encryptor
func (e *UnstableEncryptorMock) Encrypt(namespace string, key core.Key, plainTxt string) (cipherTxt []byte, err error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.counter >= e.PointOfFailure {
		return nil, fmt.Errorf("%w: %v", core.ErrEncryptionFailure, ErrEncryptionMock)
	}
	e.counter++

	return []byte("mock" + plainTxt), nil
}

// EncryptStream implements core.Encryptor
func (e *UnstableEncryptorMock) EncryptStream(namespace string, key core.Key, r io.Reader) (io.Reader, error) {
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
func (e *UnstableEncryptorMock) DecryptStream(namespace string, key core.Key, r io.Reader) (io.Reader, error) {
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

// KeyGen implements core.Encryptor
func (*UnstableEncryptorMock) KeyGen() core.KeyGen {
	return nil
}
