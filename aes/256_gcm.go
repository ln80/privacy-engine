package aes

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"

	"github.com/ln80/privacy-engine/core"
)

const aES265KeySize = 32

// AlgAES256GCM identifies field values encrypted by this package: AES-256-GCM
// directly under the DEK, random 96-bit nonce, AAD from fieldAAD.
const AlgAES256GCM uint8 = 0x01

func Key256GenFn(ctx context.Context, namespace, subID string) ([]byte, error) {
	return getRandomBytes(aES265KeySize)
}

type aes256gcm struct{}

var _ core.Encryptor = &aes256gcm{}

func New256GCMEncryptor() core.Encryptor {
	return &aes256gcm{}
}

// Algorithm implements core.Encryptor.
func (e *aes256gcm) Algorithm() uint8 {
	return AlgAES256GCM
}

func (e *aes256gcm) KeyGen() core.KeyGen {
	return Key256GenFn
}

// validateAES256Key rejects keys crypto/aes would silently accept as AES-128 or AES-192,
// and rejects a 32-byte all-zero key, which AES-GCM would use without error.
func validateAES256Key(key core.Key) error {
	if len(key) != aES265KeySize {
		return errors.New("aes-256 key must be 32 bytes")
	}
	var acc byte
	for _, b := range key {
		acc |= b
	}
	if acc == 0 {
		return errors.New("aes-256 key must not be all zeros")
	}
	return nil
}

func (e *aes256gcm) Encrypt(binding core.Binding, key core.Key, plaintext []byte) (cipherTxt []byte, err error) {
	defer func() {
		if err != nil {
			err = errors.Join(core.ErrEncryptionFailure, err)
		}
	}()

	if err = validateAES256Key(key); err != nil {
		return
	}

	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return
	}

	nonce := make([]byte, aesgcm.NonceSize())
	_, err = io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return
	}
	aad, err := fieldAAD(binding)
	if err != nil {
		return
	}

	// nonce | ciphertext | tag
	return aesgcm.Seal(nonce, nonce, plaintext, aad), nil
}

func (e *aes256gcm) Decrypt(binding core.Binding, key core.Key, cipherTxt []byte) (plaintext []byte, err error) {
	defer func() {
		if err != nil {
			err = errors.Join(core.ErrDecryptionFailure, err)
		}
	}()

	if err = validateAES256Key(key); err != nil {
		return
	}

	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return
	}

	// A ciphertext shorter than nonce + tag cannot be valid; slicing it would panic.
	if len(cipherTxt) < aesgcm.NonceSize()+aesgcm.Overhead() {
		err = errors.New("ciphertext too short")
		return
	}

	aad, err := fieldAAD(binding)
	if err != nil {
		return
	}
	return aesgcm.Open(nil, cipherTxt[:aesgcm.NonceSize()], cipherTxt[aesgcm.NonceSize():], aad) // #nosec G407
}

// EncryptStream implements core.Encryptor with stream format v2 (see stream.go).
// The returned reader does no work until read and holds no goroutine.
func (e *aes256gcm) EncryptStream(binding core.Binding, key core.Key, r io.Reader) (io.Reader, error) {
	return newStreamEncrypter(binding, key, r, DefaultStreamSegmentSize)
}

// DecryptStream implements core.Encryptor with stream format v2 (see stream.go).
// It reads and checks the header before returning. Plaintext of each segment is
// released only once that segment authenticates; the stream as a whole is valid
// only once Read returns io.EOF.
func (e *aes256gcm) DecryptStream(binding core.Binding, key core.Key, r io.Reader) (io.Reader, error) {
	return newStreamDecrypter(binding, key, r)
}
