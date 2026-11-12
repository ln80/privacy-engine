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

func Key256GenFn(ctx context.Context, namespace, subID string) ([]byte, error) {
	return getRandomBytes(aES265KeySize)
}

type aes256gcm struct{}

var _ core.Encryptor = &aes256gcm{}

func New256GCMEncryptor() core.Encryptor {
	return &aes256gcm{}
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

func (e *aes256gcm) Encrypt(namespace string, key core.Key, plainTxt string) (cipherTxt []byte, err error) {
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
	aad := prepareAdditionalData(namespace)
	cTxt, err := aesgcm.Seal(nil, nonce, []byte(plainTxt), aad), nil
	if err != nil {
		return
	}

	cTxt = append(nonce, cTxt...)

	return cTxt, nil
}

func (e *aes256gcm) Decrypt(namespace string, key core.Key, cipherTxt []byte) (plainTxt string, err error) {
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

	aad := prepareAdditionalData(namespace)
	plnTxt, err := aesgcm.Open(nil, cipherTxt[:aesgcm.NonceSize()], cipherTxt[aesgcm.NonceSize():], aad) // #nosec G407
	if err != nil {
		return
	}

	return string(plnTxt), nil
}

// EncryptStream implements core.Encryptor with stream format v2 (see stream.go).
// The returned reader does no work until read and holds no goroutine.
func (e *aes256gcm) EncryptStream(namespace string, key core.Key, r io.Reader) (io.Reader, error) {
	return newStreamEncrypter(namespace, key, r, DefaultStreamSegmentSize)
}

// DecryptStream implements core.Encryptor with stream format v2 (see stream.go).
// It reads and checks the header before returning. Plaintext of each segment is
// released only once that segment authenticates; the stream as a whole is valid
// only once Read returns io.EOF.
func (e *aes256gcm) DecryptStream(namespace string, key core.Key, r io.Reader) (io.Reader, error) {
	return newStreamDecrypter(namespace, key, r)
}
