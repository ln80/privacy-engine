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

const (
	aES265KeySize = 32
)

func Key256GenFn(ctx context.Context, namespace, subID string) (string, error) {
	d, err := getRandomBytes(aES265KeySize)
	if err != nil {
		return "", err
	}
	return string(d), nil
}

type aes256gcm struct{}

var _ core.Encryptor = &aes256gcm{}

func New256GCMEncryptor() core.Encryptor {
	return &aes256gcm{}
}

func (e *aes256gcm) KeyGen() core.KeyGen {
	return Key256GenFn
}

func prepareAdditionalData(namespace string) []byte {
	if namespace == "" {
		return nil
	}
	return append([]byte("ns:"), []byte(namespace)...)
}

func (e *aes256gcm) Encrypt(namespace string, key core.Key, plainTxt string) (cipherTxt []byte, err error) {
	defer func() {
		if err != nil {
			err = errors.Join(core.ErrEncryptionFailure, err)
		}
	}()

	block, err := aes.NewCipher([]byte(key[:]))
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

	block, err := aes.NewCipher([]byte(key[:]))
	if err != nil {
		return
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return
	}

	aad := prepareAdditionalData(namespace)
	plnTxt, err := aesgcm.Open(nil, cipherTxt[:aesgcm.NonceSize()], cipherTxt[aesgcm.NonceSize():], aad) // #nosec G407
	if err != nil {
		return
	}

	return string(plnTxt), nil
}
