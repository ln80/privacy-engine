package aes

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
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

func (e *aes256gcm) EncryptStream(namespace string, key core.Key, r io.Reader) (io.Reader, error) {
	block, err := aes.NewCipher([]byte(key[:]))
	if err != nil {
		return nil, err
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	baseNonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, baseNonce); err != nil {
		return nil, err
	}

	pr, pw := io.Pipe()

	go func() {
		defer pw.Close()

		// Write header
		header := make([]byte, 1+len(baseNonce))
		header[0] = 1 // version
		copy(header[1:], baseNonce)

		if _, err := pw.Write(header); err != nil {
			pw.CloseWithError(err)
			return
		}

		buf := make([]byte, 4*1024*1024) // 4MB chunks
		var chunkIndex uint64

		for {
			n, readErr := r.Read(buf)
			if n > 0 {
				plaintext := buf[:n]

				nonce := deriveNonce(baseNonce, chunkIndex)
				aad := prepareAdditionalData(namespaceWithChunk(namespace, chunkIndex))

				ciphertext := aead.Seal(nil, nonce, plaintext, aad)
				chunkIndex++

				var lenBuf [4]byte
				binary.BigEndian.PutUint32(lenBuf[:], uint32(len(ciphertext)))

				if _, err := pw.Write(lenBuf[:]); err != nil {
					pw.CloseWithError(err)
					return
				}
				if _, err := pw.Write(ciphertext); err != nil {
					pw.CloseWithError(err)
					return
				}
			}

			if readErr == io.EOF {
				return
			}
			if readErr != nil {
				pw.CloseWithError(readErr)
				return
			}
		}
	}()

	return pr, nil
}

func (e *aes256gcm) DecryptStream(namespace string, key core.Key, r io.Reader) (io.Reader, error) {
	block, err := aes.NewCipher([]byte(key[:]))
	if err != nil {
		return nil, err
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Read header
	header := make([]byte, 1+aead.NonceSize())
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, err
	}

	version := header[0]
	if version != 1 {
		return nil, errors.New("unsupported version")
	}

	baseNonce := header[1:]

	pr, pw := io.Pipe()

	go func() {
		defer pw.Close()

		var chunkIndex uint64

		for {
			var lenBuf [4]byte
			_, err := io.ReadFull(r, lenBuf[:])
			if err == io.EOF {
				return
			}
			if err != nil {
				pw.CloseWithError(err)
				return
			}

			chunkLen := binary.BigEndian.Uint32(lenBuf[:])
			ciphertext := make([]byte, chunkLen)

			if _, err := io.ReadFull(r, ciphertext); err != nil {
				pw.CloseWithError(err)
				return
			}

			nonce := deriveNonce(baseNonce, chunkIndex)
			aad := prepareAdditionalData(namespaceWithChunk(namespace, chunkIndex))

			plaintext, err := aead.Open(nil, nonce, ciphertext, aad)
			if err != nil {
				pw.CloseWithError(err)
				return
			}

			chunkIndex++

			if _, err := pw.Write(plaintext); err != nil {
				pw.CloseWithError(err)
				return
			}
		}
	}()

	return pr, nil
}
