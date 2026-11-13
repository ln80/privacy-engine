package privacy

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"math"

	"github.com/ln80/privacy-engine/core"
	"golang.org/x/crypto/hkdf"
)

// Token vault v2 cryptography (privacy-engine.elastic docs/token-vault-v2.md,
// section 4). One DEK per namespace, kept by the key engine under the reserved
// ID "@vault", gives two derived keys:
//
//	indexKey = HKDF-SHA256(vaultDEK, info = "privacy-engine/vault/index/v1")
//	sealKey  = HKDF-SHA256(vaultDEK, info = "privacy-engine/vault/value/v1")
//
// A value's blind index is HMAC-SHA256(indexKey, value). Its sealed form is
//
//	0x01 | nonce (12) | AES-256-GCM(sealKey, nonce, value, aad)
//	aad = "privacy-engine/vault/v1" | 0x01 | len16(namespace) | namespace | len16(token) | token
//
// Every token of a namespace shares sealKey, so the token is bound in the AAD:
// a sealed value moved onto another token, or into another namespace, fails
// to open.
const (
	vaultKeyID = "@vault"

	vaultIndexInfo = "privacy-engine/vault/index/v1"
	vaultSealInfo  = "privacy-engine/vault/value/v1"
	vaultAADLabel  = "privacy-engine/vault/v1"

	vaultKeySize   = 32
	vaultNonceSize = 12
	vaultTagSize   = 16
)

// vaultSealAlg is the leading format and algorithm byte of a sealed value.
const vaultSealAlg byte = 0x01

var errVaultSealed = errors.New("sealed vault value failed authentication: tampered, moved, or wrong key")

// vaultKeys are the keys derived from a namespace's vault DEK. Wipe them with
// zero once used.
type vaultKeys struct {
	indexKey []byte
	sealKey  []byte
}

func deriveVaultKeys(vaultDEK core.Key) (vaultKeys, error) {
	if len(vaultDEK) != vaultKeySize {
		return vaultKeys{}, errors.New("vault key must be 32 bytes")
	}
	derive := func(info string) ([]byte, error) {
		k := make([]byte, vaultKeySize)
		if _, err := io.ReadFull(hkdf.New(sha256.New, vaultDEK, nil, []byte(info)), k); err != nil {
			return nil, err
		}
		return k, nil
	}
	index, err := derive(vaultIndexInfo)
	if err != nil {
		return vaultKeys{}, err
	}
	seal, err := derive(vaultSealInfo)
	if err != nil {
		core.ZeroKey(index)
		return vaultKeys{}, err
	}
	return vaultKeys{indexKey: index, sealKey: seal}, nil
}

func (k vaultKeys) zero() {
	core.ZeroKey(k.indexKey)
	core.ZeroKey(k.sealKey)
}

// blindIndex is the keyed lookup key of a value: equal values in one
// namespace share it, and without indexKey it cannot be computed or tested.
func (k vaultKeys) blindIndex(value []byte) []byte {
	m := hmac.New(sha256.New, k.indexKey)
	m.Write(value)
	return m.Sum(nil)
}

func vaultAAD(namespace, token string) ([]byte, error) {
	if len(namespace) > math.MaxUint16 || len(token) > math.MaxUint16 {
		return nil, errors.New("namespace or token too long")
	}
	aad := make([]byte, 0, len(vaultAADLabel)+1+4+len(namespace)+len(token))
	aad = append(aad, vaultAADLabel...)
	aad = append(aad, vaultSealAlg)
	aad = binary.BigEndian.AppendUint16(aad, uint16(len(namespace))) // #nosec G115 -- bounded above
	aad = append(aad, namespace...)
	aad = binary.BigEndian.AppendUint16(aad, uint16(len(token))) // #nosec G115 -- bounded above
	aad = append(aad, token...)
	return aad, nil
}

func (k vaultKeys) aead() (cipher.AEAD, error) {
	block, err := aes.NewCipher(k.sealKey)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// seal encrypts value for token in namespace.
func (k vaultKeys) seal(namespace, token string, value []byte) ([]byte, error) {
	aad, err := vaultAAD(namespace, token)
	if err != nil {
		return nil, err
	}
	aead, err := k.aead()
	if err != nil {
		return nil, err
	}
	out := make([]byte, 1+vaultNonceSize, 1+vaultNonceSize+len(value)+vaultTagSize)
	out[0] = vaultSealAlg
	if _, err := io.ReadFull(rand.Reader, out[1:]); err != nil {
		return nil, err
	}
	return aead.Seal(out, out[1:], value, aad), nil
}

// open decrypts a value sealed for token in namespace. The caller owns the
// returned plaintext and may wipe it.
func (k vaultKeys) open(namespace, token string, sealed []byte) ([]byte, error) {
	if len(sealed) < 1+vaultNonceSize+vaultTagSize {
		return nil, errors.New("sealed vault value too short")
	}
	if sealed[0] != vaultSealAlg {
		return nil, errors.New("unsupported sealed vault value format")
	}
	aad, err := vaultAAD(namespace, token)
	if err != nil {
		return nil, err
	}
	aead, err := k.aead()
	if err != nil {
		return nil, err
	}
	plain, err := aead.Open(nil, sealed[1:1+vaultNonceSize], sealed[1+vaultNonceSize:], aad)
	if err != nil {
		return nil, errVaultSealed
	}
	return plain, nil
}
