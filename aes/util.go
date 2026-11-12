// Package aes contains implementation and helper functions related
// specifically to "Advanced Encryption Standard" algorithm and cryptography in general.
package aes

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"math"

	"github.com/ln80/privacy-engine/core"
)

func getRandomBytes(size uint16) ([]byte, error) {
	data := make([]byte, size)
	if _, err := io.ReadFull(rand.Reader, data); err != nil {
		return nil, err
	}

	return data, nil
}

const fieldAADLabel = "privacy-engine/field/v2"

var errNamespaceLimit = errors.New("namespace too long")

// fieldAAD is the canonical, length-prefixed associated data of a field value:
//
//	"privacy-engine/field/v2" | alg (1) | keyVersion (4, BE) | len16(namespace) | namespace
//
// Binding the algorithm and key version means the header written next to the
// ciphertext cannot be edited; binding the namespace rejects a value moved to
// another tenant. No two different bindings encode to the same bytes.
func fieldAAD(b core.Binding) ([]byte, error) {
	if len(b.Namespace) > math.MaxUint16 {
		return nil, errNamespaceLimit
	}
	aad := make([]byte, 0, len(fieldAADLabel)+1+4+2+len(b.Namespace))
	aad = append(aad, fieldAADLabel...)
	aad = append(aad, AlgAES256GCM)
	aad = binary.BigEndian.AppendUint32(aad, b.KeyVersion)
	aad = binary.BigEndian.AppendUint16(aad, uint16(len(b.Namespace))) // #nosec G115 -- bounded above
	aad = append(aad, b.Namespace...)
	return aad, nil
}
