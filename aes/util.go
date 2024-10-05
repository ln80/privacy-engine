// Package aes contains implementation and helper functions related
// specifically to "Advanced Encryption Standard" algorithm and cryptography in general.
package aes

import (
	"crypto/rand"
	"io"
)

func getRandomBytes(size uint16) ([]byte, error) {
	data := make([]byte, size)
	if _, err := io.ReadFull(rand.Reader, data); err != nil {
		return nil, err
	}

	return data, nil
}
