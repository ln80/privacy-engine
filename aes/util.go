// Package aes contains implementation and helper functions related
// specifically to "Advanced Encryption Standard" algorithm and cryptography in general.
package aes

import (
	"crypto/rand"
	"io"
	"strconv"
)

func getRandomBytes(size uint16) ([]byte, error) {
	data := make([]byte, size)
	if _, err := io.ReadFull(rand.Reader, data); err != nil {
		return nil, err
	}

	return data, nil
}

func prepareAdditionalData(namespace string) []byte {
	if namespace == "" {
		return nil
	}
	return append([]byte("ns:"), []byte(namespace)...)
}

func deriveNonce(base []byte, counter uint64) []byte {
	nonce := make([]byte, len(base))
	copy(nonce, base)

	for i := 0; i < 8; i++ {
		nonce[len(nonce)-1-i] ^= byte(counter >> (8 * i)) // #nosec G115 -- intentional byte extraction
	}

	return nonce
}

func namespaceWithChunk(ns string, idx uint64) string {
	return ns + "|chunk:" + strconv.FormatUint(idx, 10)
}
