package aes

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"math"

	"github.com/ln80/privacy-engine/core"
	"golang.org/x/crypto/hkdf"
)

// Stream format v2: online authenticated encryption in the STREAM construction
// (Hoang, Reyhanitabar, Rogaway, Vizár 2015), as used by Tink and age.
//
//	header    = version(1) | alg(1) | segmentSize(4, BE) | salt(32) | noncePrefix(7)
//	streamKey = HKDF-SHA256(ikm=DEK, salt=salt, info="privacy-engine/stream/v2" | len16(ns) | ns)
//	segment_i = AES-256-GCM(streamKey, nonce=noncePrefix | i(4, BE) | final(1), aad=header)
//
// Every segment holds segmentSize bytes of plaintext except the last, which holds
// 0 to segmentSize bytes and is the only one sealed with final=1. Ciphertext
// segments are therefore segmentSize+16 bytes except the last, so no length
// framing is needed. The decrypter tells the last segment by EOF and opens it
// with final=1, so a stream cut at a segment boundary, extended, reordered or
// with a segment dropped fails authentication. The header is the AAD of every
// segment and its salt feeds the key derivation, so a header edit fails too.
const (
	streamVersion          byte = 2
	streamAlgAES256GCMHKDF byte = 1

	streamSaltSize        = 32
	streamNoncePrefixSize = 7
	streamHeaderSize      = 2 + 4 + streamSaltSize + streamNoncePrefixSize
	streamTagSize         = 16

	// DefaultStreamSegmentSize is the plaintext size of every segment but the last.
	DefaultStreamSegmentSize = 64 * 1024

	minStreamSegmentSize = 16
	maxStreamSegmentSize = 4 * 1024 * 1024

	streamKDFInfo = "privacy-engine/stream/v2"
)

var (
	errStreamAuth     = errors.New("encrypted stream failed authentication: tampered, truncated, or wrong key or namespace")
	errStreamHeader   = errors.New("invalid encrypted stream header")
	errStreamTooLong  = errors.New("stream exceeds the maximum number of segments")
	errNamespaceLimit = errors.New("namespace too long")
)

// streamAEAD derives the per-stream AES-256-GCM AEAD from the DEK.
// The derived key is wiped once the cipher has expanded it.
func streamAEAD(key core.Key, namespace string, salt []byte) (cipher.AEAD, error) {
	if len(namespace) > math.MaxUint16 {
		return nil, errNamespaceLimit
	}
	info := make([]byte, 0, len(streamKDFInfo)+2+len(namespace))
	info = append(info, streamKDFInfo...)
	info = binary.BigEndian.AppendUint16(info, uint16(len(namespace))) // #nosec G115 -- bounded above
	info = append(info, namespace...)

	derived := make([]byte, aES265KeySize)
	defer core.ZeroKey(derived)
	if _, err := io.ReadFull(hkdf.New(sha256.New, key, salt, info), derived); err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(derived)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func segmentNonce(prefix []byte, idx uint32, final bool) []byte {
	nonce := make([]byte, 0, streamNoncePrefixSize+5)
	nonce = append(nonce, prefix...)
	nonce = binary.BigEndian.AppendUint32(nonce, idx)
	if final {
		return append(nonce, 1)
	}
	return append(nonce, 0)
}

// fillSegment reads into buf until it is full or src is exhausted.
// It returns the number of bytes in buf and whether src reached EOF.
func fillSegment(src io.Reader, buf []byte, have int) (int, bool, error) {
	n, err := io.ReadFull(src, buf[have:])
	n += have
	switch {
	case err == nil:
		return n, false, nil
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		return n, true, nil
	default:
		return n, false, err
	}
}

// streamEncrypter is a pull-based reader: it encrypts one segment per refill
// and holds no goroutine, so a caller that stops reading leaks nothing.
type streamEncrypter struct {
	src         io.Reader
	aead        cipher.AEAD
	header      []byte
	noncePrefix []byte
	segSize     int

	buf  []byte // segSize+1: one byte of lookahead tells the last segment
	have int    // bytes already in buf (the lookahead byte carried over)
	obuf []byte // reused ciphertext buffer
	out  []byte // ciphertext not yet returned
	idx  uint32
	done bool
	err  error
}

func newStreamEncrypter(namespace string, key core.Key, r io.Reader, segSize int) (io.Reader, error) {
	if err := validateAES256Key(key); err != nil {
		return nil, errors.Join(core.ErrEncryptionFailure, err)
	}
	if segSize < minStreamSegmentSize || segSize > maxStreamSegmentSize {
		return nil, errors.Join(core.ErrEncryptionFailure, errors.New("invalid stream segment size"))
	}

	header := make([]byte, streamHeaderSize)
	header[0] = streamVersion
	header[1] = streamAlgAES256GCMHKDF
	binary.BigEndian.PutUint32(header[2:6], uint32(segSize)) // #nosec G115 -- bounded above
	if _, err := io.ReadFull(rand.Reader, header[6:]); err != nil {
		return nil, errors.Join(core.ErrEncryptionFailure, err)
	}
	salt := header[6 : 6+streamSaltSize]

	aead, err := streamAEAD(key, namespace, salt)
	if err != nil {
		return nil, errors.Join(core.ErrEncryptionFailure, err)
	}

	return &streamEncrypter{
		src:         r,
		aead:        aead,
		header:      header,
		noncePrefix: header[6+streamSaltSize:],
		segSize:     segSize,
		buf:         make([]byte, segSize+1),
		obuf:        make([]byte, 0, segSize+streamTagSize),
		out:         header,
	}, nil
}

func (s *streamEncrypter) Read(p []byte) (int, error) {
	for len(s.out) == 0 {
		if s.err != nil {
			return 0, s.err
		}
		if s.done {
			return 0, io.EOF
		}
		s.next()
	}
	n := copy(p, s.out)
	s.out = s.out[n:]
	return n, nil
}

func (s *streamEncrypter) next() {
	n, eof, err := fillSegment(s.src, s.buf, s.have)
	if err != nil {
		s.err = errors.Join(core.ErrEncryptionFailure, err)
		return
	}
	final := eof
	if !final && s.idx == math.MaxUint32 {
		s.err = errors.Join(core.ErrEncryptionFailure, errStreamTooLong)
		return
	}

	plain := s.buf[:n]
	if !final {
		plain = s.buf[:s.segSize]
	}
	s.out = s.aead.Seal(s.obuf[:0], segmentNonce(s.noncePrefix, s.idx, final), plain, s.header)
	clear(plain)

	if final {
		s.done = true
		return
	}
	s.buf[0] = s.buf[s.segSize]
	s.have = 1
	s.idx++
}

// streamDecrypter releases a segment's plaintext only after that segment
// authenticates. A truncated or tampered stream still yields the segments
// before the damage, then an error: callers must treat a stream as valid only
// once Read returns io.EOF.
type streamDecrypter struct {
	src         io.Reader
	aead        cipher.AEAD
	header      []byte
	noncePrefix []byte
	cSegSize    int

	buf  []byte // cSegSize+1, with one byte of lookahead
	have int
	obuf []byte // reused plaintext buffer
	out  []byte
	idx  uint32
	done bool
	err  error
}

func newStreamDecrypter(namespace string, key core.Key, r io.Reader) (io.Reader, error) {
	if err := validateAES256Key(key); err != nil {
		return nil, errors.Join(core.ErrDecryptionFailure, err)
	}

	header := make([]byte, streamHeaderSize)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, errors.Join(core.ErrDecryptionFailure, errStreamHeader, err)
	}
	if header[0] != streamVersion || header[1] != streamAlgAES256GCMHKDF {
		return nil, errors.Join(core.ErrDecryptionFailure, errStreamHeader, errors.New("unsupported version or algorithm"))
	}
	segSize := int(binary.BigEndian.Uint32(header[2:6]))
	if segSize < minStreamSegmentSize || segSize > maxStreamSegmentSize {
		return nil, errors.Join(core.ErrDecryptionFailure, errStreamHeader, errors.New("segment size out of range"))
	}

	aead, err := streamAEAD(key, namespace, header[6:6+streamSaltSize])
	if err != nil {
		return nil, errors.Join(core.ErrDecryptionFailure, err)
	}

	cSegSize := segSize + streamTagSize
	return &streamDecrypter{
		src:         r,
		aead:        aead,
		header:      header,
		noncePrefix: header[6+streamSaltSize:],
		cSegSize:    cSegSize,
		buf:         make([]byte, cSegSize+1),
		obuf:        make([]byte, 0, segSize),
	}, nil
}

func (s *streamDecrypter) Read(p []byte) (int, error) {
	for len(s.out) == 0 {
		if s.err != nil {
			return 0, s.err
		}
		if s.done {
			return 0, io.EOF
		}
		s.next()
	}
	n := copy(p, s.out)
	s.out = s.out[n:]
	return n, nil
}

func (s *streamDecrypter) next() {
	n, eof, err := fillSegment(s.src, s.buf, s.have)
	if err != nil {
		s.err = errors.Join(core.ErrDecryptionFailure, err)
		return
	}
	final := eof
	if !final && s.idx == math.MaxUint32 {
		s.err = errors.Join(core.ErrDecryptionFailure, errStreamTooLong)
		return
	}

	sealed := s.buf[:n]
	if !final {
		sealed = s.buf[:s.cSegSize]
	}
	if len(sealed) < streamTagSize {
		s.err = errors.Join(core.ErrDecryptionFailure, errStreamAuth)
		return
	}
	plain, err := s.aead.Open(s.obuf[:0], segmentNonce(s.noncePrefix, s.idx, final), sealed, s.header)
	if err != nil {
		s.err = errors.Join(core.ErrDecryptionFailure, errStreamAuth)
		return
	}
	s.out = plain

	if final {
		s.done = true
		return
	}
	s.buf[0] = s.buf[s.cSegSize]
	s.have = 1
	s.idx++
}
