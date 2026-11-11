package aes

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"io"
	"runtime"
	"strings"
	"testing"
	"testing/iotest"
	"time"

	"github.com/ln80/privacy-engine/core"
)

const testNS = "tenant-stream"

func testKey(t testing.TB) core.Key {
	t.Helper()
	k, err := Key256GenFn(context.Background(), testNS, "subject-1")
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func randBytes(t testing.TB, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

func encryptWith(t testing.TB, key core.Key, ns string, plain []byte, segSize int) []byte {
	t.Helper()
	r, err := newStreamEncrypter(ns, key, bytes.NewReader(plain), segSize)
	if err != nil {
		t.Fatal(err)
	}
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// decryptAll returns the plaintext and the first error from the constructor or Read.
func decryptAll(key core.Key, ns string, sealed []byte) ([]byte, error) {
	r, err := newStreamDecrypter(ns, key, bytes.NewReader(sealed))
	if err != nil {
		return nil, err
	}
	return io.ReadAll(r)
}

func TestStreamRoundTrip(t *testing.T) {
	key := testKey(t)
	const seg = 64
	for _, n := range []int{0, 1, seg - 1, seg, seg + 1, 2 * seg, 3*seg + 7} {
		plain := randBytes(t, n)
		sealed := encryptWith(t, key, testNS, plain, seg)

		segments := max(1, (n+seg-1)/seg) // the last segment is final; empty only for empty input
		if want := streamHeaderSize + n + segments*streamTagSize; len(sealed) != want {
			t.Fatalf("n=%d: ciphertext length %d, want %d", n, len(sealed), want)
		}
		got, err := decryptAll(key, testNS, sealed)
		if err != nil {
			t.Fatalf("n=%d: %v", n, err)
		}
		if !bytes.Equal(got, plain) {
			t.Fatalf("n=%d: plaintext mismatch", n)
		}
	}
}

func TestStreamDefaultSegmentThroughEncryptor(t *testing.T) {
	enc := New256GCMEncryptor()
	key := testKey(t)
	plain := randBytes(t, 3*DefaultStreamSegmentSize+123)

	r, err := enc.EncryptStream(testNS, key, bytes.NewReader(plain))
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	d, err := enc.DecryptStream(testNS, key, bytes.NewReader(sealed))
	if err != nil {
		t.Fatal(err)
	}
	// iotest.TestReader also checks the reader against short reads and Seek-free misuse.
	if err := iotest.TestReader(d, plain); err != nil {
		t.Fatal(err)
	}
}

// Segment boundaries must not depend on how the source reader returns data.
func TestStreamSegmentsIndependentOfSourceReads(t *testing.T) {
	key := testKey(t)
	plain := randBytes(t, 5*64+3)
	r, err := newStreamEncrypter(testNS, key, iotest.OneByteReader(bytes.NewReader(plain)), 64)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	if want := streamHeaderSize + len(plain) + 6*streamTagSize; len(sealed) != want {
		t.Fatalf("ciphertext length %d, want %d", len(sealed), want)
	}
	got, err := decryptAll(key, testNS, sealed)
	if err != nil || !bytes.Equal(got, plain) {
		t.Fatalf("round trip failed: %v", err)
	}
}

// PE-02 regression: cutting the stream anywhere, including at a segment
// boundary and right after the header, must fail.
func TestStreamTruncationDetected(t *testing.T) {
	key := testKey(t)
	const seg = 32
	plain := randBytes(t, 4*seg+5)
	sealed := encryptWith(t, key, testNS, plain, seg)

	for cut := 0; cut < len(sealed); cut++ {
		_, err := decryptAll(key, testNS, sealed[:cut])
		if !errors.Is(err, core.ErrDecryptionFailure) {
			t.Fatalf("cut at %d of %d: expect ErrDecryptionFailure, got %v", cut, len(sealed), err)
		}
	}
}

// The v1 attack: keep the header, drop everything after a boundary, append
// what used to be the end marker.
func TestStreamV1StyleTruncationRejected(t *testing.T) {
	key := testKey(t)
	const seg = 32
	sealed := encryptWith(t, key, testNS, randBytes(t, 3*seg), seg)
	cSeg := seg + streamTagSize

	forged := append(bytes.Clone(sealed[:streamHeaderSize+cSeg]), 0, 0, 0, 0)
	if _, err := decryptAll(key, testNS, forged); !errors.Is(err, core.ErrDecryptionFailure) {
		t.Fatalf("expect ErrDecryptionFailure, got %v", err)
	}
}

func TestStreamSegmentManipulationDetected(t *testing.T) {
	key := testKey(t)
	const seg = 32
	cSeg := seg + streamTagSize
	plain := randBytes(t, 3*seg+10) // segments: full, full, full, final(10)
	sealed := encryptWith(t, key, testNS, plain, seg)
	header, body := sealed[:streamHeaderSize], sealed[streamHeaderSize:]
	segAt := func(i int) []byte { return body[i*cSeg : min((i+1)*cSeg, len(body))] }
	join := func(parts ...[]byte) []byte { return bytes.Join(append([][]byte{header}, parts...), nil) }

	cases := map[string][]byte{
		"drop middle":      join(segAt(0), segAt(2), segAt(3)),
		"swap":             join(segAt(1), segAt(0), segAt(2), segAt(3)),
		"duplicate":        join(segAt(0), segAt(0), segAt(1), segAt(2), segAt(3)),
		"drop final":       join(segAt(0), segAt(1), segAt(2)),
		"append byte":      append(bytes.Clone(sealed), 0),
		"append segment":   join(segAt(0), segAt(1), segAt(2), segAt(3), segAt(0)),
		"repeat final":     join(segAt(0), segAt(1), segAt(2), segAt(3), segAt(3)),
		"header only":      bytes.Clone(header),
		"final moved left": join(segAt(3)),
	}
	for name, forged := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := decryptAll(key, testNS, forged); !errors.Is(err, core.ErrDecryptionFailure) {
				t.Fatalf("expect ErrDecryptionFailure, got %v", err)
			}
		})
	}
}

func TestStreamBitFlipsDetected(t *testing.T) {
	key := testKey(t)
	sealed := encryptWith(t, key, testNS, randBytes(t, 100), 32)
	for i := range sealed {
		forged := bytes.Clone(sealed)
		forged[i] ^= 0x01
		if _, err := decryptAll(key, testNS, forged); !errors.Is(err, core.ErrDecryptionFailure) {
			t.Fatalf("flip at byte %d: expect ErrDecryptionFailure, got %v", i, err)
		}
	}
}

func TestStreamBoundToKeyAndNamespace(t *testing.T) {
	key := testKey(t)
	sealed := encryptWith(t, key, testNS, []byte("payload"), 32)

	if _, err := decryptAll(testKey(t), testNS, sealed); !errors.Is(err, core.ErrDecryptionFailure) {
		t.Fatalf("other key: expect ErrDecryptionFailure, got %v", err)
	}
	if _, err := decryptAll(key, "tenant-other", sealed); !errors.Is(err, core.ErrDecryptionFailure) {
		t.Fatalf("other namespace: expect ErrDecryptionFailure, got %v", err)
	}
	// Length-prefixed namespace: "ab"+"c" and "a"+"bc" style ambiguity is impossible.
	if _, err := decryptAll(key, testNS+"|chunk:0", sealed); !errors.Is(err, core.ErrDecryptionFailure) {
		t.Fatalf("suffixed namespace: expect ErrDecryptionFailure, got %v", err)
	}
}

func TestStreamRejectsBadHeader(t *testing.T) {
	key := testKey(t)
	sealed := encryptWith(t, key, testNS, []byte("payload"), 32)

	cases := map[string]func([]byte){
		"v1":              func(b []byte) { b[0] = 1 },
		"unknown alg":     func(b []byte) { b[1] = 9 },
		"segment zero":    func(b []byte) { copy(b[2:6], []byte{0, 0, 0, 0}) },
		"segment too big": func(b []byte) { copy(b[2:6], []byte{0xff, 0xff, 0xff, 0xff}) },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			forged := bytes.Clone(sealed)
			mutate(forged)
			_, err := newStreamDecrypter(testNS, key, bytes.NewReader(forged))
			if !errors.Is(err, core.ErrDecryptionFailure) {
				t.Fatalf("expect ErrDecryptionFailure from constructor, got %v", err)
			}
		})
	}
	if _, err := newStreamDecrypter(testNS, key, strings.NewReader("short")); !errors.Is(err, core.ErrDecryptionFailure) {
		t.Fatalf("short header: expect ErrDecryptionFailure, got %v", err)
	}
}

func TestStreamPropagatesSourceError(t *testing.T) {
	key := testKey(t)
	boom := errors.New("boom")
	r, err := newStreamEncrypter(testNS, key, iotest.ErrReader(boom), 32)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadAll(r); !errors.Is(err, boom) || !errors.Is(err, core.ErrEncryptionFailure) {
		t.Fatalf("expect source error joined with ErrEncryptionFailure, got %v", err)
	}
}

// PE-19 regression: abandoned streams hold no goroutine.
func TestStreamAbandonedLeaksNoGoroutine(t *testing.T) {
	enc := New256GCMEncryptor()
	key := testKey(t)
	sealed := encryptWith(t, key, testNS, randBytes(t, 1024), 64)

	before := runtime.NumGoroutine()
	for range 50 {
		e, err := enc.EncryptStream(testNS, key, bytes.NewReader(randBytes(t, 1024)))
		if err != nil {
			t.Fatal(err)
		}
		_, _ = e.Read(make([]byte, 10))
		d, err := enc.DecryptStream(testNS, key, bytes.NewReader(sealed))
		if err != nil {
			t.Fatal(err)
		}
		_, _ = d.Read(make([]byte, 10))
	}
	time.Sleep(10 * time.Millisecond)
	if after := runtime.NumGoroutine(); after > before {
		t.Fatalf("goroutines grew from %d to %d", before, after)
	}
}

// FuzzDecryptStream: arbitrary input never panics, and any change to a valid
// stream either fails or decrypts to exactly the original plaintext.
func FuzzDecryptStream(f *testing.F) {
	key := testKey(f)
	plain := []byte("fuzz plaintext spanning several small segments!")
	valid := encryptWith(f, key, testNS, plain, 16)
	f.Add(valid)
	f.Add(valid[:streamHeaderSize])
	f.Add([]byte{2, 1, 0, 0, 0, 16})
	f.Fuzz(func(t *testing.T, in []byte) {
		got, err := decryptAll(key, testNS, in)
		if err == nil && !bytes.Equal(in, valid) {
			t.Fatalf("forged stream accepted: %q", got)
		}
		if err == nil && !bytes.Equal(got, plain) {
			t.Fatalf("valid stream decrypted to %q", got)
		}
	})
}
