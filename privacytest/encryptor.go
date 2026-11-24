package privacytest

import (
	"bytes"
	"context"
	"io"
	"strconv"
	"testing"

	"github.com/ln80/privacy-engine/core"
)

// EncryptorTestConfig configures TestEncryptor.
type EncryptorTestConfig struct {
	// StreamSize is the plaintext size of the stream checks. Make it span
	// several of your segments. Default 200 KiB.
	StreamSize int
}

// TestEncryptor is the conformance suite of core.Encryptor. It runs one
// subtest per requirement R-EN of docs/implementing-backends.md, named after
// its ID. It knows nothing of the construction: key sizes come from the
// encryptor's KeyGen, and stream checks cut, move, repeat and drop byte
// ranges without knowing the segment layout.
func TestEncryptor(t *testing.T, enc core.Encryptor, opts ...func(*EncryptorTestConfig)) {
	t.Helper()
	cfg := &EncryptorTestConfig{}
	for _, opt := range opts {
		if opt != nil {
			opt(cfg)
		}
	}
	if cfg.StreamSize <= 0 {
		cfg.StreamSize = 200 << 10
	}
	run := func(name string, f func(c *encCheck)) {
		t.Helper()
		t.Run(name, func(t *testing.T) {
			f(&encCheck{t: t, enc: enc, binding: core.Binding{Namespace: newNamespace("privacytest"), KeyVersion: 1}})
		})
	}

	run("R-EN-1 the algorithm ID is stable and not reserved", func(c *encCheck) {
		id := c.enc.Algorithm()
		if c.enc.Algorithm() != id {
			c.t.Fatal("Algorithm returns different IDs")
		}
		if id == 0xFF {
			c.t.Fatal("0xFF is reserved for test doubles")
		}
	})

	run("R-EN-2 the binding is authenticated", func(c *encCheck) {
		key := c.key()
		ct := c.seal(key, c.binding, []byte("personal data"))
		for name, b := range map[string]core.Binding{
			"another namespace":   {Namespace: c.binding.Namespace + "x", KeyVersion: 1},
			"another key version": {Namespace: c.binding.Namespace, KeyVersion: 2},
			"caller-key version":  {Namespace: c.binding.Namespace, KeyVersion: 0},
		} {
			c.refused(key, b, ct, name)
		}
		r, err := c.enc.EncryptStream(c.binding, key, bytes.NewReader([]byte("stream")))
		c.must(err, "EncryptStream")
		sealed, err := io.ReadAll(r)
		c.must(err, "EncryptStream read")
		if _, err := readStream(c.enc.DecryptStream(core.Binding{Namespace: c.binding.Namespace + "x", KeyVersion: 1}, key, bytes.NewReader(sealed))); err == nil {
			c.t.Fatal("a stream opened under another namespace")
		}
		if _, err := readStream(c.enc.DecryptStream(core.Binding{Namespace: c.binding.Namespace, KeyVersion: 2}, key, bytes.NewReader(sealed))); err == nil {
			c.t.Fatal("a stream opened under another key version")
		}
	})

	run("R-EN-3 nonces are fresh and any change fails", func(c *encCheck) {
		key := c.key()
		plain := []byte("thirty-two bytes of personal da")
		ct := c.seal(key, c.binding, plain)
		if bytes.Equal(ct, c.seal(key, c.binding, plain)) {
			c.t.Fatal("two encryptions of one plaintext are equal: the nonce is not fresh")
		}
		if bytes.Contains(ct, plain[:16]) {
			c.t.Fatal("the ciphertext contains the plaintext")
		}
		for _, p := range [][]byte{{}, bytes.Repeat([]byte{7}, 1<<16)} {
			if got := c.open(key, c.binding, c.seal(key, c.binding, p)); !bytes.Equal(got, p) {
				c.t.Fatalf("a %d-byte plaintext does not round-trip", len(p))
			}
		}
		for i := range ct {
			for bit := range 8 {
				bad := bytes.Clone(ct)
				bad[i] ^= 1 << bit
				c.refused(key, c.binding, bad, "a flipped bit")
			}
		}
		for n := range len(ct) {
			c.refused(key, c.binding, ct[:n], "a truncated ciphertext")
		}
		c.refused(key, c.binding, append(bytes.Clone(ct), 0), "an extended ciphertext")
		c.refused(c.key(), c.binding, ct, "another key")
	})

	run("R-EN-4 wrong-size and all-zero keys are refused", func(c *encCheck) {
		key := c.key()
		if bytes.Equal(key, c.key()) {
			c.t.Fatal("KeyGen repeats keys")
		}
		n := len(key)
		for _, size := range []int{0, 1, n / 2, n - 1, n + 1} {
			if _, err := c.enc.Encrypt(c.binding, make(core.Key, size), []byte("x")); err == nil {
				c.t.Fatalf("Encrypt accepted a %d-byte key", size)
			}
		}
		zero := make(core.Key, n)
		if _, err := c.enc.Encrypt(c.binding, zero, []byte("x")); err == nil {
			c.t.Fatal("Encrypt accepted an all-zero key")
		}
		if _, err := c.enc.EncryptStream(c.binding, zero, bytes.NewReader([]byte("x"))); err == nil {
			c.t.Fatal("EncryptStream accepted an all-zero key")
		}
	})

	run("R-EN-5 streams fail on truncation, reordering, duplication or appended data", func(c *encCheck) {
		key := c.key()
		plain := bytes.Repeat([]byte("0123456789abcdef"), cfg.StreamSize/16)
		r, err := c.enc.EncryptStream(c.binding, key, bytes.NewReader(plain))
		c.must(err, "EncryptStream")
		sealed, err := io.ReadAll(r)
		c.must(err, "EncryptStream read")
		got, err := readStream(c.enc.DecryptStream(c.binding, key, bytes.NewReader(sealed)))
		if err != nil || !bytes.Equal(got, plain) {
			c.t.Fatalf("the stream does not round-trip: %v", err)
		}

		n := len(sealed)
		q := n / 4
		cat := func(parts ...[]byte) []byte { return bytes.Join(parts, nil) }
		forged := map[string][]byte{
			"appended byte":     cat(sealed, []byte{0}),
			"appended copy":     cat(sealed, sealed[n-q:]),
			"middle dropped":    cat(sealed[:q], sealed[2*q:]),
			"middle duplicated": cat(sealed[:2*q], sealed[q:]),
			"quarters swapped":  cat(sealed[:q], sealed[2*q:3*q], sealed[q:2*q], sealed[3*q:]),
			"tail dropped":      sealed[:n-1],
			"half dropped":      sealed[:n/2],
		}
		for cut := range min(n, 64) {
			forged["cut at "+strconv.Itoa(cut)] = sealed[:cut]
		}
		for i := 0; i < n; i += max(1, n/97) {
			b := bytes.Clone(sealed)
			b[i] ^= 0x01
			forged["flip at "+strconv.Itoa(i)] = b
		}
		for name, s := range forged {
			if _, err := readStream(c.enc.DecryptStream(c.binding, key, bytes.NewReader(s))); err == nil {
				c.t.Fatalf("%s: the stream decrypted to the end", name)
			}
		}
	})
}

type encCheck struct {
	t       *testing.T
	enc     core.Encryptor
	binding core.Binding
}

func (c *encCheck) must(err error, what string) {
	c.t.Helper()
	if err != nil {
		c.t.Fatalf("%s: %v", what, err)
	}
}

func (c *encCheck) key() core.Key {
	c.t.Helper()
	k, err := c.enc.KeyGen()(context.Background(), c.binding.Namespace, randomID())
	c.must(err, "KeyGen")
	return k
}

func (c *encCheck) seal(key core.Key, b core.Binding, plain []byte) []byte {
	c.t.Helper()
	ct, err := c.enc.Encrypt(b, key, plain)
	c.must(err, "Encrypt")
	return ct
}

func (c *encCheck) open(key core.Key, b core.Binding, ct []byte) []byte {
	c.t.Helper()
	p, err := c.enc.Decrypt(b, key, ct)
	c.must(err, "Decrypt")
	return p
}

func (c *encCheck) refused(key core.Key, b core.Binding, ct []byte, what string) {
	c.t.Helper()
	p, err := c.enc.Decrypt(b, key, ct)
	if err == nil {
		c.t.Fatalf("Decrypt with %s: expect an error", what)
	}
	if len(p) != 0 {
		c.t.Fatalf("Decrypt with %s: returned plaintext with its error", what)
	}
}

// readStream reads a stream to its end: errors may come from the
// constructor or from Read. A stream is valid only once it reaches io.EOF.
func readStream(r io.Reader, err error) ([]byte, error) {
	if err != nil {
		return nil, err
	}
	return io.ReadAll(r)
}
