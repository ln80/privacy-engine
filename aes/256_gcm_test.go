package aes

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/ln80/privacy-engine/core"
)

func TestAES256RejectsBadKeys(t *testing.T) {
	enc := New256GCMEncryptor()
	namespace := "tenant-pe08"
	keys := []struct {
		name string
		key  core.Key
	}{
		{name: "16-byte", key: bytes.Repeat([]byte{1}, 16)},
		{name: "24-byte", key: bytes.Repeat([]byte{1}, 24)},
		{name: "31-byte", key: bytes.Repeat([]byte{1}, 31)},
		{name: "all-zero", key: make(core.Key, 32)},
	}

	for _, tc := range keys {
		t.Run(tc.name, func(t *testing.T) {
			_, err := enc.Encrypt(namespace, tc.key, "plain")
			if !errors.Is(err, core.ErrEncryptionFailure) {
				t.Fatalf("Encrypt: expect %v, got %v", core.ErrEncryptionFailure, err)
			}
			_, err = enc.Decrypt(namespace, tc.key, []byte("not-a-ciphertext"))
			if !errors.Is(err, core.ErrDecryptionFailure) {
				t.Fatalf("Decrypt: expect %v, got %v", core.ErrDecryptionFailure, err)
			}
			_, err = enc.EncryptStream(namespace, tc.key, strings.NewReader("plain"))
			if !errors.Is(err, core.ErrEncryptionFailure) {
				t.Fatalf("EncryptStream: expect %v, got %v", core.ErrEncryptionFailure, err)
			}
			_, err = enc.DecryptStream(namespace, tc.key, strings.NewReader("cipher"))
			if !errors.Is(err, core.ErrDecryptionFailure) {
				t.Fatalf("DecryptStream: expect %v, got %v", core.ErrDecryptionFailure, err)
			}
		})
	}
}

func TestAES256RoundTrip(t *testing.T) {
	enc := New256GCMEncryptor()
	namespace := "tenant-pe08"
	key, err := Key256GenFn(context.Background(), namespace, "subject-1")
	if err != nil {
		t.Fatal(err)
	}

	const plain = "hello"
	cipherTxt, err := enc.Encrypt(namespace, key, plain)
	if err != nil {
		t.Fatal(err)
	}
	got, err := enc.Decrypt(namespace, key, cipherTxt)
	if err != nil {
		t.Fatal(err)
	}
	if got != plain {
		t.Fatalf("expect %q, got %q", plain, got)
	}

	stream, err := enc.EncryptStream(namespace, key, strings.NewReader(plain))
	if err != nil {
		t.Fatal(err)
	}
	encrypted, err := io.ReadAll(stream)
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err := enc.DecryptStream(namespace, key, bytes.NewReader(encrypted))
	if err != nil {
		t.Fatal(err)
	}
	out, err := io.ReadAll(decrypted)
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != plain {
		t.Fatalf("expect %q, got %q", plain, out)
	}
}

// PE-03 regression: a ciphertext shorter than nonce + tag returns an error
// instead of panicking on the nonce slice.
func TestAES256DecryptShortCiphertext(t *testing.T) {
	enc := New256GCMEncryptor()
	key := testKey(t)
	for n := 0; n < 12+16; n++ {
		_, err := enc.Decrypt(testNS, key, make([]byte, n))
		if !errors.Is(err, core.ErrDecryptionFailure) {
			t.Fatalf("len %d: expect ErrDecryptionFailure, got %v", n, err)
		}
	}
}

// FuzzDecrypt: arbitrary input never panics, and only the exact ciphertext
// that was produced decrypts.
func FuzzDecrypt(f *testing.F) {
	enc := New256GCMEncryptor()
	key := testKey(f)
	const plain = "fuzz plaintext"
	valid, err := enc.Encrypt(testNS, key, plain)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(valid)
	f.Add([]byte{1, 2, 3}) // the PE-03 crash input
	f.Add(valid[:28])
	f.Fuzz(func(t *testing.T, in []byte) {
		got, err := enc.Decrypt(testNS, key, in)
		if err == nil && (!bytes.Equal(in, valid) || got != plain) {
			t.Fatalf("forged ciphertext accepted: %q", got)
		}
	})
}
