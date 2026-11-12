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
			_, err := enc.Encrypt(bind(namespace), tc.key, []byte("plain"))
			if !errors.Is(err, core.ErrEncryptionFailure) {
				t.Fatalf("Encrypt: expect %v, got %v", core.ErrEncryptionFailure, err)
			}
			_, err = enc.Decrypt(bind(namespace), tc.key, []byte("not-a-ciphertext"))
			if !errors.Is(err, core.ErrDecryptionFailure) {
				t.Fatalf("Decrypt: expect %v, got %v", core.ErrDecryptionFailure, err)
			}
			_, err = enc.EncryptStream(bind(namespace), tc.key, strings.NewReader("plain"))
			if !errors.Is(err, core.ErrEncryptionFailure) {
				t.Fatalf("EncryptStream: expect %v, got %v", core.ErrEncryptionFailure, err)
			}
			_, err = enc.DecryptStream(bind(namespace), tc.key, strings.NewReader("cipher"))
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
	cipherTxt, err := enc.Encrypt(bind(namespace), key, []byte(plain))
	if err != nil {
		t.Fatal(err)
	}
	got, err := enc.Decrypt(bind(namespace), key, cipherTxt)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != plain {
		t.Fatalf("expect %q, got %q", plain, got)
	}

	stream, err := enc.EncryptStream(bind(namespace), key, strings.NewReader(plain))
	if err != nil {
		t.Fatal(err)
	}
	encrypted, err := io.ReadAll(stream)
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err := enc.DecryptStream(bind(namespace), key, bytes.NewReader(encrypted))
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
		_, err := enc.Decrypt(bind(testNS), key, make([]byte, n))
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
	valid, err := enc.Encrypt(bind(testNS), key, []byte(plain))
	if err != nil {
		f.Fatal(err)
	}
	f.Add(valid)
	f.Add([]byte{1, 2, 3}) // the PE-03 crash input
	f.Add(valid[:28])
	f.Fuzz(func(t *testing.T, in []byte) {
		got, err := enc.Decrypt(bind(testNS), key, in)
		if err == nil && (!bytes.Equal(in, valid) || string(got) != plain) {
			t.Fatalf("forged ciphertext accepted: %q", got)
		}
	})
}

// The AAD binds the namespace, the key version and the algorithm: a value
// decrypts only under the exact binding it was encrypted with.
func TestAES256FieldBinding(t *testing.T) {
	enc := New256GCMEncryptor()
	key := testKey(t)
	b := core.Binding{Namespace: testNS, KeyVersion: 1}
	sealed, err := enc.Encrypt(b, key, []byte("payload"))
	if err != nil {
		t.Fatal(err)
	}
	if got, err := enc.Decrypt(b, key, sealed); err != nil || string(got) != "payload" {
		t.Fatalf("same binding: got %q, %v", got, err)
	}
	for name, other := range map[string]core.Binding{
		"other namespace":   {Namespace: "tenant-other", KeyVersion: 1},
		"other key version": {Namespace: testNS, KeyVersion: 2},
		"caller-managed":    {Namespace: testNS, KeyVersion: 0},
		"empty namespace":   {KeyVersion: 1},
	} {
		if _, err := enc.Decrypt(other, key, sealed); !errors.Is(err, core.ErrDecryptionFailure) {
			t.Fatalf("%s: expect ErrDecryptionFailure, got %v", name, err)
		}
	}
	if enc.Algorithm() != AlgAES256GCM {
		t.Fatalf("expect algorithm %#x, got %#x", AlgAES256GCM, enc.Algorithm())
	}
}

// Length prefixing keeps two different bindings from sharing AAD bytes.
func TestFieldAADIsUnambiguous(t *testing.T) {
	a, _ := fieldAAD(core.Binding{Namespace: "ab", KeyVersion: 1})
	b, _ := fieldAAD(core.Binding{Namespace: "a", KeyVersion: 1})
	if bytes.Equal(a, b) {
		t.Fatal("distinct bindings produced the same AAD")
	}
	if _, err := fieldAAD(core.Binding{Namespace: strings.Repeat("n", 1<<16)}); err == nil {
		t.Fatal("expect an error for a namespace longer than 65535 bytes")
	}
}
