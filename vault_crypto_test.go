package privacy

import (
	"bytes"
	"context"
	"testing"

	"github.com/ln80/privacy-engine/aes"
)

func testVaultKeys(t testing.TB) vaultKeys {
	t.Helper()
	dek, err := aes.Key256GenFn(context.Background(), "ns", vaultKeyID)
	if err != nil {
		t.Fatal(err)
	}
	k, err := deriveVaultKeys(dek)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestVaultKeysAreSeparated(t *testing.T) {
	k := testVaultKeys(t)
	if bytes.Equal(k.indexKey, k.sealKey) {
		t.Fatal("index and seal keys must differ")
	}
	if _, err := deriveVaultKeys(make([]byte, 16)); err == nil {
		t.Fatal("expect an error for a 16-byte vault key")
	}
	// Deterministic: the same DEK always derives the same keys.
	dek, _ := aes.Key256GenFn(context.Background(), "ns", vaultKeyID)
	a, _ := deriveVaultKeys(dek)
	b, _ := deriveVaultKeys(dek)
	if !bytes.Equal(a.indexKey, b.indexKey) || !bytes.Equal(a.sealKey, b.sealKey) {
		t.Fatal("derivation must be deterministic")
	}
}

func TestBlindIndexIsKeyedAndDeterministic(t *testing.T) {
	k1, k2 := testVaultKeys(t), testVaultKeys(t)
	v := []byte("alice@example.org")
	if !bytes.Equal(k1.blindIndex(v), k1.blindIndex(v)) {
		t.Fatal("same key and value must give the same index")
	}
	if bytes.Equal(k1.blindIndex(v), k2.blindIndex(v)) {
		t.Fatal("another namespace key must give another index")
	}
	if bytes.Equal(k1.blindIndex(v), k1.blindIndex([]byte("bob@example.org"))) {
		t.Fatal("different values must give different indexes")
	}
	if len(k1.blindIndex(v)) != 32 {
		t.Fatal("index must be 32 bytes")
	}
}

func TestVaultSealRoundTripAndBinding(t *testing.T) {
	k := testVaultKeys(t)
	v := []byte("alice@example.org")
	sealed, err := k.seal("ns-a", "sub_1", v)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sealed, v) {
		t.Fatal("sealed value contains the plaintext")
	}
	got, err := k.open("ns-a", "sub_1", sealed)
	if err != nil || !bytes.Equal(got, v) {
		t.Fatalf("round trip: %q, %v", got, err)
	}

	// Moved onto another token or namespace, or opened with another key: refused.
	for name, open := range map[string]func() ([]byte, error){
		"other token":     func() ([]byte, error) { return k.open("ns-a", "sub_2", sealed) },
		"other namespace": func() ([]byte, error) { return k.open("ns-b", "sub_1", sealed) },
		"other key":       func() ([]byte, error) { return testVaultKeys(t).open("ns-a", "sub_1", sealed) },
	} {
		if _, err := open(); err == nil {
			t.Fatalf("%s: expect authentication failure", name)
		}
	}
	// Length-prefixed AAD: ("ab", "c") and ("a", "bc") differ.
	s2, _ := k.seal("ab", "c", v)
	if _, err := k.open("a", "bc", s2); err == nil {
		t.Fatal("ambiguous AAD accepted")
	}
}

func TestVaultOpenRejectsMalformed(t *testing.T) {
	k := testVaultKeys(t)
	sealed, _ := k.seal("ns", "t", []byte("v"))
	for i := range sealed {
		bad := bytes.Clone(sealed)
		bad[i] ^= 1
		if _, err := k.open("ns", "t", bad); err == nil {
			t.Fatalf("bit flip at %d accepted", i)
		}
	}
	for n := 0; n < 1+vaultNonceSize+vaultTagSize; n++ {
		if _, err := k.open("ns", "t", make([]byte, n)); err == nil {
			t.Fatalf("%d-byte input accepted", n)
		}
	}
}

func FuzzVaultOpen(f *testing.F) {
	k := testVaultKeys(f)
	valid, _ := k.seal("ns", "tok", []byte("alice@example.org"))
	f.Add(valid)
	f.Add([]byte{1})
	f.Fuzz(func(t *testing.T, in []byte) {
		got, err := k.open("ns", "tok", in)
		if err == nil && (!bytes.Equal(in, valid) || string(got) != "alice@example.org") {
			t.Fatalf("forged sealed value accepted: %q", got)
		}
	})
}

func TestVaultKeysZero(t *testing.T) {
	k := testVaultKeys(t)
	k.zero()
	if !bytes.Equal(k.indexKey, make([]byte, 32)) || !bytes.Equal(k.sealKey, make([]byte, 32)) {
		t.Fatal("zero must wipe both derived keys")
	}
}
