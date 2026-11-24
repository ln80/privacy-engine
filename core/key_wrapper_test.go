package core

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestBindDataKey(t *testing.T) {
	dek := Key(bytes.Repeat([]byte{0x42}, 32))
	p, err := BindDataKey(dek, "ns", "sub_1")
	if err != nil {
		t.Fatal(err)
	}
	if len(p) != BoundDataKeySize || BoundDataKeySize%8 != 0 {
		t.Fatalf("payload is %d bytes, want %d (a multiple of 8)", len(p), BoundDataKeySize)
	}
	got, err := UnbindDataKey(p, "ns", "sub_1")
	if err != nil || !bytes.Equal(got, dek) {
		t.Fatalf("round trip: %v", err)
	}
	got[0] ^= 1
	if again, _ := UnbindDataKey(p, "ns", "sub_1"); !bytes.Equal(again, dek) {
		t.Fatal("the returned key shares memory with the payload")
	}

	refused := func(payload []byte, ns, id, what string) {
		t.Helper()
		if k, err := UnbindDataKey(payload, ns, id); !errors.Is(err, ErrKeyBinding) || k != nil {
			t.Fatalf("%s: expect ErrKeyBinding and no key, got %v", what, err)
		}
	}
	refused(p, "other", "sub_1", "another namespace")
	refused(p, "ns", "sub_2", "another key ID")
	refused(p[:len(p)-1], "ns", "sub_1", "a short payload")
	refused(append(bytes.Clone(p), 0), "ns", "sub_1", "a long payload")
	for i := range 1 + bindingDigest { // version and digest bytes
		bad := bytes.Clone(p)
		bad[i] ^= 0x01
		refused(bad, "ns", "sub_1", "an altered header")
	}

	// Length-prefixed: ("ab", "c") and ("a", "bc") differ.
	ab, _ := BindDataKey(dek, "ab", "c")
	refused(ab, "a", "bc", "an ambiguous binding")
}

func TestBindDataKeyRefusesBadInput(t *testing.T) {
	if _, err := BindDataKey(make(Key, 16), "ns", "a"); err == nil {
		t.Fatal("expect a 16-byte key refused")
	}
	long := strings.Repeat("x", 0x10000)
	if _, err := BindDataKey(make(Key, 32), long, "a"); err == nil {
		t.Fatal("expect a namespace over 65535 bytes refused")
	}
	if _, err := UnbindDataKey(make([]byte, BoundDataKeySize), "ns", long); err == nil {
		t.Fatal("expect a key ID over 65535 bytes refused")
	}
}
