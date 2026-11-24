package memory

import (
	"strings"
	"testing"

	"github.com/ln80/privacy-engine/privacytest"
)

func TestKeyWrapper(t *testing.T) {
	privacytest.TestKeyWrapper(t, NewKeyWrapper())
}

func TestKeyWrapperRefusesBadInput(t *testing.T) {
	ctx := t.Context()
	w := NewKeyWrapper()
	long := strings.Repeat("x", 0x10000)
	if _, _, err := w.GenerateKey(ctx, long, "a"); err == nil {
		t.Fatal("expect a namespace over 65535 bytes refused")
	}
	if _, err := w.UnwrapKey(ctx, "ns", long, []byte("blob")); err == nil {
		t.Fatal("expect a key ID over 65535 bytes refused")
	}
	if _, err := w.UnwrapKey(ctx, "ns", "a", []byte("short")); err == nil {
		t.Fatal("expect a blob shorter than nonce and tag refused")
	}
	// Two wrappers have different KEKs: one cannot unwrap the other's keys.
	_, wrapped, err := w.GenerateKey(ctx, "ns", "a")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewKeyWrapper().UnwrapKey(ctx, "ns", "a", wrapped); err == nil {
		t.Fatal("expect another KEK to fail")
	}
}
