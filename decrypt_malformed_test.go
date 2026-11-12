package privacy

import (
	"context"
	"errors"
	"testing"

	"github.com/ln80/privacy-engine/memory"
)

// PE-03 regression through the public API: a field value with a valid wire
// shape but a 3-byte ciphertext must fail Decrypt, not crash the process, and
// must leave the field untouched.
func TestProtector_DecryptShortCiphertext(t *testing.T) {
	ctx := context.Background()
	p := NewProtector("tenant-pe03", memory.NewKeyEngine())

	pf := &Profile{UserID: "u1", Fullname: "Alice"}
	if err := p.Encrypt(ctx, pf); err != nil { // creates u1's key
		t.Fatal(err)
	}

	forged := encodeWireValue(wireValue{subjectID: "u1", alg: 1, keyVersion: 1, ciphertext: []byte{1, 2, 3}})
	pf.Fullname = forged
	if err := p.Decrypt(ctx, pf); err == nil {
		t.Fatal("expect an error for a short ciphertext")
	}
	if pf.Fullname != forged {
		t.Fatalf("field changed on failure: %q", pf.Fullname)
	}
}

// A value with an algorithm or key version this protector does not know is an
// error, checked before the key lookup, and the field is left untouched.
func TestProtector_DecryptRejectsUnknownHeader(t *testing.T) {
	ctx := context.Background()
	p := NewProtector("tenant-header", memory.NewKeyEngine())

	pf := &Profile{UserID: "u1", Fullname: "Alice"}
	if err := p.Encrypt(ctx, pf); err != nil {
		t.Fatal(err)
	}
	valid, err := parseWireValue(pf.Fullname)
	if err != nil {
		t.Fatal(err)
	}

	for name, edit := range map[string]func(*wireValue){
		"unknown algorithm":   func(v *wireValue) { v.alg = 0x02 },
		"unknown key version": func(v *wireValue) { v.keyVersion = 2 },
	} {
		t.Run(name, func(t *testing.T) {
			v := valid
			edit(&v)
			forged := encodeWireValue(v)
			pf.Fullname = forged
			if err := p.Decrypt(ctx, pf); !errors.Is(err, ErrInvalidWireFormat) {
				t.Fatalf("expect ErrInvalidWireFormat, got %v", err)
			}
			if pf.Fullname != forged {
				t.Fatalf("field changed on failure: %q", pf.Fullname)
			}
		})
	}
}

// Decrypt must not mistake a v1 value for a v2 one: it is left as is.
func TestProtector_DecryptIgnoresV1Values(t *testing.T) {
	ctx := context.Background()
	p := NewProtector("tenant-v1", memory.NewKeyEngine())
	const v1 = "ENC..dTE=.q2b0Kh37phctoSNql2DUhpOOvIGdLKAqyoV45VQ="
	pf := &Profile{UserID: "u1", Fullname: v1}
	if err := p.Decrypt(ctx, pf); err != nil {
		t.Fatal(err)
	}
	if pf.Fullname != v1 {
		t.Fatalf("expect v1 value left untouched, got %q", pf.Fullname)
	}
}
