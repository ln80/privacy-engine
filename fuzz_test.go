package privacy

import (
	"context"
	"testing"

	"github.com/ln80/privacy-engine/memory"
)

// fuzzFixture holds a protector and three genuine values: one of an active
// subject, one of another active subject, one of a forgotten subject.
type fuzzFixture struct {
	p                        *Protector
	active, other, forgotten string
}

func newFuzzFixture(f *testing.F) fuzzFixture {
	f.Helper()
	ctx := context.Background()
	p := NewProtector("ns", memory.NewKeyEngine(), WithoutCache())
	enc := func(id, text string) string {
		n := note{ID: id, Text: text}
		if err := p.Encrypt(ctx, &n); err != nil {
			f.Fatal(err)
		}
		return n.Text
	}
	fx := fuzzFixture{p: p, active: enc("sub_1", "secret"), other: enc("sub_2", "other"), forgotten: enc("sub_3", "gone")}
	if err := p.Forget(ctx, "sub_3"); err != nil {
		f.Fatal(err)
	}
	for _, s := range []string{fx.active, fx.other, fx.forgotten, fx.active[:len(fx.active)-1], "ENC.", "ENC.c3ViXzE.", "", "plain text"} {
		f.Add(s)
	}
	return fx
}

// namesForgotten reports whether s is a well-formed value of the forgotten
// subject. Its key is gone, so it cannot be authenticated: any such value is
// shredded, and decrypts to the placeholder. Fuzz workers build their own
// fixture, so a seed from another process is one of them.
func namesForgotten(s string) bool {
	v, err := parseWireValue(s)
	return err == nil && v.subjectID == "sub_3" && v.alg == 0x01 && v.keyVersion == subjectKeyVersion
}

// Decrypt of any string: no panic, the struct untouched on error, and only
// genuine values, or shredded ones, are ever changed.
func FuzzDecryptField(f *testing.F) {
	fx := newFuzzFixture(f)
	f.Fuzz(func(t *testing.T, s string) {
		n := note{ID: "sub_1", Text: s}
		err := fx.p.Decrypt(context.Background(), &n)
		switch {
		case n.Text == s:
		case err != nil:
			t.Fatalf("Decrypt failed with %v but changed the field", err)
		case s == fx.active && n.Text == "secret",
			s == fx.other && n.Text == "other",
			namesForgotten(s) && n.Text == "forgotten":
		default:
			t.Fatalf("%q decrypted to %q", s, n.Text)
		}
	})
}

// Encrypt of any string: no panic, and whatever Encrypt accepts decrypts
// back to it, unless it was a genuine value, which is kept as is.
func FuzzEncryptField(f *testing.F) {
	fx := newFuzzFixture(f)
	f.Fuzz(func(t *testing.T, s string) {
		ctx := context.Background()
		n := note{ID: "sub_1", Text: s}
		if err := fx.p.Encrypt(ctx, &n); err != nil {
			if n.Text != s {
				t.Fatalf("Encrypt failed with %v but changed the field", err)
			}
			return
		}
		if s == fx.active || s == fx.other || namesForgotten(s) {
			if n.Text != s {
				t.Fatal("Encrypt re-encrypted a genuine or shredded value")
			}
			return
		}
		if s != "" && n.Text == s {
			t.Fatalf("Encrypt kept %q as is", s)
		}
		if err := fx.p.Decrypt(ctx, &n); err != nil || n.Text != s {
			t.Fatalf("round trip of %q gave %q, %v", s, n.Text, err)
		}
	})
}
