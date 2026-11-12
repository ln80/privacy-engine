package privacy

import (
	"context"
	"testing"

	"github.com/ln80/privacy-engine/memory"
)

// PE-03 regression through the public API: a field value with a valid wire
// shape but a 3-byte ciphertext ("u1" is base64 "dTE=") must fail Decrypt,
// not crash the process, and must leave the field untouched.
func TestProtector_DecryptShortCiphertext(t *testing.T) {
	ctx := context.Background()
	p := NewProtector("tenant-pe03", memory.NewKeyEngine())

	pf := &Profile{UserID: "u1", Fullname: "Alice"}
	if err := p.Encrypt(ctx, pf); err != nil { // creates u1's key
		t.Fatal(err)
	}

	const forged = "ENC..dTE=.AQID"
	pf.Fullname = forged
	if err := p.Decrypt(ctx, pf); err == nil {
		t.Fatal("expect an error for a short ciphertext")
	}
	if pf.Fullname != forged {
		t.Fatalf("field changed on failure: %q", pf.Fullname)
	}
}
