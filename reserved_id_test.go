package privacy

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/ln80/privacy-engine/core"
	"github.com/ln80/privacy-engine/memory"
)

// V12 regression: IDs starting with "@" belong to the library (the vault key
// is "@vault") and are refused wherever a caller names a subject, so no caller
// can encrypt under, forget, recover or derive from an internal key.
func TestReservedSubjectIDsAreRefused(t *testing.T) {
	ctx := context.Background()
	eng := memory.NewKeyEngine()
	p := NewProtector("tenant-v12", eng)

	calls := map[string]func(id string) error{
		"Encrypt": func(id string) error { return p.Encrypt(ctx, &Profile{UserID: id, Fullname: "x"}) },
		"Forget":  func(id string) error { return p.Forget(ctx, id) },
		"Recover": func(id string) error { return p.Recover(ctx, id) },
		"EncryptStream": func(id string) error {
			_, err := p.EncryptStream(ctx, id, strings.NewReader("x"))
			return err
		},
		"DecryptStream": func(id string) error {
			_, err := p.DecryptStream(ctx, id, strings.NewReader("x"))
			return err
		},
		"DeriveSubjectKey": func(id string) error {
			_, err := p.DeriveSubjectKey(ctx, id, "purpose")
			return err
		},
	}
	for name, call := range calls {
		for _, id := range []string{"@vault", "@anything"} {
			if err := call(id); !errors.Is(err, ErrReservedSubjectID) {
				t.Fatalf("%s(%q): expect ErrReservedSubjectID, got %v", name, id, err)
			}
		}
	}

	// Nothing was created or changed for the reserved ID.
	if _, missing, _ := eng.GetKeys(ctx, "tenant-v12", []string{"@vault", "@anything"}); missing["@vault"] != core.StateUnknown || missing["@anything"] != core.StateUnknown {
		t.Fatalf("expect no key created for reserved IDs, got %v", missing)
	}

	// A field value naming a reserved subject is refused on Decrypt too.
	pf := &Profile{UserID: "u1", Fullname: encodeWireValue(wireValue{subjectID: "@vault", alg: 1, keyVersion: 1, ciphertext: make([]byte, 40)})}
	if err := p.Decrypt(ctx, pf); !errors.Is(err, ErrReservedSubjectID) {
		t.Fatalf("Decrypt: expect ErrReservedSubjectID, got %v", err)
	}

	// Ordinary IDs, including ones containing "@" elsewhere, are unaffected.
	if err := p.Encrypt(ctx, &Profile{UserID: "anon@request-1", Fullname: "x"}); err != nil {
		t.Fatalf("an ID with @ inside must stay valid: %v", err)
	}
}
