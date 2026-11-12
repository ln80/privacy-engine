package privacy

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/ln80/privacy-engine/core"
	"github.com/ln80/privacy-engine/memory"
)

// Step 5 of wire format v2: Encrypt keeps an existing value only when it
// authenticates (PE-05), and Decrypt acts on the key state (PE-10).

func newStateProtector(ns string, eng core.KeyEngine, opts ...func(*ProtectorConfig)) Protector {
	opts = append([]func(*ProtectorConfig){func(pc *ProtectorConfig) { pc.CacheEnabled = false }}, opts...)
	return NewProtector(ns, eng, opts...)
}

func encryptedProfile(t *testing.T, p Protector, subject string) *Profile {
	t.Helper()
	pf := &Profile{UserID: subject, Fullname: "Alice Doe", Gender: "F", Address: Address{Street: "1 Main St"}}
	if err := p.Encrypt(context.Background(), pf); err != nil {
		t.Fatal(err)
	}
	return pf
}

// PE-10: data read in the wrong namespace is an error, never a silent wipe.
func TestDecrypt_WrongNamespaceIsAnError(t *testing.T) {
	ctx := context.Background()
	eng := memory.NewKeyEngine()
	pf := encryptedProfile(t, newStateProtector("tenant-a", eng), "u1")
	sealed := *pf

	t.Run("subject unknown there", func(t *testing.T) {
		got := sealed
		err := newStateProtector("tenant-b", eng).Decrypt(ctx, &got)
		if !errors.Is(err, ErrKeyUnknown) {
			t.Fatalf("expect ErrKeyUnknown, got %v", err)
		}
		if got != sealed {
			t.Fatalf("expect struct untouched, got %+v", got)
		}
	})

	t.Run("subject has its own key there", func(t *testing.T) {
		b := newStateProtector("tenant-b", eng)
		encryptedProfile(t, b, "u1") // creates tenant-b's own key for u1
		got := sealed
		if err := b.Decrypt(ctx, &got); !errors.Is(err, core.ErrDecryptionFailure) {
			t.Fatalf("expect ErrDecryptionFailure, got %v", err)
		}
		if got != sealed {
			t.Fatalf("expect struct untouched, got %+v", got)
		}
	})
}

// A forgotten subject (disabled or deleted key) yields the placeholder: the
// tag's replace= option, else ProtectorConfig.ForgottenValue.
func TestDecrypt_ForgottenSubjectGetsPlaceholder(t *testing.T) {
	ctx := context.Background()
	for name, graceful := range map[string]bool{"disabled": true, "deleted": false} {
		t.Run(name, func(t *testing.T) {
			p := newStateProtector("tenant-forget", memory.NewKeyEngine(), func(pc *ProtectorConfig) {
				pc.GracefulMode = graceful
				pc.ForgottenValue = "[forgotten]"
			})
			pf := encryptedProfile(t, p, "u1")
			if err := p.Forget(ctx, "u1"); err != nil {
				t.Fatal(err)
			}
			if err := p.Decrypt(ctx, pf); err != nil {
				t.Fatal(err)
			}
			if pf.Fullname != "deleted pii" {
				t.Fatalf("tag placeholder: got %q", pf.Fullname)
			}
			if pf.Gender != "[forgotten]" || pf.Address.Street != "[forgotten]" {
				t.Fatalf("ForgottenValue: got %q, %q", pf.Gender, pf.Address.Street)
			}
		})
	}
}

func TestDecrypt_ForgottenValueDefaultsToEmpty(t *testing.T) {
	ctx := context.Background()
	p := newStateProtector("tenant-forget", memory.NewKeyEngine())
	pf := encryptedProfile(t, p, "u1")
	if err := p.Forget(ctx, "u1"); err != nil {
		t.Fatal(err)
	}
	if err := p.Decrypt(ctx, pf); err != nil {
		t.Fatal(err)
	}
	if pf.Gender != "" {
		t.Fatalf("expect empty, got %q", pf.Gender)
	}
}

// A value naming a subject the engine never had is an error on both paths.
func TestUnknownSubjectValue(t *testing.T) {
	ctx := context.Background()
	p := newStateProtector("tenant-unknown", memory.NewKeyEngine())
	pf := encryptedProfile(t, p, "u1")
	v, err := parseWireValue(pf.Gender)
	if err != nil {
		t.Fatal(err)
	}
	v.subjectID = "ghost"
	pf.Gender = encodeWireValue(v)
	before := *pf

	if err := p.Decrypt(ctx, pf); !errors.Is(err, ErrKeyUnknown) {
		t.Fatalf("Decrypt: expect ErrKeyUnknown, got %v", err)
	}
	if *pf != before {
		t.Fatalf("Decrypt changed the struct: %+v", *pf)
	}
	if err := p.Encrypt(ctx, pf); !errors.Is(err, ErrKeyUnknown) {
		t.Fatalf("Encrypt: expect ErrKeyUnknown, got %v", err)
	}
	if *pf != before {
		t.Fatalf("Encrypt changed the struct: %+v", *pf)
	}
}

// PE-05: input that merely looks encrypted is refused, not stored as is.
func TestEncrypt_LookAlikeValueIsRefused(t *testing.T) {
	ctx := context.Background()
	p := newStateProtector("tenant-pe05", memory.NewKeyEngine())
	encryptedProfile(t, p, "u1") // u1 has an active key

	forged := encodeWireValue(wireValue{subjectID: "u1", alg: 1, keyVersion: 1, ciphertext: []byte(strings.Repeat("x", 40))})
	pf := &Profile{UserID: "u1", Fullname: forged, Gender: "F"}
	if err := p.Encrypt(ctx, pf); !errors.Is(err, ErrValueNotAuthentic) {
		t.Fatalf("expect ErrValueNotAuthentic, got %v", err)
	}
	if pf.Fullname != forged || pf.Gender != "F" {
		t.Fatalf("expect struct untouched, got %+v", pf)
	}
}

// A value encrypted in another namespace does not authenticate here.
func TestEncrypt_ValueFromOtherNamespaceIsRefused(t *testing.T) {
	ctx := context.Background()
	eng := memory.NewKeyEngine()
	fromA := encryptedProfile(t, newStateProtector("tenant-a", eng), "u1")
	b := newStateProtector("tenant-b", eng)
	encryptedProfile(t, b, "u1")

	pf := &Profile{UserID: "u1", Fullname: fromA.Fullname}
	if err := b.Encrypt(ctx, pf); !errors.Is(err, ErrValueNotAuthentic) {
		t.Fatalf("expect ErrValueNotAuthentic, got %v", err)
	}
}

func TestEncrypt_Idempotent(t *testing.T) {
	ctx := context.Background()
	p := newStateProtector("tenant-idem", memory.NewKeyEngine())
	pf := encryptedProfile(t, p, "u1")
	first := *pf
	if err := p.Encrypt(ctx, pf); err != nil {
		t.Fatal(err)
	}
	if *pf != first {
		t.Fatalf("second Encrypt changed values: %+v", *pf)
	}
}

// A value copied from subject A into subject B's record keeps following A:
// it is kept by Encrypt, decrypts with A's key, and is shredded by Forget(A).
func TestCopiedValueFollowsItsOwnSubject(t *testing.T) {
	ctx := context.Background()
	p := newStateProtector("tenant-copy", memory.NewKeyEngine(), func(pc *ProtectorConfig) {
		pc.ForgottenValue = "[forgotten]"
	})
	alice := encryptedProfile(t, p, "alice")

	bob := &Profile{UserID: "bob", Fullname: "Bob", Gender: alice.Gender}
	if err := p.Encrypt(ctx, bob); err != nil {
		t.Fatal(err)
	}
	if bob.Gender != alice.Gender {
		t.Fatal("expect the copied value kept as is")
	}

	read := *bob
	if err := p.Decrypt(ctx, &read); err != nil {
		t.Fatal(err)
	}
	if read.Gender != "F" || read.Fullname != "Bob" {
		t.Fatalf("got %+v", read)
	}

	if err := p.Forget(ctx, "alice"); err != nil {
		t.Fatal(err)
	}
	// Re-saving Bob still works: the copied value is shredded, not invalid.
	if err := p.Encrypt(ctx, bob); err != nil {
		t.Fatal(err)
	}
	read = *bob
	if err := p.Decrypt(ctx, &read); err != nil {
		t.Fatal(err)
	}
	if read.Gender != "[forgotten]" || read.Fullname != "Bob" {
		t.Fatalf("got %+v", read)
	}
}

// A forgotten subject's record can be saved again as long as it holds only
// ciphertext; new plaintext for it cannot be encrypted.
func TestEncrypt_ForgottenSubjectRecord(t *testing.T) {
	ctx := context.Background()
	p := newStateProtector("tenant-resave", memory.NewKeyEngine())
	pf := encryptedProfile(t, p, "u1")
	if err := p.Forget(ctx, "u1"); err != nil {
		t.Fatal(err)
	}
	sealed := *pf
	if err := p.Encrypt(ctx, pf); err != nil {
		t.Fatalf("re-save of shredded values: %v", err)
	}
	if *pf != sealed {
		t.Fatalf("expect values unchanged, got %+v", *pf)
	}

	pf.Gender = "M"
	if err := p.Encrypt(ctx, pf); !errors.Is(err, ErrSubjectForgotten) {
		t.Fatalf("expect ErrSubjectForgotten, got %v", err)
	}
}

func TestDecrypt_TamperedValueIsAnError(t *testing.T) {
	ctx := context.Background()
	p := newStateProtector("tenant-tamper", memory.NewKeyEngine())
	pf := encryptedProfile(t, p, "u1")
	v, err := parseWireValue(pf.Gender)
	if err != nil {
		t.Fatal(err)
	}
	v.ciphertext[len(v.ciphertext)-1] ^= 1
	pf.Gender = encodeWireValue(v)
	before := *pf
	if err := p.Decrypt(ctx, pf); !errors.Is(err, core.ErrDecryptionFailure) {
		t.Fatalf("expect ErrDecryptionFailure, got %v", err)
	}
	if *pf != before {
		t.Fatalf("expect struct untouched, got %+v", *pf)
	}
}

// Streams and key derivation tell a forgotten subject from an unknown one.
func TestStreamsAndDeriveReportKeyState(t *testing.T) {
	ctx := context.Background()
	p := newStateProtector("tenant-streams", memory.NewKeyEngine())
	encryptedProfile(t, p, "u1")
	if err := p.Forget(ctx, "u1"); err != nil {
		t.Fatal(err)
	}
	for subject, want := range map[string]error{"u1": ErrSubjectForgotten, "ghost": ErrKeyUnknown} {
		if _, err := p.DecryptStream(ctx, subject, strings.NewReader("x")); !errors.Is(err, want) {
			t.Fatalf("DecryptStream(%s): expect %v, got %v", subject, want, err)
		}
		if _, err := p.DeriveSubjectKey(ctx, subject, "purpose"); !errors.Is(err, want) {
			t.Fatalf("DeriveSubjectKey(%s): expect %v, got %v", subject, want, err)
		}
	}
}

// Error messages carry field paths, never values or subject IDs.
func TestKeyStateErrorsDoNotLeak(t *testing.T) {
	ctx := context.Background()
	eng := memory.NewKeyEngine()
	pf := encryptedProfile(t, newStateProtector("tenant-a", eng), "secret-subject-id")
	err := newStateProtector("tenant-b", eng).Decrypt(ctx, pf)
	if err == nil {
		t.Fatal("expect an error")
	}
	if msg := err.Error(); strings.Contains(msg, "secret-subject-id") || strings.Contains(msg, "Alice") {
		t.Fatalf("error leaks data: %q", msg)
	}
	var perr Error
	if !errors.As(err, &perr) || perr.Subject() != "secret-subject-id" {
		t.Fatalf("expect the subject available through Error.Subject, got %v", err)
	}
}
