package privacy

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/ln80/privacy-engine/core"
	"github.com/ln80/privacy-engine/memory"
)

// R-CS-8: a stored value that was changed in any way never decrypts to
// plaintext, and the struct is never partly changed.

// tamperFixture is a profile of u1 encrypted in ns, with a second subject u2
// known to the same engine, so that a changed subject can name a real key.
func tamperFixture(t *testing.T) (*Protector, Profile) {
	t.Helper()
	p := newStateProtector("ns", memory.NewKeyEngine())
	encryptedProfile(t, p, "u2")
	return p, *encryptedProfile(t, p, "u1")
}

// checkDecrypt decrypts a copy of pf whose Fullname is forged, and checks
// that the forged value is never turned into plaintext.
func checkDecrypt(t *testing.T, p *Protector, pf Profile, forged, what string) {
	t.Helper()
	pf.Fullname = forged
	before := pf
	err := p.Decrypt(context.Background(), &pf)
	if err != nil {
		if pf != before {
			t.Fatalf("%s: Decrypt failed with %v but changed the struct", what, err)
		}
		return
	}
	// Accepted only as a string that is not a field value: left as is.
	if pf.Fullname != forged {
		t.Fatalf("%s: a forged value decrypted to %q", what, pf.Fullname)
	}
}

// checkEncrypt encrypts a copy of pf whose Fullname is forged: Encrypt must
// never keep a forged value as if it were authentic.
func checkEncrypt(t *testing.T, p *Protector, pf Profile, forged, what string) {
	t.Helper()
	pf.Fullname = forged
	before := pf
	err := p.Encrypt(context.Background(), &pf)
	if err != nil {
		if pf != before {
			t.Fatalf("%s: Encrypt failed with %v but changed the struct", what, err)
		}
		return
	}
	if pf.Fullname == forged {
		t.Fatalf("%s: Encrypt kept a forged value as authentic", what)
	}
}

// Every character of the text form, replaced by characters that keep it
// well-formed (base64url) or break its structure.
func TestTamper_FieldValueText(t *testing.T) {
	p, pf := tamperFixture(t)
	orig := pf.Fullname
	for i := range len(orig) {
		for _, c := range []byte{'A', 'I', '_', '-', '.', '='} {
			if orig[i] == c {
				continue
			}
			forged := orig[:i] + string(c) + orig[i+1:]
			checkDecrypt(t, p, pf, forged, "text edit")
			checkEncrypt(t, p, pf, forged, "text edit")
		}
	}
	for n := range len(orig) {
		checkDecrypt(t, p, pf, orig[:n], "text cut")
	}
}

// Every bit of every payload byte: algorithm, key version, nonce,
// ciphertext and tag. All must fail, with the struct untouched.
func TestTamper_FieldValuePayload(t *testing.T) {
	p, pf := tamperFixture(t)
	v, err := parseWireValue(pf.Fullname)
	if err != nil {
		t.Fatal(err)
	}
	// payload = alg (1) | keyVersion (4) | ciphertext
	for i := range 5 + len(v.ciphertext) {
		for bit := range 8 {
			forged := wireValue{subjectID: v.subjectID, alg: v.alg, keyVersion: v.keyVersion, ciphertext: append([]byte(nil), v.ciphertext...)}
			switch {
			case i == 0:
				forged.alg ^= 1 << bit
			case i < 5:
				forged.keyVersion ^= 1 << (bit + 8*(4-i))
			default:
				forged.ciphertext[i-5] ^= 1 << bit
			}
			s := encodeWireValue(forged)
			pf2 := pf
			pf2.Fullname = s
			if err := p.Decrypt(context.Background(), &pf2); err == nil {
				t.Fatalf("payload byte %d bit %d: expect an error", i, bit)
			}
			checkDecrypt(t, p, pf, s, "payload flip")
		}
	}
	for n := range len(v.ciphertext) {
		forged := v
		forged.ciphertext = v.ciphertext[:n]
		checkDecrypt(t, p, pf, encodeWireValue(forged), "ciphertext cut")
	}
	forged := v
	forged.ciphertext = append(append([]byte(nil), v.ciphertext...), 0)
	checkDecrypt(t, p, pf, encodeWireValue(forged), "ciphertext extended")
}

// A value relabelled with another subject: that subject's key does not
// open it, and an unknown subject is an error, not a placeholder.
func TestTamper_FieldValueSubject(t *testing.T) {
	p, pf := tamperFixture(t)
	v, err := parseWireValue(pf.Fullname)
	if err != nil {
		t.Fatal(err)
	}
	for subject, want := range map[string]error{"u2": core.ErrDecryptionFailure, "never-seen": ErrKeyUnknown} {
		forged := v
		forged.subjectID = subject
		pf2 := pf
		pf2.Fullname = encodeWireValue(forged)
		before := pf2
		if err := p.Decrypt(context.Background(), &pf2); !errors.Is(err, want) {
			t.Fatalf("relabelled to %s: expect %v, got %v", subject, want, err)
		}
		if pf2 != before {
			t.Fatalf("relabelled to %s: the struct changed", subject)
		}
	}
}

// Accepted risk (wire-format.md §7): two values of one subject can be
// swapped. This pins the documented behaviour; binding fields would change it.
func TestTamper_FieldSwapWithinSubjectIsAcceptedRisk(t *testing.T) {
	p, pf := tamperFixture(t)
	pf.Fullname, pf.Gender = pf.Gender, pf.Fullname
	if err := p.Decrypt(context.Background(), &pf); err != nil || pf.Fullname != "F" || pf.Gender != "Alice Doe" {
		t.Fatalf("expect the swap to go undetected, got %+v, %v", pf, err)
	}
}

// tamperingTokens hands out records changed by mutate, as a token store
// written to by an attacker would.
type tamperingTokens struct {
	core.TokenEngine
	mutate func(recs map[string]core.VaultRecord)
}

func (e tamperingTokens) GetRecords(ctx context.Context, ns string, tokens []string) (map[string]core.VaultRecord, error) {
	recs, err := e.TokenEngine.GetRecords(ctx, ns, tokens)
	if err == nil {
		e.mutate(recs)
	}
	return recs, err
}

func (e tamperingTokens) ListTokens(ctx context.Context, ns string, q core.ListTokensQuery) (*core.ListRecordsResult, error) {
	page, err := e.TokenEngine.ListTokens(ctx, ns, q)
	if err == nil {
		recs := map[string]core.VaultRecord{}
		for _, r := range page.Records {
			recs[r.Token] = r
		}
		e.mutate(recs)
		for i, r := range page.Records {
			page.Records[i] = recs[r.Token]
		}
	}
	return page, err
}

// R-TK-4: a sealed value changed or moved in the token store never opens.
func TestTamper_VaultRecords(t *testing.T) {
	ctx := t.Context()
	keys, store := memory.NewKeyEngine(), memory.NewTokenEngine()
	clean := NewProtector("ns", keys, WithTokenEngine(store))
	res, err := clean.Tokenize(ctx, TokenDataSlice("alice@example.com", "bob@example.com"))
	if err != nil {
		t.Fatal(err)
	}
	a, b := res.Get("alice@example.com").Token, res.Get("bob@example.com").Token
	recs, err := store.GetRecords(ctx, "ns", []string{a})
	if err != nil {
		t.Fatal(err)
	}
	size := len(recs[a].Sealed)

	attacks := map[string]func(map[string]core.VaultRecord){
		"swap sealed values": func(m map[string]core.VaultRecord) {
			ra, rb := m[a], m[b]
			ra.Sealed, rb.Sealed = rb.Sealed, ra.Sealed
			m[a], m[b] = ra, rb
		},
		"truncate": func(m map[string]core.VaultRecord) {
			r := m[a]
			r.Sealed = r.Sealed[:len(r.Sealed)-1]
			m[a] = r
		},
	}
	for i := range size {
		attacks[fmt.Sprintf("flip byte %d", i)] = func(m map[string]core.VaultRecord) {
			r := m[a]
			r.Sealed = append([]byte(nil), r.Sealed...)
			r.Sealed[i] ^= 0x01
			m[a] = r
		}
	}
	for name, mutate := range attacks {
		p := NewProtector("ns", keys, WithTokenEngine(tamperingTokens{TokenEngine: store, mutate: mutate}))
		vals, err := p.Detokenize(ctx, []string{a, b})
		if !errors.Is(err, ErrDetokenizeFailure) || vals != nil {
			t.Fatalf("Detokenize, %s: expect ErrDetokenizeFailure and no values, got %v, %v", name, vals, err)
		}
		page, err := p.ListTokens(ctx, core.ListTokensQuery{})
		if !errors.Is(err, ErrListTokensFailure) || page != nil {
			t.Fatalf("ListTokens, %s: expect ErrListTokensFailure and nothing, got %v, %v", name, page, err)
		}
	}
}
