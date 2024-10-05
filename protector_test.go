package privacy

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/ln80/privacy-engine/core"
	"github.com/ln80/privacy-engine/memory"
	"github.com/ln80/privacy-engine/privacytest"
	sensitive "github.com/ln80/struct-sensitive"
)

func TestProtector_EncryptDecrypt(t *testing.T) {
	ctx := context.Background()

	nspace := "tenant-d195kla"

	p := NewProtector(nspace, memory.NewKeyEngine())

	pf1 := Profile{
		UserID:   "kal5430",
		Fullname: "Idir Moore",
		Gender:   "M",
		Country:  "MA",
		Address: Address{
			Street: "56559 Von Divide",
		},
	}
	opf1 := pf1

	pf2 := Profile{
		UserID:   "aze6590",
		Fullname: "Anna Gibz",
		Gender:   "F",
		Country:  "GB",
	}
	opf2 := pf2

	t.Run("encrypt-decrypt personal data with nonsense values", func(t *testing.T) {
		if err := p.Encrypt(ctx); err != nil {
			t.Fatal("expect err be nil, got", err)
		}

		ignored := StructNotPII{Val: "value"}
		oignored := ignored

		if err := p.Encrypt(ctx, &ignored); err != nil {
			t.Fatal("expect err be nil, got", err)
		}
		if want, got := ignored, oignored; !reflect.DeepEqual(want, got) {
			t.Fatalf("expect %v, %v be equals", want, got)
		}

		if err := p.Encrypt(ctx, &ignored); err != nil {
			t.Fatal("expect err be nil, got", err)
		}
		if want, got := ignored, oignored; !reflect.DeepEqual(want, got) {
			t.Fatalf("expect %v, %v be equals", want, got)
		}
	})

	t.Run("encrypt-decrypt unsupported type value", func(t *testing.T) {
		tcs := []any{
			nil, pf1, pf2, make(map[string]any),
			[]byte(""), "primitive txt", 23, func() {}, make(chan int),
		}

		want := sensitive.ErrUnsupportedType
		for _, value := range tcs {
			if err := p.Encrypt(ctx, value); !errors.Is(err, want) {
				t.Errorf("expect err be %v, got %v", want, err)
			}
			if err := p.Decrypt(ctx, value); !errors.Is(err, want) {
				t.Errorf("expect err be %v, got %v", want, err)
			}
		}
	})

	t.Run("encrypt-decrypt unsupported field type", func(t *testing.T) {
		tcs := []any{
			&StructSubjectInvalidType{Val1: "id", Val2: 30},
		}

		want := sensitive.ErrUnsupportedFieldType
		for _, value := range tcs {
			if err := p.Encrypt(ctx, value); !errors.Is(err, want) {
				t.Errorf("expect err be %v, got %v", want, err)
			}
			if err := p.Decrypt(ctx, value); !errors.Is(err, want) {
				t.Errorf("expect err be %v, got %v", want, err)
			}
		}
	})

	t.Run("encrypt-decrypt personal data with invalid tag configuration", func(t *testing.T) {
		tcs := []struct {
			val        any
			Encryptorr error
			decryptErr error
		}{
			{
				val:        &StructSubjectNotFound{},
				Encryptorr: sensitive.ErrInvalidTagConfiguration,
			},
			{
				val:        &StructMultipleSubjects{Val1: "id", Val2: "otherId"},
				Encryptorr: sensitive.ErrInvalidTagConfiguration,
				decryptErr: sensitive.ErrInvalidTagConfiguration,
			},
		}

		for _, tc := range tcs {
			if err := p.Encrypt(ctx, tc.val); !errors.Is(err, tc.Encryptorr) {
				t.Errorf("expect err be '%v', got '%v'", tc.Encryptorr, err)
			}
			if err := p.Decrypt(ctx, tc.val); !errors.Is(err, tc.decryptErr) {
				t.Errorf("expect err be '%v', got '%v'", tc.decryptErr, err)
			}
		}
	})

	t.Run("encrypt-decrypt personal data with success", func(t *testing.T) {
		if err := p.Encrypt(ctx, &pf1, &pf2); err != nil {
			t.Fatal("expect err be nil, got", err)
		}

		// assert personal data are mutated (to a cipher text)
		if want, got := opf1.Fullname, pf1.Fullname; reflect.DeepEqual(want, got) {
			t.Fatalf("expect %v, %v not be equals", want, got)
		}
		if want, got := opf1.Address, pf1.Address; reflect.DeepEqual(want, got) {
			t.Fatalf("expect %v, %v not be equals", want, got)
		}
		if want, got := opf2.Fullname, pf2.Fullname; reflect.DeepEqual(want, got) {
			t.Fatalf("expect %v, %v not be equals", want, got)
		}

		// assert personal data are mutated back to their plain text values
		if err := p.Decrypt(ctx, &pf1, &pf2); err != nil {
			t.Fatal("expect err be nil, got", err)
		}
		if want, got := opf1.Fullname, pf1.Fullname; !reflect.DeepEqual(want, got) {
			t.Fatalf("expect %v, %v be equals", want, got)
		}
		if want, got := opf1.Address, pf1.Address; !reflect.DeepEqual(want, got) {
			t.Fatalf("expect %v, %v be equals", want, got)
		}
		if want, got := opf2.Fullname, pf2.Fullname; !reflect.DeepEqual(want, got) {
			t.Fatalf("expect %v, %v be equals", want, got)
		}
	})

	t.Run("encrypt-decrypt atomicity", func(t *testing.T) {

		t.Skip("skipping this test as atomicity support has been dropped by now.")

		enc := &privacytest.UnstableEncryptorMock{
			PointOfFailure: 2,
		}

		p := NewProtector(nspace, memory.NewKeyEngine(), func(pc *ProtectorConfig) {
			pc.Encryptor = enc
		})

		pf1 := Profile{
			UserID:   "kal5430",
			Fullname: "Idir Moore",
			Gender:   "M",
			Country:  "MA",
		}
		opf1 := pf1

		pf2 := Profile{
			UserID:   "hjl5a00",
			Fullname: "Jav Koelpin",
			Gender:   "M",
			Country:  "DE",
		}
		opf2 := pf2

		if want, err := core.ErrEncryptionFailure, p.Encrypt(ctx, &pf1, &pf2); !errors.Is(err, want) {
			t.Fatalf("expect err be %v, got %v", want, err)
		}

		// expect pii structs to be different from originals
		if want, got := opf1, pf1; !reflect.DeepEqual(want, got) {
			t.Fatalf("expect %v, %v be equals", want, got)
		}
		if want, got := opf2, pf2; !reflect.DeepEqual(want, got) {
			t.Fatalf("expect %v, %v be equals", want, got)
		}

		// make sure not to fail encryption
		enc.PointOfFailure = 1000
		enc.ResetCounter()

		if err := p.Encrypt(ctx, &pf1, &pf2); err != nil {
			t.Fatal("expect err be nil, got", err)
		}

		enc.PointOfFailure = 2
		enc.ResetCounter()

		err := p.Decrypt(ctx, &pf1, &pf2)
		if err == nil {
			t.Fatal("expect err be not nil")
		}

		// expect none of pii structs to be decrypted back to normal
		if want, got := opf1, pf1; reflect.DeepEqual(want, got) {
			t.Fatalf("expect %v, %v not be equals", want, got)
		}
		if want, got := opf2, pf2; reflect.DeepEqual(want, got) {
			t.Fatalf("expect %v, %v not be equals", want, got)
		}
	})

	t.Run("encrypt-decrypt idempotency", func(t *testing.T) {
		p := NewProtector(nspace, memory.NewKeyEngine())

		pf1 := Profile{
			UserID:   "kal5430",
			Fullname: "Idir Moore",
			Gender:   "M",
			Country:  "MA",
		}

		// successfully encrypt pii struct & save a copy of encrypted struct
		if err := p.Encrypt(ctx, &pf1); err != nil {
			t.Fatal("expect err be nil, got", err)
		}
		encpf1 := pf1

		// try to re-encrypt & make sure that pii field values remain the same
		if err := p.Encrypt(ctx, &pf1); err != nil {
			t.Fatal("expect err be nil, got", err)
		}
		if want, got := encpf1, pf1; !reflect.DeepEqual(want, got) {
			t.Fatalf("expect %v, %v be equals", want, got)
		}

		// same logic applies to decrypt...
		if err := p.Decrypt(ctx, &pf1); err != nil {
			t.Fatal("expect err be nil, got", err)
		}
		decpf1 := pf1

		if err := p.Decrypt(ctx, &pf1); err != nil {
			t.Fatal("expect err be nil, got", err)
		}
		if want, got := decpf1, pf1; !reflect.DeepEqual(want, got) {
			t.Fatalf("expect %v, %v be equals", want, got)
		}
	})

	t.Run("crypto-erase personal data", func(t *testing.T) {
		pf := Profile{
			UserID:   "dal5431",
			Fullname: "Idir Moore",
			Gender:   "M",
			Country:  "MA",
		}
		opf := pf

		// assert personal data are encrypted and changed (to a cipher text)
		if err := p.Encrypt(ctx, &pf); err != nil {
			t.Fatal("expect err be nil, got", err)
		}
		if want, got := opf.Fullname, pf.Fullname; reflect.DeepEqual(want, got) {
			t.Fatalf("expect %v, %v not be equals", want, got)
		}
		if val := pf.Fullname; !isWireFormatted(val) {
			t.Fatalf("expect %s be wire formatted and encrypted", val)
		}

		// forget subjectID i.e, forget subjectID's encryption key
		if err := p.Forget(ctx, pf.UserID); err != nil {
			t.Fatal("expect err be nil, got", err)
		}

		// assert personal data can't be decrypted and PIIs are replaced with fallback values
		if err := p.Decrypt(ctx, &pf); err != nil {
			t.Fatal("expect err be nil, got", err)
		}

		if want, got := sensitive.MustFieldTag(pf, "Fullname").Options.Get("replace"), pf.Fullname; !reflect.DeepEqual(want, got) {
			t.Fatalf("expect %v, %v be equals", want, got)
		}
		if want, got := sensitive.MustFieldTag(pf, "Gender").Options.Get("replace"), pf.Gender; !reflect.DeepEqual(want, got) {
			t.Fatalf("expect %v, %v be equals", want, got)
		}

		// assert we can't encrypt new PIIs for a forgotten subjectID
		if want, err := ErrSubjectForgotten, p.Encrypt(ctx, &pf); !errors.Is(err, want) {
			t.Fatalf("expect err be %v, got %v", want, err)
		}

		// succefully recover a subjectID encryption material (optional, Key engine may not support it)
		if err := p.Recover(ctx, pf.UserID); err != nil {
			t.Fatal("expect err be nil, got", err)
		}

		// assert we are back to normal
		if err := p.Encrypt(ctx, &pf); err != nil {
			t.Fatal("expect err be nil, got", err)
		}
		if err := p.Decrypt(ctx, &pf); err != nil {
			t.Fatal("expect err be nil, got", err)
		}
		if want, got := sensitive.MustFieldTag(pf, "Fullname").Options.Get("replace"), pf.Fullname; !reflect.DeepEqual(want, got) {
			t.Fatalf("expect %v, %v be equals", want, got)
		}
		if want, got := sensitive.MustFieldTag(pf, "Gender").Options.Get("replace"), pf.Gender; !reflect.DeepEqual(want, got) {
			t.Fatalf("expect %v, %v be equals", want, got)
		}

		// forget subject for real, and assert we are unable to recover it
		// p2 := NewProtector(nspace, func(pc *ProtectorConfig) {
		// 	pc.Engine = memory.NewKeyEngine()
		// 	pc.GracefulMode = false
		// })

		p.(*protector).GracefulMode = false

		if err := p.Forget(ctx, pf.UserID); err != nil {
			t.Fatal("expect err be nil, got", err)
		}
		if want, err := ErrCannotRecoverSubject, p.Recover(ctx, pf.UserID); !errors.Is(err, want) {
			t.Fatalf("expect err be %v, got %v", want, err)
		}
	})
}

func BenchmarkProtector(b *testing.B) {
	nspace := "tenant-d195kla"

	ctx := context.Background()

	p := NewProtector(nspace, memory.NewKeyEngine())

	b.Run("encrypt", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			pfs := []any{
				&Profile{
					UserID:   "xal5430",
					Fullname: "Idir Moore",
					Gender:   "M",
					Country:  "MA",
				},
				&Profile{
					UserID:   "kal5430",
					Fullname: "Idir Moore",
					Gender:   "M",
					Country:  "MA",
				},
			}
			err := p.Encrypt(ctx, pfs...)
			if err != nil {
				b.Fatal("expect err be nil, got", err)
			}

		}
	})

	b.Run("decrypt", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			b.StopTimer()
			pfs := []any{
				&Profile{
					UserID:   "xal5430",
					Fullname: "Idir Moore",
					Gender:   "M",
					Country:  "MA",
				},
				&Profile{
					UserID:   "kal5430",
					Fullname: "Idir Moore",
					Gender:   "M",
					Country:  "MA",
				},
			}
			err := p.Encrypt(ctx, pfs...)
			if err != nil {
				b.Fatal("expect err be nil, got", err)
			}
			b.StartTimer()

			if err := p.Decrypt(ctx, pfs...); err != nil {
				b.Fatal("expect err be nil, got", err)
			}
		}
	})
}
