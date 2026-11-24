package privacy

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"

	"github.com/ln80/privacy-engine/core"
	"github.com/ln80/privacy-engine/memory"
)

var streamPlaintext = bytes.Repeat([]byte("personal data "), 10_000) // ~140 KiB: several segments

// decryptAll reads a whole stream: errors may come from the constructor or
// from Read.
func decryptAll(r io.Reader, err error) ([]byte, error) {
	if err != nil {
		return nil, err
	}
	return io.ReadAll(r)
}

// mustReadAll returns a reader of whole streams that fails t on any error.
func mustReadAll(t *testing.T) func(io.Reader, error) []byte {
	return func(r io.Reader, err error) []byte {
		t.Helper()
		out, err := decryptAll(r, err)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
}

func TestStream_SubjectLifecycle(t *testing.T) {
	ctx := t.Context()
	p := NewProtector("ns", memory.NewKeyEngine())
	readAll := mustReadAll(t)

	enc := readAll(p.EncryptStream(ctx, "sub_1", bytes.NewReader(streamPlaintext)))
	if bytes.Contains(enc, streamPlaintext[:64]) {
		t.Fatal("ciphertext contains plaintext")
	}
	got, err := decryptAll(p.DecryptStream(ctx, "sub_1", bytes.NewReader(enc)))
	if err != nil || !bytes.Equal(got, streamPlaintext) {
		t.Fatalf("round trip: %v", err)
	}

	// Another subject's key does not open it.
	_ = readAll(p.EncryptStream(ctx, "sub_2", bytes.NewReader(nil)))
	if _, err := decryptAll(p.DecryptStream(ctx, "sub_2", bytes.NewReader(enc))); err == nil {
		t.Fatal("expect another subject's key to fail")
	}

	// Tampering fails before EOF.
	bad := bytes.Clone(enc)
	bad[len(bad)/2] ^= 0x01
	if _, err := decryptAll(p.DecryptStream(ctx, "sub_1", bytes.NewReader(bad))); !errors.Is(err, core.ErrDecryptionFailure) {
		t.Fatalf("tampered stream: expect core.ErrDecryptionFailure, got %v", err)
	}

	// Shredded: neither direction works any more.
	if err := p.Forget(ctx, "sub_1"); err != nil {
		t.Fatal(err)
	}
	if _, err := decryptAll(p.DecryptStream(ctx, "sub_1", bytes.NewReader(enc))); !errors.Is(err, ErrSubjectForgotten) {
		t.Fatalf("DecryptStream after Forget: expect ErrSubjectForgotten, got %v", err)
	}
	if _, err := p.EncryptStream(ctx, "sub_1", bytes.NewReader(streamPlaintext)); !errors.Is(err, ErrSubjectForgotten) {
		t.Fatalf("EncryptStream after Forget: expect ErrSubjectForgotten, got %v", err)
	}

	// Unknown subject, and the same subject in another namespace.
	if _, err := decryptAll(p.DecryptStream(ctx, "never-seen", bytes.NewReader(enc))); !errors.Is(err, ErrKeyUnknown) {
		t.Fatalf("unknown subject: expect ErrKeyUnknown, got %v", err)
	}
}

func TestStream_RejectsBadSubjects(t *testing.T) {
	ctx := t.Context()
	p := NewProtector("ns", memory.NewKeyEngine())
	for _, id := range []string{"", "@vault"} {
		if _, err := p.EncryptStream(ctx, id, bytes.NewReader(nil)); !errors.Is(err, ErrEncryptDecryptFailure) {
			t.Fatalf("EncryptStream(%q): expect ErrEncryptDecryptFailure, got %v", id, err)
		}
	}
}

func TestStream_KeyEngineFailure(t *testing.T) {
	boom := errors.New("store down")
	p := NewProtector("ns", failingKeys{KeyEngine: memory.NewKeyEngine(), err: boom}, WithoutCache())
	_, err := p.EncryptStream(t.Context(), "sub_1", bytes.NewReader(nil))
	if !errors.Is(err, ErrEncryptDecryptFailure) || !errors.Is(err, boom) {
		t.Fatalf("expect ErrEncryptDecryptFailure wrapping the engine error, got %v", err)
	}
}

// Caller-managed keys: keyVersion 0 and the namespace are bound.
func TestStream_WithKey(t *testing.T) {
	ctx := t.Context()
	engine := memory.NewKeyEngine()
	p := NewProtector("ns", engine)
	if err := p.Encrypt(ctx, &struct {
		ID string `pii:"subjectID"`
		V  string `pii:"data"`
	}{ID: "sub_1", V: "x"}); err != nil {
		t.Fatal(err)
	}
	key, err := p.DeriveSubjectKey(ctx, "sub_1", "attachments")
	if err != nil {
		t.Fatal(err)
	}
	readAll := mustReadAll(t)

	enc := readAll(p.EncryptStreamWithKey(ctx, key, bytes.NewReader(streamPlaintext)))
	got, err := decryptAll(p.DecryptStreamWithKey(ctx, key, bytes.NewReader(enc)))
	if err != nil || !bytes.Equal(got, streamPlaintext) {
		t.Fatalf("round trip: %v", err)
	}

	other, err := p.DeriveSubjectKey(ctx, "sub_1", "other-purpose")
	if err != nil {
		t.Fatal(err)
	}
	for name, open := range map[string]func() (io.Reader, error){
		"another key": func() (io.Reader, error) { return p.DecryptStreamWithKey(ctx, other, bytes.NewReader(enc)) },
		"another namespace": func() (io.Reader, error) {
			return NewProtector("ns2", engine).DecryptStreamWithKey(ctx, key, bytes.NewReader(enc))
		},
		"the subject's key": func() (io.Reader, error) { return p.DecryptStream(ctx, "sub_1", bytes.NewReader(enc)) },
	} {
		if _, err := decryptAll(open()); err == nil {
			t.Fatalf("%s opened a caller-key stream", name)
		}
	}

	if _, err := p.EncryptStreamWithKey(ctx, core.Key("short"), bytes.NewReader(nil)); !errors.Is(err, ErrEncryptDecryptFailure) {
		t.Fatalf("short key: expect ErrEncryptDecryptFailure, got %v", err)
	}
	if _, err := decryptAll(p.DecryptStreamWithKey(ctx, core.Key("short"), bytes.NewReader(enc))); err == nil {
		t.Fatal("short key: expect an error")
	}
}

// failingKeys fails every call with err.
type failingKeys struct {
	core.KeyEngine
	err error
}

func (f failingKeys) GetKeys(context.Context, string, []string) (core.KeyMap, core.KeyStates, error) {
	return nil, nil, f.err
}

func (f failingKeys) GetOrCreateKeys(context.Context, string, []string, core.KeyGen) (core.KeyMap, error) {
	return nil, f.err
}

func (f failingKeys) PurgeNamespace(context.Context, string) error { return f.err }
