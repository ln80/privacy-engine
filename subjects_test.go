package privacy

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/ln80/privacy-engine/memory"
	sensitive "github.com/ln80/struct-sensitive"
)

type subjAuthor struct {
	Subject string `pii:"subjectID"`
	Email   string `pii:"data,replace=forgotten"`
}

// A record whose payload belongs to the record and whose embedded author's
// email belongs to the author.
type subjRecord struct {
	ID string `pii:"subjectID"`
	subjAuthor
	Payload string `pii:"data,replace=deleted"`
}

type subjMember struct {
	ID    string `pii:"subjectID"`
	Email string `pii:"data"`
}

type subjGroup struct {
	Members []subjMember `pii:"dive"`
}

func newSubjRecord() *subjRecord {
	return &subjRecord{ID: "rec-1", subjAuthor: subjAuthor{Subject: "author-1", Email: "a@b.c"}, Payload: "body"}
}

func TestEncrypt_SingleSubjectByDefault(t *testing.T) {
	ctx := context.Background()
	p := NewProtector("ns", memory.NewKeyEngine())

	rec := newSubjRecord()
	if err := p.Encrypt(ctx, rec); !errors.Is(err, sensitive.ErrMultipleSubjectID) {
		t.Fatalf("Encrypt() err = %v, want ErrMultipleSubjectID", err)
	}
	if rec.Payload != "body" || rec.Email != "a@b.c" {
		t.Fatal("a refused Encrypt changed the record")
	}

	group := &subjGroup{Members: []subjMember{{ID: "u1", Email: "a@x"}, {ID: "u2", Email: "b@x"}}}
	if err := p.Encrypt(ctx, group); !errors.Is(err, sensitive.ErrMultipleSubjectID) {
		t.Fatalf("Encrypt(group) err = %v, want ErrMultipleSubjectID", err)
	}
}

func TestEncrypt_MultipleSubjects(t *testing.T) {
	ctx := context.Background()
	p := NewProtector("ns", memory.NewKeyEngine(), func(pc *ProtectorConfig) {
		pc.MultipleSubjects = true
	})

	rec := newSubjRecord()
	if err := p.Encrypt(ctx, rec); err != nil {
		t.Fatal(err)
	}
	// Each value names the subject whose key encrypted it.
	if _, sub, _, err := parseWireFormat(rec.Payload); err != nil || sub != "rec-1" {
		t.Fatalf("payload subject = %q, %v", sub, err)
	}
	if _, sub, _, err := parseWireFormat(rec.Email); err != nil || sub != "author-1" {
		t.Fatalf("email subject = %q, %v", sub, err)
	}

	// Forgetting the author erases the author's data only.
	if err := p.Forget(ctx, "author-1"); err != nil {
		t.Fatal(err)
	}
	if err := p.Decrypt(ctx, rec); err != nil {
		t.Fatal(err)
	}
	if rec.Email != "forgotten" || rec.Payload != "body" {
		t.Fatalf("after Forget(author): email %q payload %q", rec.Email, rec.Payload)
	}

	// A new record by the forgotten author is refused, naming the right cause.
	if err := p.Encrypt(ctx, newSubjRecord()); !errors.Is(err, ErrSubjectForgotten) {
		t.Fatalf("Encrypt() after Forget err = %v, want ErrSubjectForgotten", err)
	}

	group := &subjGroup{Members: []subjMember{{ID: "u1", Email: "a@x"}, {ID: "u2", Email: "b@x"}}}
	if err := p.Encrypt(ctx, group); err != nil {
		t.Fatal(err)
	}
	for i, want := range []string{"u1", "u2"} {
		if _, sub, _, err := parseWireFormat(group.Members[i].Email); err != nil || sub != want {
			t.Fatalf("member %d subject = %q, %v", i, sub, err)
		}
	}
}

func TestEncrypt_SingleSubjectStillEncrypts(t *testing.T) {
	ctx := context.Background()
	p := NewProtector("ns", memory.NewKeyEngine())
	group := &subjGroup{Members: []subjMember{{ID: "u1", Email: "a@x"}, {ID: "u1", Email: "b@x"}}}
	if err := p.Encrypt(ctx, group); err != nil {
		t.Fatal(err)
	}
	for _, m := range group.Members {
		if !strings.HasPrefix(m.Email, "ENC.") {
			t.Fatalf("email not encrypted: %q", m.Email)
		}
	}
	if err := p.Decrypt(ctx, group); err != nil {
		t.Fatal(err)
	}
	if group.Members[0].Email != "a@x" || group.Members[1].Email != "b@x" {
		t.Fatalf("round trip = %+v", group.Members)
	}
}
