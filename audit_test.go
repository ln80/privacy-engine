package privacy

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/ln80/privacy-engine/core"
	"github.com/ln80/privacy-engine/memory"
)

type recordingAuditor struct {
	events []AuditEvent
	fail   error
}

func (r *recordingAuditor) Audit(_ context.Context, e AuditEvent) error {
	r.events = append(r.events, e)
	return r.fail
}

func (r *recordingAuditor) last(t *testing.T) AuditEvent {
	t.Helper()
	if len(r.events) == 0 {
		t.Fatal("expect an audit event, got none")
	}
	return r.events[len(r.events)-1]
}

const auditGrace = time.Hour

func newAuditProtector(t *testing.T, graceful bool) (Protector, *recordingAuditor) {
	t.Helper()
	a := &recordingAuditor{}
	eng := memory.NewKeyEngine(func(c *core.KeyEngineConfig) { c.GracePeriod = auditGrace })
	p := NewProtector("tenant-audit", eng, func(pc *ProtectorConfig) {
		pc.TokenEngine = memory.NewTokenEngine()
		pc.GracefulMode = graceful
		pc.Auditor = a
	})
	return p, a
}

type auditRecord struct {
	ID    string `pii:"subjectID"`
	Email string `pii:"data"`
}

func TestAudit_ForgetGraceful(t *testing.T) {
	ctx := context.Background()
	p, a := newAuditProtector(t, true)
	if err := p.Encrypt(ctx, &auditRecord{ID: "u1", Email: "a@example.com"}); err != nil {
		t.Fatal(err)
	}
	if len(a.events) != 0 {
		t.Fatalf("Encrypt must emit nothing, got %v", a.events)
	}

	if err := p.Forget(ctx, "u1"); err != nil {
		t.Fatal(err)
	}
	e := a.last(t)
	if e.Op != OpForget || e.Namespace != "tenant-audit" || e.Subject != "u1" || e.Err != nil {
		t.Fatalf("unexpected event %+v", e)
	}
	if e.Immediate || !e.HadKey || e.HadToken {
		t.Fatalf("expect graceful, key only: %+v", e)
	}
	// The memory token engine reports no grace period, but it held nothing
	// for u1: only the key engine's period counts.
	if want := e.At.Add(auditGrace); !e.FinalAt.Equal(want) {
		t.Fatalf("expect FinalAt %v, got %v", want, e.FinalAt)
	}
}

func TestAudit_ForgetImmediateAndUnknown(t *testing.T) {
	ctx := context.Background()
	p, a := newAuditProtector(t, true)
	if err := p.Encrypt(ctx, &auditRecord{ID: "u1", Email: "a@example.com"}); err != nil {
		t.Fatal(err)
	}
	if err := p.Forget(ctx, "u1", Immediately()); err != nil {
		t.Fatal(err)
	}
	if e := a.last(t); !e.Immediate || !e.FinalAt.Equal(e.At) {
		t.Fatalf("expect immediate, final at once: %+v", e)
	}

	// A failed attempt is audited too.
	err := p.Forget(ctx, "never-seen")
	e := a.last(t)
	if !errors.Is(err, core.ErrKeyNotFound) || !errors.Is(e.Err, core.ErrKeyNotFound) {
		t.Fatalf("expect ErrKeyNotFound in call and event, got %v / %v", err, e.Err)
	}
	if !e.FinalAt.IsZero() || e.HadKey || e.HadToken {
		t.Fatalf("nothing was forgotten: %+v", e)
	}
}

func TestAudit_ForgetTokenUnknownGrace(t *testing.T) {
	ctx := context.Background()
	p, a := newAuditProtector(t, true)
	toks, err := p.Tokenize(ctx, TokenDataSlice("a@example.com"))
	if err != nil {
		t.Fatal(err)
	}
	tok := toks.Get("a@example.com").Token
	if len(a.events) != 0 {
		t.Fatalf("Tokenize must emit nothing, got %v", a.events)
	}
	if err := p.Forget(ctx, tok); err != nil {
		t.Fatal(err)
	}
	// The vault entry was forgotten, and the memory token engine reports no
	// grace period: the deadline is unknown.
	if e := a.last(t); !e.HadToken || !e.FinalAt.IsZero() {
		t.Fatalf("expect a vault entry and an unknown deadline: %+v", e)
	}
}

func TestAudit_MutationsSurviveAuditFailure(t *testing.T) {
	ctx := context.Background()
	p, a := newAuditProtector(t, true)
	if err := p.Encrypt(ctx, &auditRecord{ID: "u1", Email: "a@example.com"}); err != nil {
		t.Fatal(err)
	}
	a.fail = errors.New("sink down")

	err := p.Forget(ctx, "u1")
	if !errors.Is(err, ErrAuditFailure) {
		t.Fatalf("expect ErrAuditFailure, got %v", err)
	}
	// The subject is forgotten nonetheless, and a retry is safe.
	r := auditRecord{ID: "u1", Email: "b@example.com"}
	if err := p.Encrypt(ctx, &r); !errors.Is(err, ErrSubjectForgotten) {
		t.Fatalf("expect the subject forgotten, got %v", err)
	}
	a.fail = nil
	if err := p.Forget(ctx, "u1"); err != nil {
		t.Fatalf("retry: %v", err)
	}

	a.fail = errors.New("sink down")
	if err := p.Recover(ctx, "u1"); !errors.Is(err, ErrAuditFailure) {
		t.Fatalf("Recover: expect ErrAuditFailure, got %v", err)
	}
	if e := a.last(t); e.Op != OpRecover || e.Subject != "u1" || e.Err != nil {
		t.Fatalf("unexpected event %+v", e)
	}
	if err := p.Purge(ctx); !errors.Is(err, ErrAuditFailure) {
		t.Fatalf("Purge: expect ErrAuditFailure, got %v", err)
	}
	if e := a.last(t); e.Op != OpPurge || e.Subject != "" {
		t.Fatalf("unexpected event %+v", e)
	}
}

func TestAudit_DisclosureFailsClosed(t *testing.T) {
	ctx := context.Background()
	p, a := newAuditProtector(t, true)
	toks, err := p.Tokenize(ctx, TokenDataSlice("a@example.com", "b@example.com"))
	if err != nil {
		t.Fatal(err)
	}
	ta, tb := toks.Get("a@example.com").Token, toks.Get("b@example.com").Token
	if err := p.Forget(ctx, tb); err != nil {
		t.Fatal(err)
	}

	vals, err := p.Detokenize(ctx, []string{ta, tb, "unknown"})
	if err != nil || len(vals) != 1 {
		t.Fatalf("expect one value, got %v, %v", vals, err)
	}
	if e := a.last(t); e.Op != OpDetokenize || !slices.Equal(e.Revealed, []string{ta}) {
		t.Fatalf("expect only %s revealed, got %+v", ta, e)
	}

	page, err := p.ListTokens(ctx, core.ListTokensQuery{})
	if err != nil || len(page.Tokens) != 2 {
		t.Fatalf("expect two listed tokens, got %v, %v", page, err)
	}
	if e := a.last(t); e.Op != OpListTokens || !slices.Equal(e.Revealed, []string{ta}) {
		t.Fatalf("expect only the active token revealed, got %+v", e)
	}

	a.fail = errors.New("sink down")
	if vals, err := p.Detokenize(ctx, []string{ta}); !errors.Is(err, ErrAuditFailure) || vals != nil {
		t.Fatalf("Detokenize must return nothing, got %v, %v", vals, err)
	}
	if page, err := p.ListTokens(ctx, core.ListTokensQuery{}); !errors.Is(err, ErrAuditFailure) || page != nil {
		t.Fatalf("ListTokens must return nothing, got %v, %v", page, err)
	}

	if err := p.Encrypt(ctx, &auditRecord{ID: "u1", Email: "a@example.com"}); err != nil {
		t.Fatal(err)
	}
	if key, err := p.DeriveSubjectKey(ctx, "u1", "attachments"); !errors.Is(err, ErrAuditFailure) || key != nil {
		t.Fatalf("DeriveSubjectKey must return no key, got %v", err)
	}
	if e := a.last(t); e.Op != OpDeriveKey || e.Subject != "u1" || e.Purpose != "attachments" {
		t.Fatalf("unexpected event %+v", e)
	}
}

func TestAudit_DeleteToken(t *testing.T) {
	ctx := context.Background()
	p, a := newAuditProtector(t, true)
	if err := p.DeleteToken(ctx, "tok"); err != nil {
		t.Fatal(err)
	}
	if e := a.last(t); e.Op != OpDeleteToken || e.Subject != "tok" {
		t.Fatalf("unexpected event %+v", e)
	}
}

func TestGracePeriodOfThroughCache(t *testing.T) {
	store := memory.NewKeyEngine(func(c *core.KeyEngineConfig) { c.GracePeriod = auditGrace })
	if got := core.GracePeriodOf(memory.NewCacheWrapper(store, time.Second)); got != auditGrace {
		t.Fatalf("expect %v through the cache wrapper, got %v", auditGrace, got)
	}
	if got := core.GracePeriodOf(memory.NewTokenEngine()); got != 0 {
		t.Fatalf("expect 0 for an engine that reports none, got %v", got)
	}
}
