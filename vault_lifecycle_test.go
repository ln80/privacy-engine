package privacy

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ln80/privacy-engine/core"
	"github.com/ln80/privacy-engine/memory"
)

// viewer is a doconvoy-like record: a sub_ token is the subject of its data.
type viewer struct {
	Token string `pii:"subjectID"`
	Note  string `pii:"data"`
}

type lifecycle struct {
	t      *testing.T
	ctx    context.Context
	keys   core.KeyEngine
	tokens *memory.TokenEngine
	p      Protector
}

func newLifecycle(t *testing.T, graceful bool) *lifecycle {
	keys, tokens := memory.NewKeyEngine(), memory.NewTokenEngine()
	return &lifecycle{t: t, ctx: context.Background(), keys: keys, tokens: tokens,
		p: NewProtector("tnt-life", keys, func(pc *ProtectorConfig) {
			pc.TokenEngine = tokens
			pc.CacheEnabled = false
			pc.GracefulMode = graceful
			pc.ForgottenValue = "[forgotten]"
		})}
}

func (l *lifecycle) tokenize(email string) string {
	l.t.Helper()
	m, err := l.p.Tokenize(l.ctx, TokenDataSlice(email), WithPrefix("sub_"))
	if err != nil {
		l.t.Fatal(err)
	}
	return m.Get(email).Token
}

func (l *lifecycle) resolves(token string) (string, bool) {
	l.t.Helper()
	m, err := l.p.Detokenize(l.ctx, []string{token})
	if err != nil {
		l.t.Fatal(err)
	}
	r, ok := m[token]
	return r.Value.Reveal(), ok
}

func (l *lifecycle) listed(token string) core.TokenRecord {
	l.t.Helper()
	page, err := l.p.ListTokens(l.ctx, core.ListTokensQuery{Prefix: "sub_"})
	if err != nil {
		l.t.Fatal(err)
	}
	for _, r := range page.Tokens {
		if r.Token == token {
			return r
		}
	}
	l.t.Fatalf("token %s not listed", token)
	return core.TokenRecord{}
}

func (l *lifecycle) encrypt(token, note string) *viewer {
	l.t.Helper()
	v := &viewer{Token: token, Note: note}
	if err := l.p.Encrypt(l.ctx, v); err != nil {
		l.t.Fatal(err)
	}
	return v
}

func (l *lifecycle) decrypt(v *viewer) string {
	l.t.Helper()
	c := *v
	if err := l.p.Decrypt(l.ctx, &c); err != nil {
		l.t.Fatal(err)
	}
	return c.Note
}

// V3: a graceful Forget hides the email at once, drops it from lookups, and a
// returning person gets a fresh token whose data encrypts normally. Before,
// the email stayed in the vault in clear and Tokenize returned the forgotten
// token, so Encrypt failed with ErrSubjectForgotten.
func TestForget_HidesTheVaultEntryAndFreesTheValue(t *testing.T) {
	l := newLifecycle(t, true)
	old := l.tokenize("alice@example.org")
	data := l.encrypt(old, "viewed secret 1")

	if err := l.p.Forget(l.ctx, old); err != nil {
		t.Fatal(err)
	}
	if err := l.p.Forget(l.ctx, old); err != nil {
		t.Fatalf("Forget must be idempotent: %v", err)
	}
	if _, ok := l.resolves(old); ok {
		t.Fatal("a forgotten token still resolves")
	}
	if r := l.listed(old); r.State != core.TokenForgotten || r.Value != "" {
		t.Fatalf("listed as %+v, want FORGOTTEN without value", r)
	}
	if got := l.decrypt(data); got != "[forgotten]" {
		t.Fatalf("forgotten data decrypts to %q", got)
	}

	fresh := l.tokenize("alice@example.org")
	if fresh == old {
		t.Fatal("a returning person got the forgotten token back")
	}
	if got := l.decrypt(l.encrypt(fresh, "viewed secret 2")); got != "viewed secret 2" {
		t.Fatalf("new data under the fresh token: %q", got)
	}
}

func TestRecover_RestoresTheVaultEntry(t *testing.T) {
	l := newLifecycle(t, true)
	tok := l.tokenize("bob@example.org")
	data := l.encrypt(tok, "note")
	if err := l.p.Forget(l.ctx, tok); err != nil {
		t.Fatal(err)
	}
	if err := l.p.Recover(l.ctx, tok); err != nil {
		t.Fatal(err)
	}
	if v, ok := l.resolves(tok); !ok || v != "bob@example.org" {
		t.Fatalf("after Recover: %q, %v", v, ok)
	}
	if got := l.decrypt(data); got != "note" {
		t.Fatalf("data after Recover: %q", got)
	}
	if again := l.tokenize("bob@example.org"); again != tok {
		t.Fatal("after Recover the value must find its token again")
	}
}

// V11: recovering a token whose value was tokenized again meanwhile restores
// the old data, and the value stays with the newer token.
func TestRecover_AfterTheValueMovedOn(t *testing.T) {
	l := newLifecycle(t, true)
	old := l.tokenize("carol@example.org")
	data := l.encrypt(old, "old note")
	if err := l.p.Forget(l.ctx, old); err != nil {
		t.Fatal(err)
	}
	newer := l.tokenize("carol@example.org")
	if err := l.p.Recover(l.ctx, old); err != nil {
		t.Fatal(err)
	}
	if got := l.decrypt(data); got != "old note" {
		t.Fatalf("old data after Recover: %q", got)
	}
	if v, ok := l.resolves(old); !ok || v != "carol@example.org" {
		t.Fatalf("old token after Recover: %q, %v", v, ok)
	}
	if again := l.tokenize("carol@example.org"); again != newer {
		t.Fatal("the value must stay with the newer token")
	}
}

// Immediate mode erases the vault entry with the key; nothing can be recovered.
func TestForget_ImmediateErases(t *testing.T) {
	l := newLifecycle(t, false)
	tok := l.tokenize("dave@example.org")
	l.encrypt(tok, "note")
	if err := l.p.Forget(l.ctx, tok); err != nil {
		t.Fatal(err)
	}
	if r := l.listed(tok); r.State != core.TokenErased {
		t.Fatalf("state %s, want ERASED", r.State)
	}
	if err := l.p.Recover(l.ctx, tok); !errors.Is(err, ErrCannotRecoverSubject) {
		t.Fatalf("Recover after an immediate Forget: expect ErrCannotRecoverSubject, got %v", err)
	}
}

// V10: a token never used as a subject has no key but has a vault entry;
// Forget succeeds and hides it.
func TestForget_TokenWithoutKey(t *testing.T) {
	l := newLifecycle(t, true)
	tok := l.tokenize("erin@example.org")
	if err := l.p.Forget(l.ctx, tok); err != nil {
		t.Fatalf("Forget of a key-less token: %v", err)
	}
	if _, ok := l.resolves(tok); ok {
		t.Fatal("the key-less token still resolves")
	}
	if err := l.p.Recover(l.ctx, tok); err != nil {
		t.Fatalf("Recover of a key-less token: %v", err)
	}
	if _, ok := l.resolves(tok); !ok {
		t.Fatal("the key-less token does not resolve after Recover")
	}
}

// An ID with neither a key nor a vault entry still reports ErrKeyNotFound, as
// doconvoy's erasure.Forget expects.
func TestForget_UnknownID(t *testing.T) {
	l := newLifecycle(t, true)
	if err := l.p.Forget(l.ctx, "sub_unknown"); !errors.Is(err, core.ErrKeyNotFound) {
		t.Fatalf("Forget unknown: expect ErrKeyNotFound, got %v", err)
	}
	if err := l.p.Recover(l.ctx, "sub_unknown"); !errors.Is(err, ErrCannotRecoverSubject) {
		t.Fatalf("Recover unknown: expect ErrCannotRecoverSubject, got %v", err)
	}
}

// The janitor erases entries forgotten longer than the grace period.
func TestEraseForgotten_AfterGrace(t *testing.T) {
	l := newLifecycle(t, true)
	tok := l.tokenize("frank@example.org")
	if err := l.p.Forget(l.ctx, tok); err != nil {
		t.Fatal(err)
	}
	if n, err := l.tokens.EraseForgotten(l.ctx, "tnt-life", time.Now().Add(-time.Hour)); err != nil || n != 0 {
		t.Fatalf("inside the grace period: erased %d, %v", n, err)
	}
	if n, err := l.tokens.EraseForgotten(l.ctx, "tnt-life", time.Now().Add(time.Second)); err != nil || n != 1 {
		t.Fatalf("past the grace period: erased %d, %v", n, err)
	}
	if r := l.listed(tok); r.State != core.TokenErased {
		t.Fatalf("state %s, want ERASED", r.State)
	}
}
