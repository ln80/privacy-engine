package privacy

import (
	"context"
	"errors"
	"testing"

	"github.com/ln80/privacy-engine/core"
	"github.com/ln80/privacy-engine/memory"
)

type failingPurgeTokens struct {
	core.TokenEngine
	err error
}

func (f failingPurgeTokens) PurgeNamespace(context.Context, string) error { return f.err }

func TestPurge_Failures(t *testing.T) {
	ctx := t.Context()
	boom := errors.New("store down")

	p := NewProtector("ns", failingKeys{KeyEngine: memory.NewKeyEngine(), err: boom}, WithoutCache())
	if err := p.Purge(ctx); !errors.Is(err, ErrPurgeNamespaceFailure) || !errors.Is(err, boom) {
		t.Fatalf("key engine failure: expect ErrPurgeNamespaceFailure wrapping it, got %v", err)
	}

	p = NewProtector("ns", memory.NewKeyEngine(), WithTokenEngine(failingPurgeTokens{TokenEngine: memory.NewTokenEngine(), err: boom}))
	err := p.Purge(ctx)
	if !errors.Is(err, ErrPurgeNamespaceFailure) || !errors.Is(err, boom) {
		t.Fatalf("token engine failure: expect ErrPurgeNamespaceFailure wrapping it, got %v", err)
	}
	var perr Error
	if !errors.As(err, &perr) || perr.Namespace() != "ns" || perr.Message() != "failed to purge namespace" {
		t.Fatalf("expect the namespace and message on the error, got %+v", perr)
	}
}

func TestTokenize_GeneratorFailures(t *testing.T) {
	ctx := t.Context()
	p := NewProtector("ns", memory.NewKeyEngine(), WithTokenEngine(memory.NewTokenEngine()))

	constant := func(c *core.TokenizeConfig) {
		c.TokenGenFunc = func(context.Context, string) (string, error) { return "same", nil }
	}
	if _, err := p.Tokenize(ctx, TokenDataSlice("a@example.com"), constant); err != nil {
		t.Fatal(err)
	}
	// Every new token collides: the protector gives up after its retries.
	_, err := p.Tokenize(ctx, TokenDataSlice("b@example.com"), constant)
	if !errors.Is(err, ErrTokenizeFailure) {
		t.Fatalf("collisions: expect ErrTokenizeFailure, got %v", err)
	}
	// The value already tokenized still resolves to its token.
	res, err := p.Tokenize(ctx, TokenDataSlice("a@example.com"), constant)
	if err != nil || res.Get("a@example.com").Token != "same" {
		t.Fatalf("expect the existing token, got %v, %v", res, err)
	}

	boom := errors.New("no entropy")
	_, err = p.Tokenize(ctx, TokenDataSlice("c@example.com"), func(c *core.TokenizeConfig) {
		c.TokenGenFunc = func(context.Context, string) (string, error) { return "", boom }
	})
	if !errors.Is(err, ErrTokenizeFailure) || !errors.Is(err, boom) {
		t.Fatalf("generator error: expect ErrTokenizeFailure wrapping it, got %v", err)
	}
}

func TestAuditorFunc(t *testing.T) {
	var got []AuditOp
	p := NewProtector("ns", memory.NewKeyEngine(), WithAuditor(AuditorFunc(func(_ context.Context, e AuditEvent) error {
		got = append(got, e.Op)
		return nil
	})))
	_ = p.Purge(t.Context())
	if len(got) != 1 || got[0] != OpPurge {
		t.Fatalf("expect one purge event through AuditorFunc, got %v", got)
	}
}
