package privacy

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/ln80/privacy-engine/core"
	"github.com/ln80/privacy-engine/memory"
)

func newVaultProtector(ns string, keys core.KeyEngine, tokens core.TokenEngine) Protector {
	return NewProtector(ns, keys, func(pc *ProtectorConfig) {
		pc.TokenEngine = tokens
		pc.CacheEnabled = false
	})
}

func TestVault_RoundTrip(t *testing.T) {
	ctx := context.Background()
	store := memory.NewTokenEngine()
	p := newVaultProtector("tnt-vault", memory.NewKeyEngine(), store)

	values := TokenDataSlice("alice@example.org", "bob@example.org", "alice@example.org")
	first, err := p.Tokenize(ctx, values, WithPrefix("sub_"))
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != 2 {
		t.Fatalf("got %d tokens for 2 distinct values", len(first))
	}
	for v, r := range first {
		if len(r.Token) <= 4 || r.Token[:4] != "sub_" || r.State != core.TokenActive || r.Value != v {
			t.Fatalf("bad record %+v", r)
		}
	}

	again, err := p.Tokenize(ctx, values, WithPrefix("sub_"))
	if err != nil {
		t.Fatal(err)
	}
	for v, r := range first {
		if again[v].Token != r.Token {
			t.Fatal("Tokenize is not idempotent")
		}
	}

	got, err := p.Detokenize(ctx, append(first.Tokens(), "sub_unknown"))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d values, want 2 (unknown omitted)", len(got))
	}
	for v, r := range first {
		if got.Get(r.Token).Value != v {
			t.Fatalf("token %s resolves to the wrong value", r.Token)
		}
	}

	list, err := p.ListTokens(ctx, core.ListTokensQuery{Prefix: "sub_"})
	if err != nil {
		t.Fatal(err)
	}
	if len(list.Tokens) != 2 {
		t.Fatalf("listed %d tokens, want 2", len(list.Tokens))
	}
	for _, r := range list.Tokens {
		if r.State != core.TokenActive || first[r.Value].Token != r.Token {
			t.Fatalf("listed record %+v does not match", r)
		}
	}

	// PX-18: the store holds no value in clear, anywhere.
	stored, err := store.ListTokens(ctx, "tnt-vault", core.ListTokensQuery{})
	if err != nil {
		t.Fatal(err)
	}
	for _, rec := range stored.Records {
		for _, v := range []string{"alice@example.org", "bob@example.org"} {
			if bytes.Contains(rec.Sealed, []byte(v)) || bytes.Contains(rec.Index, []byte(v)) || bytes.Contains([]byte(rec.Token), []byte(v)) {
				t.Fatalf("the store holds %q in clear", v)
			}
		}
	}
}

// PX-21 regression: concurrent first Tokenize of one value, from independent
// protectors over one store, yields one token.
func TestVault_ConcurrentFirstTokenize(t *testing.T) {
	ctx := context.Background()
	keys, store := memory.NewKeyEngine(), memory.NewTokenEngine()
	if _, err := newVaultProtector("tnt-race", keys, store).Tokenize(ctx, TokenDataSlice("warmup")); err != nil {
		t.Fatal(err) // creates @vault so every goroutine shares it
	}

	const n = 20
	tokens := make([]string, n)
	errs := make([]error, n)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			p := newVaultProtector("tnt-race", keys, store)
			<-start
			m, err := p.Tokenize(ctx, TokenDataSlice("carol@example.org"))
			errs[i] = err
			tokens[i] = m.Get("carol@example.org").Token
		}()
	}
	close(start)
	wg.Wait()
	for i := range n {
		if errs[i] != nil {
			t.Fatal(errs[i])
		}
		if tokens[i] != tokens[0] {
			t.Fatalf("got tokens %q and %q for one value", tokens[0], tokens[i])
		}
	}
}

// PX-20 regression: a generated token that already exists is replaced, never
// returned for another value.
func TestVault_TokenCollisionIsRetried(t *testing.T) {
	ctx := context.Background()
	p := newVaultProtector("tnt-collide", memory.NewKeyEngine(), memory.NewTokenEngine())
	seq := []string{"same", "same", "fresh"}
	i := 0
	gen := func(c *core.TokenizeConfig) {
		c.TokenGenFunc = func(context.Context, string) (string, error) {
			tok := seq[i]
			i++
			return tok, nil
		}
	}
	a, err := p.Tokenize(ctx, TokenDataSlice("a@example.org"), gen)
	if err != nil {
		t.Fatal(err)
	}
	b, err := p.Tokenize(ctx, TokenDataSlice("b@example.org"), gen)
	if err != nil {
		t.Fatal(err)
	}
	if a.Get("a@example.org").Token != "same" || b.Get("b@example.org").Token != "fresh" {
		t.Fatalf("got %q and %q", a.Get("a@example.org").Token, b.Get("b@example.org").Token)
	}
	got, err := p.Detokenize(ctx, []string{"same", "fresh"})
	if err != nil {
		t.Fatal(err)
	}
	if got.Get("same").Value != "a@example.org" || got.Get("fresh").Value != "b@example.org" {
		t.Fatal("a collision mapped a token to the wrong value")
	}
}

// swappingEngine returns token B's sealed value for token A, as someone with
// write access to the table could arrange.
type swappingEngine struct {
	core.TokenEngine
	a, b string
}

func (s swappingEngine) GetRecords(ctx context.Context, ns string, tokens []string) (map[string]core.VaultRecord, error) {
	recs, err := s.TokenEngine.GetRecords(ctx, ns, []string{s.a, s.b})
	if err != nil {
		return nil, err
	}
	a := recs[s.a]
	a.Sealed = recs[s.b].Sealed
	return map[string]core.VaultRecord{s.a: a}, nil
}

func TestVault_MovedSealedValueFails(t *testing.T) {
	ctx := context.Background()
	keys, store := memory.NewKeyEngine(), memory.NewTokenEngine()
	m, err := newVaultProtector("tnt-swap", keys, store).Tokenize(ctx, TokenDataSlice("alice@example.org", "bob@example.org"))
	if err != nil {
		t.Fatal(err)
	}
	a, b := m.Get("alice@example.org").Token, m.Get("bob@example.org").Token
	p := newVaultProtector("tnt-swap", keys, swappingEngine{TokenEngine: store, a: a, b: b})
	if _, err := p.Detokenize(ctx, []string{a}); !errors.Is(err, core.ErrDetokenizeFailure) {
		t.Fatalf("expect a moved sealed value to fail, got %v", err)
	}
}

func TestVault_ConfigErrors(t *testing.T) {
	ctx := context.Background()
	p := newVaultProtector("tnt-cfg", memory.NewKeyEngine(), memory.NewTokenEngine())
	if _, err := p.Tokenize(ctx, TokenDataSlice("x"), WithPrefix("@x")); !errors.Is(err, ErrReservedSubjectID) {
		t.Fatalf("reserved prefix: expect ErrReservedSubjectID, got %v", err)
	}
	noGen := func(c *core.TokenizeConfig) { c.TokenGenFunc = nil }
	if _, err := p.Tokenize(ctx, TokenDataSlice("x"), noGen); !errors.Is(err, core.ErrTokenGenFuncNotFound) {
		t.Fatalf("nil generator: expect ErrTokenGenFuncNotFound, got %v", err)
	}
	if _, err := NewProtector("tnt-cfg", memory.NewKeyEngine()).Tokenize(ctx, TokenDataSlice("x")); !errors.Is(err, core.ErrTokenEngineNotConfigured) {
		t.Fatalf("no engine: expect ErrTokenEngineNotConfigured, got %v", err)
	}
	if m, err := p.Tokenize(ctx, nil); err != nil || len(m) != 0 {
		t.Fatalf("empty input: got %v, %v", m, err)
	}
}

// Purge destroys the vault key with the records: nothing resolves, and the
// namespace can tokenize again from scratch.
func TestVault_Purge(t *testing.T) {
	ctx := context.Background()
	keys := memory.NewKeyEngine()
	p := newVaultProtector("tnt-purge", keys, memory.NewTokenEngine())
	m, err := p.Tokenize(ctx, TokenDataSlice("alice@example.org"))
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Purge(ctx); err != nil {
		t.Fatal(err)
	}
	if got, err := p.Detokenize(ctx, m.Tokens()); err != nil || len(got) != 0 {
		t.Fatalf("after purge: got %v, %v", got, err)
	}
	if _, missing, _ := keys.GetKeys(ctx, "tnt-purge", []string{vaultKeyID}); missing[vaultKeyID] != core.StateUnknown {
		t.Fatalf("vault key state %s after purge, want UNKNOWN", missing[vaultKeyID])
	}
	again, err := p.Tokenize(ctx, TokenDataSlice("alice@example.org"))
	if err != nil {
		t.Fatal(err)
	}
	if again.Get("alice@example.org").Token == m.Get("alice@example.org").Token {
		t.Fatal("expect a new token after purge")
	}
}

func TestVault_ListTokensPaging(t *testing.T) {
	ctx := context.Background()
	p := newVaultProtector("tnt-page", memory.NewKeyEngine(), memory.NewTokenEngine())
	var values []core.TokenData
	for i := range 7 {
		values = append(values, core.TokenData(fmt.Sprintf("user%d@example.org", i)))
	}
	if _, err := p.Tokenize(ctx, values, WithPrefix("sub_")); err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	var cursor *string
	for range 5 {
		page, err := p.ListTokens(ctx, core.ListTokensQuery{Prefix: "sub_", Limit: 3, Cursor: cursor})
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range page.Tokens {
			seen[r.Value.Reveal()] = true
		}
		if page.Cursor == nil {
			break
		}
		cursor = page.Cursor
	}
	if len(seen) != 7 {
		t.Fatalf("paging listed %d distinct values, want 7", len(seen))
	}
}
