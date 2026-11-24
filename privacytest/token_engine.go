package privacytest

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/ln80/privacy-engine/core"
)

// TokenEngineTestConfig configures TestTokenEngine.
type TokenEngineTestConfig struct {
	// GracePeriod declares an engine that erases records forgotten longer
	// than it ago by itself, for example through a storage TTL. Zero skips
	// R-TE-5. Other subtests forget records up to two hours in the past and
	// expect them restorable, so it must exceed three hours.
	GracePeriod time.Duration

	// SealedProbe reads the backend's storage directly, bypassing the
	// engine, and reports whether a sealed value is still stored for token.
	// Without it the suite cannot check that erasure removes values.
	SealedProbe func(ctx context.Context, namespace, token string) (stored bool, err error)

	// Namespace prefixes the namespaces the suite creates, one per subtest.
	// Default "privacytest".
	Namespace string
}

// TestTokenEngine is the conformance suite of core.TokenEngine. It runs one
// subtest per requirement of docs/implementing-backends.md, named after its
// ID (run one with -run 'TestX/R-TE-2'), each in a namespace of its own.
func TestTokenEngine(t *testing.T, eng core.TokenEngine, opts ...func(*TokenEngineTestConfig)) {
	t.Helper()
	cfg := &TokenEngineTestConfig{}
	for _, opt := range opts {
		if opt != nil {
			opt(cfg)
		}
	}
	if cfg.Namespace == "" {
		cfg.Namespace = "privacytest"
	}
	run := func(name string, f func(c *tokenCheck)) {
		t.Helper()
		t.Run(name, func(t *testing.T) {
			f(&tokenCheck{t: t, ctx: t.Context(), eng: eng, cfg: cfg, ns: newNamespace(cfg.Namespace)})
		})
	}

	run("R-TE-1 records and index entries are stored as given", func(c *tokenCheck) {
		a, b := c.insert("tok-a"), c.insert("tok-b")
		idx, err := c.eng.LookupIndex(c.ctx, c.ns, [][]byte{a.Index, b.Index, randomBytes(32)})
		c.must(err, "LookupIndex")
		if len(idx) != 2 || idx[string(a.Index)] != a.Token || idx[string(b.Index)] != b.Token {
			c.t.Fatalf("LookupIndex: expect both tokens and no unknown index, got %v", idx)
		}
		recs, err := c.eng.GetRecords(c.ctx, c.ns, []string{a.Token, b.Token, "unknown"})
		c.must(err, "GetRecords")
		if len(recs) != 2 {
			c.t.Fatalf("GetRecords: expect 2 records, unknown omitted, got %d", len(recs))
		}
		if r := recs[a.Token]; !bytes.Equal(r.Index, a.Index) || !bytes.Equal(r.Sealed, a.Sealed) || r.State != core.TokenActive || r.CreatedAt != a.CreatedAt {
			c.t.Fatalf("GetRecords: the record differs from the one inserted: %+v", r)
		}

		// Returned records are copies.
		recs[a.Token].Sealed[0] ^= 0xff
		recs[a.Token].Index[0] ^= 0xff
		if r := c.record(a.Token); !bytes.Equal(r.Sealed, a.Sealed) || !bytes.Equal(r.Index, a.Index) {
			c.t.Fatal("changing a returned record changed the stored one")
		}
	})

	run("R-TE-2 Insert is atomic and doubly conditioned", func(c *tokenCheck) {
		a := c.insert("tok-a")

		dup := newRecord(a.Token)
		if err := c.eng.Insert(c.ctx, c.ns, dup); !errors.Is(err, core.ErrTokenExists) {
			c.t.Fatalf("Insert of an existing token: expect core.ErrTokenExists, got %v", err)
		}
		if c.indexOf(dup.Index) != "" {
			c.t.Fatal("a failed Insert wrote its index entry")
		}

		taken := newRecord("tok-taken-" + randomID())
		taken.Index = bytes.Clone(a.Index)
		c.taken(c.eng.Insert(c.ctx, c.ns, taken), a.Token)
		if c.state(taken.Token) != "" {
			c.t.Fatal("a failed Insert wrote its record")
		}

		// Concurrent inserts of one index: one wins, the others learn its token.
		const callers = 16
		index := randomBytes(32)
		recs := make([]core.VaultRecord, callers)
		errs := make([]error, callers)
		var wg sync.WaitGroup
		for i := range callers {
			recs[i] = newRecord(fmt.Sprintf("tok-race-%02d-%s", i, randomID()))
			recs[i].Index = index
			wg.Go(func() { errs[i] = c.eng.Insert(c.ctx, c.ns, recs[i]) })
		}
		wg.Wait()
		winner := c.indexOf(index)
		wins := 0
		for i, err := range errs {
			if err == nil {
				wins++
				if recs[i].Token != winner {
					c.t.Fatalf("Insert of %s succeeded but the index points to %s", recs[i].Token, winner)
				}
				continue
			}
			c.taken(err, winner)
			if c.state(recs[i].Token) != "" {
				c.t.Fatal("a losing concurrent Insert wrote its record")
			}
		}
		if wins != 1 {
			c.t.Fatalf("expect exactly one concurrent Insert to win, got %d", wins)
		}
	})

	run("R-TE-3 index entries are removed only by their own token", func(c *tokenCheck) {
		old := c.insert("tok-old")
		c.must(c.eng.Forget(c.ctx, c.ns, old.Token, time.Now()), "Forget")
		newer := newRecord("tok-newer-" + randomID())
		newer.Index = bytes.Clone(old.Index)
		c.must(c.eng.Insert(c.ctx, c.ns, newer), "Insert of the same index after Forget")

		c.must(c.eng.Forget(c.ctx, c.ns, old.Token, time.Now()), "Forget again")
		c.must(c.eng.Erase(c.ctx, c.ns, old.Token), "Erase")
		c.must(c.eng.DeleteToken(c.ctx, c.ns, old.Token), "DeleteToken")
		if got := c.indexOf(old.Index); got != newer.Token {
			c.t.Fatalf("an older token removed the index entry of %s (now %q)", newer.Token, got)
		}

		for name, remove := range map[string]func(string) error{
			"Forget":      func(tok string) error { return c.eng.Forget(c.ctx, c.ns, tok, time.Now()) },
			"Erase":       func(tok string) error { return c.eng.Erase(c.ctx, c.ns, tok) },
			"DeleteToken": func(tok string) error { return c.eng.DeleteToken(c.ctx, c.ns, tok) },
		} {
			r := c.insert("tok-" + name)
			c.must(remove(r.Token), name)
			if c.indexOf(r.Index) != "" {
				c.t.Fatalf("%s left the token's own index entry", name)
			}
		}
		c.sealed(newer.Token, "nothing", true)
	})

	run("R-TE-4 Forget, Restore and Erase follow the record's state", func(c *tokenCheck) {
		a := c.insert("tok-a")
		t1 := time.Unix(time.Now().Unix()-100, 0)
		c.must(c.eng.Forget(c.ctx, c.ns, a.Token, t1), "Forget")
		c.must(c.eng.Forget(c.ctx, c.ns, a.Token, t1.Add(50*time.Second)), "Forget again")
		if r := c.record(a.Token); r.State != core.TokenForgotten || r.ForgottenAt != t1.Unix() || !bytes.Equal(r.Sealed, a.Sealed) {
			c.t.Fatalf("Forget: expect FORGOTTEN at the first time with the sealed value kept, got %+v", r)
		}
		c.notFound(c.eng.Forget(c.ctx, c.ns, "unknown", t1), "Forget of an unknown token")

		reindexed, err := c.eng.Restore(c.ctx, c.ns, a.Token)
		c.must(err, "Restore")
		if !reindexed || c.state(a.Token) != core.TokenActive || c.indexOf(a.Index) != a.Token {
			c.t.Fatal("Restore with a free index: expect active and reindexed")
		}
		if reindexed, err := c.eng.Restore(c.ctx, c.ns, a.Token); err != nil || reindexed {
			c.t.Fatalf("Restore of an active record: expect (false, nil), got (%v, %v)", reindexed, err)
		}

		c.must(c.eng.Forget(c.ctx, c.ns, a.Token, t1), "Forget")
		newer := newRecord("tok-newer-" + randomID())
		newer.Index = bytes.Clone(a.Index)
		c.must(c.eng.Insert(c.ctx, c.ns, newer), "Insert")
		reindexed, err = c.eng.Restore(c.ctx, c.ns, a.Token)
		c.must(err, "Restore")
		if reindexed || c.state(a.Token) != core.TokenActive || c.indexOf(a.Index) != newer.Token {
			c.t.Fatal("Restore with a taken index: expect active, not reindexed")
		}
		if _, err := c.eng.Restore(c.ctx, c.ns, "unknown"); !errors.Is(err, core.ErrTokenNotFound) {
			c.t.Fatalf("Restore of an unknown token: expect core.ErrTokenNotFound, got %v", err)
		}

		for range 2 {
			c.must(c.eng.Erase(c.ctx, c.ns, a.Token), "Erase")
		}
		if r := c.record(a.Token); r.State != core.TokenErased || len(r.Sealed) != 0 {
			c.t.Fatalf("Erase: expect ERASED without sealed value, got %+v", r)
		}
		c.sealed(a.Token, "Erase", false)
		if _, err := c.eng.Restore(c.ctx, c.ns, a.Token); !errors.Is(err, core.ErrTokenErased) {
			c.t.Fatalf("Restore of an erased record: expect core.ErrTokenErased, got %v", err)
		}
		c.must(c.eng.Forget(c.ctx, c.ns, a.Token, t1), "Forget of an erased record")
		if c.state(a.Token) != core.TokenErased {
			c.t.Fatal("Forget changed an erased record")
		}
		c.notFound(c.eng.Erase(c.ctx, c.ns, "unknown"), "Erase of an unknown token")

		// EraseForgotten erases records forgotten strictly before the cutoff.
		old, recent := c.insert("tok-old"), c.insert("tok-recent")
		now := time.Now()
		c.must(c.eng.Forget(c.ctx, c.ns, old.Token, now.Add(-2*time.Hour)), "Forget")
		c.must(c.eng.Forget(c.ctx, c.ns, recent.Token, now), "Forget")
		n, err := c.eng.EraseForgotten(c.ctx, c.ns, now.Add(-time.Hour))
		c.must(err, "EraseForgotten")
		if n != 1 || c.state(old.Token) != core.TokenErased || c.state(recent.Token) != core.TokenForgotten {
			c.t.Fatalf("EraseForgotten: expect only the older record erased, erased %d", n)
		}
		c.sealed(old.Token, "EraseForgotten", false)
	})

	run("R-TE-5 a record forgotten past the grace period reads ERASED", func(c *tokenCheck) {
		g := c.cfg.GracePeriod
		if g == 0 {
			c.t.Skip("set GracePeriod to check it")
		}
		r := c.insert("tok-expired")
		c.must(c.eng.Forget(c.ctx, c.ns, r.Token, time.Now().Add(-g-2*time.Second)), "Forget")
		if got := c.record(r.Token); got.State != core.TokenErased || len(got.Sealed) != 0 {
			c.t.Fatalf("expect ERASED without sealed value, got %s with %d sealed bytes", got.State, len(got.Sealed))
		}
		if _, err := c.eng.Restore(c.ctx, c.ns, r.Token); !errors.Is(err, core.ErrTokenErased) {
			c.t.Fatalf("Restore: expect core.ErrTokenErased, got %v", err)
		}
		if c.indexOf(r.Index) != "" {
			c.t.Fatal("the record still holds its index entry")
		}
		page, err := c.eng.ListTokens(c.ctx, c.ns, core.ListTokensQuery{})
		c.must(err, "ListTokens")
		if len(page.Records) != 1 || page.Records[0].State != core.TokenErased || len(page.Records[0].Sealed) != 0 {
			c.t.Fatalf("ListTokens: expect the record ERASED without sealed value, got %+v", page.Records)
		}
		c.must(c.eng.Erase(c.ctx, c.ns, r.Token), "Erase")
		c.sealed(r.Token, "Erase", false)
	})

	run("R-TE-6 ListTokens pages through tokens in order", func(c *tokenCheck) {
		var want []string
		for i := range 7 {
			r := newRecord(fmt.Sprintf("sub_%02d", i))
			c.must(c.eng.Insert(c.ctx, c.ns, r), "Insert")
			want = append(want, r.Token)
		}
		c.must(c.eng.Insert(c.ctx, c.ns, newRecord("rcp_00")), "Insert")
		c.must(c.eng.Forget(c.ctx, c.ns, "sub_03", time.Now()), "Forget")

		var got []string
		var cursor *string
		for pages := 0; ; pages++ {
			if pages > 10 {
				c.t.Fatal("ListTokens: paging does not end")
			}
			page, err := c.eng.ListTokens(c.ctx, c.ns, core.ListTokensQuery{Prefix: "sub_", Limit: 3, Cursor: cursor})
			c.must(err, "ListTokens")
			if len(page.Records) > 3 {
				c.t.Fatalf("ListTokens: page of %d records, limit 3", len(page.Records))
			}
			for _, r := range page.Records {
				got = append(got, r.Token)
				state := core.TokenActive
				if r.Token == "sub_03" {
					state = core.TokenForgotten
				}
				if r.State != state {
					c.t.Fatalf("ListTokens: %s is %s, want %s", r.Token, r.State, state)
				}
			}
			if page.Cursor == nil {
				break
			}
			cursor = page.Cursor
		}
		if !slices.Equal(got, want) {
			c.t.Fatalf("ListTokens: expect %v, got %v", want, got)
		}
	})

	run("R-TE-7 PurgeNamespace removes every record", func(c *tokenCheck) {
		a, b := c.insert("tok-a"), c.insert("tok-b")
		c.must(c.eng.Forget(c.ctx, c.ns, b.Token, time.Now()), "Forget")
		for range 2 {
			c.must(c.eng.PurgeNamespace(c.ctx, c.ns), "PurgeNamespace")
		}
		page, err := c.eng.ListTokens(c.ctx, c.ns, core.ListTokensQuery{})
		c.must(err, "ListTokens")
		if len(page.Records) != 0 || c.indexOf(a.Index) != "" {
			c.t.Fatalf("PurgeNamespace left %d records", len(page.Records))
		}
		c.sealed(a.Token, "PurgeNamespace", false)
		c.sealed(b.Token, "PurgeNamespace", false)
		c.must(c.eng.Insert(c.ctx, c.ns, a), "Insert after PurgeNamespace")
	})

	run("R-TE-8 namespaces are isolated", func(c *tokenCheck) {
		other := c.in(newNamespace(c.cfg.Namespace))
		r := c.insert("tok-shared")
		c.must(c.eng.Insert(c.ctx, other.ns, r), "Insert of the same record in another namespace")
		c.must(c.eng.Forget(c.ctx, c.ns, r.Token, time.Now()), "Forget")
		if other.state(r.Token) != core.TokenActive || other.indexOf(r.Index) != r.Token {
			c.t.Fatal("Forget changed another namespace")
		}
		c.must(c.eng.PurgeNamespace(c.ctx, c.ns), "PurgeNamespace")
		if other.state(r.Token) != core.TokenActive {
			c.t.Fatal("PurgeNamespace changed another namespace")
		}
	})
}

// newRecord returns an active record with random opaque index and sealed
// bytes, as the protector would produce them.
func newRecord(token string) core.VaultRecord {
	return core.VaultRecord{
		Token:     token,
		Index:     randomBytes(32),
		Sealed:    randomBytes(48),
		State:     core.TokenActive,
		CreatedAt: time.Now().Unix(),
	}
}

type tokenCheck struct {
	t   *testing.T
	ctx context.Context
	eng core.TokenEngine
	cfg *TokenEngineTestConfig
	ns  string
}

func (c *tokenCheck) in(ns string) *tokenCheck {
	o := *c
	o.ns = ns
	return &o
}

func (c *tokenCheck) must(err error, what string) {
	c.t.Helper()
	if err != nil {
		c.t.Fatalf("%s: %v", what, err)
	}
}

func (c *tokenCheck) notFound(err error, what string) {
	c.t.Helper()
	if !errors.Is(err, core.ErrTokenNotFound) {
		c.t.Fatalf("%s: expect core.ErrTokenNotFound, got %v", what, err)
	}
}

func (c *tokenCheck) taken(err error, winner string) {
	c.t.Helper()
	var taken *core.IndexTakenError
	if !errors.As(err, &taken) || taken.Token != winner {
		c.t.Fatalf("Insert of a taken index: expect *core.IndexTakenError naming %s, got %v", winner, err)
	}
}

// insert stores a new active record whose token starts with prefix.
func (c *tokenCheck) insert(prefix string) core.VaultRecord {
	c.t.Helper()
	r := newRecord(prefix + "-" + randomID())
	c.must(c.eng.Insert(c.ctx, c.ns, r), "Insert")
	return r
}

func (c *tokenCheck) record(token string) core.VaultRecord {
	c.t.Helper()
	got, err := c.eng.GetRecords(c.ctx, c.ns, []string{token})
	c.must(err, "GetRecords")
	return got[token]
}

func (c *tokenCheck) state(token string) core.TokenState {
	c.t.Helper()
	return c.record(token).State
}

func (c *tokenCheck) indexOf(index []byte) string {
	c.t.Helper()
	got, err := c.eng.LookupIndex(c.ctx, c.ns, [][]byte{index})
	c.must(err, "LookupIndex")
	return got[string(index)]
}

// sealed checks with SealedProbe that the token's sealed value is gone,
// or, with want set, still stored.
func (c *tokenCheck) sealed(token, after string, want bool) {
	c.t.Helper()
	if c.cfg.SealedProbe == nil {
		return
	}
	stored, err := c.cfg.SealedProbe(c.ctx, c.ns, token)
	c.must(err, "SealedProbe")
	if stored != want {
		c.t.Fatalf("sealed value of %s: expect stored=%v after %s, got %v", token, want, after, stored)
	}
}
