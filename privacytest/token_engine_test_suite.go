package privacytest

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/ln80/privacy-engine/core"
)

type TokenEngineTestConfig struct {
	Namespace string
	// GracePeriod declares an engine that erases a record forgotten longer
	// than it ago by itself (for example through a storage TTL), without
	// EraseForgotten: the record then reads ERASED with no sealed value and
	// cannot be restored. Zero means the engine relies on EraseForgotten. The
	// rest of the suite forgets records up to two hours in the past and
	// expects them to stay restorable, so it must be longer than three hours.
	GracePeriod time.Duration
	// SealedProbe reads the backend's storage directly, bypassing the engine,
	// and reports whether a sealed value is still stored for token. When set,
	// the suite checks that none is left after Erase, EraseForgotten,
	// DeleteToken and PurgeNamespace. It is not checked for records erased by
	// the grace period: a storage TTL removes the value later, and the engine
	// must only stop returning it.
	SealedProbe func(ctx context.Context, namespace, token string) (stored bool, err error)
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
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

// RunTokenEngineTest is the conformance suite of core.TokenEngine: the opaque
// storage of token vault v2. Every backend must pass it.
func RunTokenEngineTest(t *testing.T, ctx context.Context, eng core.TokenEngine, opts ...func(*TokenEngineTestConfig)) {
	t.Helper()
	cfg := &TokenEngineTestConfig{}
	for _, opt := range opts {
		if opt != nil {
			opt(cfg)
		}
	}
	ns := "tenant-dcm30oI"
	if cfg.Namespace != "" {
		ns = cfg.Namespace
	}
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatalf("expect err be nil, got: %v", err)
		}
	}
	state := func(token string) core.TokenState {
		t.Helper()
		got, err := eng.GetRecords(ctx, ns, []string{token})
		must(err)
		r, ok := got[token]
		if !ok {
			return ""
		}
		return r.State
	}
	noSealed := func(namespace, token, after string) {
		t.Helper()
		if cfg.SealedProbe == nil {
			return
		}
		stored, err := cfg.SealedProbe(ctx, namespace, token)
		must(err)
		if stored {
			t.Fatalf("sealed value of %s is still stored after %s", token, after)
		}
	}
	indexOf := func(idx []byte) string {
		t.Helper()
		got, err := eng.LookupIndex(ctx, ns, [][]byte{idx})
		must(err)
		return got[string(idx)]
	}

	// Insert, then read back through both lookups.
	a, b := newRecord("tok-a-"+randomID()), newRecord("tok-b-"+randomID())
	must(eng.Insert(ctx, ns, a))
	must(eng.Insert(ctx, ns, b))
	idx, err := eng.LookupIndex(ctx, ns, [][]byte{a.Index, b.Index, randomBytes(32)})
	must(err)
	if len(idx) != 2 || idx[string(a.Index)] != a.Token || idx[string(b.Index)] != b.Token {
		t.Fatalf("LookupIndex: got %v", idx)
	}
	recs, err := eng.GetRecords(ctx, ns, []string{a.Token, b.Token, "unknown"})
	must(err)
	if len(recs) != 2 {
		t.Fatalf("GetRecords: got %d records, want 2 (unknown omitted)", len(recs))
	}
	if r := recs[a.Token]; !bytes.Equal(r.Index, a.Index) || !bytes.Equal(r.Sealed, a.Sealed) || r.State != core.TokenActive {
		t.Fatalf("GetRecords: record differs: %+v", r)
	}

	// Returned records are copies.
	recs[a.Token].Sealed[0] ^= 0xff
	again, err := eng.GetRecords(ctx, ns, []string{a.Token})
	must(err)
	if !bytes.Equal(again[a.Token].Sealed, a.Sealed) {
		t.Fatal("mutating a returned record changed the stored one")
	}

	// Collision: the token exists. Nothing is written for the second record.
	dup := newRecord(a.Token)
	if err := eng.Insert(ctx, ns, dup); !errors.Is(err, core.ErrTokenExists) {
		t.Fatalf("Insert existing token: expect ErrTokenExists, got %v", err)
	}
	if indexOf(dup.Index) != "" {
		t.Fatal("a failed Insert wrote its index entry")
	}

	// Taken index: another Tokenize of the same value won.
	race := newRecord("tok-race-" + randomID())
	race.Index = bytes.Clone(a.Index)
	var taken *core.IndexTakenError
	if err := eng.Insert(ctx, ns, race); !errors.As(err, &taken) || taken.Token != a.Token {
		t.Fatalf("Insert taken index: expect IndexTakenError{%s}, got %v", a.Token, err)
	}
	if state(race.Token) != "" {
		t.Fatal("a failed Insert wrote its record")
	}

	// Forget: hidden from its index, kept sealed, first time kept.
	t1 := time.Unix(time.Now().Unix()-100, 0)
	must(eng.Forget(ctx, ns, a.Token, t1))
	must(eng.Forget(ctx, ns, a.Token, t1.Add(50*time.Second)))
	r, err := eng.GetRecords(ctx, ns, []string{a.Token})
	must(err)
	if r[a.Token].State != core.TokenForgotten || r[a.Token].ForgottenAt != t1.Unix() || !bytes.Equal(r[a.Token].Sealed, a.Sealed) {
		t.Fatalf("Forget: got %+v", r[a.Token])
	}
	if indexOf(a.Index) != "" {
		t.Fatal("Forget left the index entry")
	}
	if err := eng.Forget(ctx, ns, "unknown", t1); !errors.Is(err, core.ErrTokenNotFound) {
		t.Fatalf("Forget unknown: expect ErrTokenNotFound, got %v", err)
	}

	// Restore with a free index: reindexed.
	reindexed, err := eng.Restore(ctx, ns, a.Token)
	must(err)
	if !reindexed || state(a.Token) != core.TokenActive || indexOf(a.Index) != a.Token {
		t.Fatalf("Restore: reindexed=%v state=%s index=%q", reindexed, state(a.Token), indexOf(a.Index))
	}
	if reindexed, err := eng.Restore(ctx, ns, a.Token); err != nil || reindexed {
		t.Fatalf("Restore active: expect (false, nil), got (%v, %v)", reindexed, err)
	}

	// Restore after the value was given to a newer token: active, not reindexed.
	must(eng.Forget(ctx, ns, a.Token, t1))
	newer := newRecord("tok-newer-" + randomID())
	newer.Index = bytes.Clone(a.Index)
	must(eng.Insert(ctx, ns, newer))
	reindexed, err = eng.Restore(ctx, ns, a.Token)
	must(err)
	if reindexed || state(a.Token) != core.TokenActive || indexOf(a.Index) != newer.Token {
		t.Fatalf("Restore taken: reindexed=%v state=%s index=%q", reindexed, state(a.Token), indexOf(a.Index))
	}
	if _, err := eng.Restore(ctx, ns, "unknown"); !errors.Is(err, core.ErrTokenNotFound) {
		t.Fatalf("Restore unknown: expect ErrTokenNotFound, got %v", err)
	}

	// Erase: sealed value gone, index entry gone only if it pointed here.
	must(eng.Erase(ctx, ns, a.Token)) // a does not hold its index any more
	must(eng.Erase(ctx, ns, a.Token))
	r, err = eng.GetRecords(ctx, ns, []string{a.Token})
	must(err)
	if r[a.Token].State != core.TokenErased || len(r[a.Token].Sealed) != 0 {
		t.Fatalf("Erase: got %+v", r[a.Token])
	}
	if indexOf(a.Index) != newer.Token {
		t.Fatal("Erase removed an index entry that pointed to another token")
	}
	if _, err := eng.Restore(ctx, ns, a.Token); !errors.Is(err, core.ErrTokenErased) {
		t.Fatalf("Restore erased: expect ErrTokenErased, got %v", err)
	}
	must(eng.Forget(ctx, ns, a.Token, t1)) // no-op on an erased record
	if state(a.Token) != core.TokenErased {
		t.Fatal("Forget changed an erased record")
	}
	must(eng.Erase(ctx, ns, b.Token)) // b holds its index
	if indexOf(b.Index) != "" {
		t.Fatal("Erase left the record's own index entry")
	}
	noSealed(ns, a.Token, "Erase")
	noSealed(ns, b.Token, "Erase")
	if err := eng.Erase(ctx, ns, "unknown"); !errors.Is(err, core.ErrTokenNotFound) {
		t.Fatalf("Erase unknown: expect ErrTokenNotFound, got %v", err)
	}

	// EraseForgotten: only records forgotten strictly before the cutoff.
	old, recent := newRecord("tok-old-"+randomID()), newRecord("tok-recent-"+randomID())
	must(eng.Insert(ctx, ns, old))
	must(eng.Insert(ctx, ns, recent))
	now := time.Now()
	must(eng.Forget(ctx, ns, old.Token, now.Add(-2*time.Hour)))
	must(eng.Forget(ctx, ns, recent.Token, now))
	n, err := eng.EraseForgotten(ctx, ns, now.Add(-time.Hour))
	must(err)
	if n != 1 || state(old.Token) != core.TokenErased || state(recent.Token) != core.TokenForgotten {
		t.Fatalf("EraseForgotten: erased %d, old=%s recent=%s", n, state(old.Token), state(recent.Token))
	}
	noSealed(ns, old.Token, "EraseForgotten")

	// DeleteToken: record and own index entry gone; unknown is a no-op.
	must(eng.DeleteToken(ctx, ns, newer.Token))
	if state(newer.Token) != "" || indexOf(newer.Index) != "" {
		t.Fatal("DeleteToken left the record or its index entry")
	}
	noSealed(ns, newer.Token, "DeleteToken")
	must(eng.DeleteToken(ctx, ns, "unknown"))
	reuse := newRecord("tok-reuse-" + randomID())
	reuse.Index = bytes.Clone(newer.Index)
	must(eng.Insert(ctx, ns, reuse)) // the value can be tokenized again

	// ListTokens: prefix, token order, states, and paging that covers all.
	pns := ns + "-list"
	var listed []string
	for i := range 7 {
		rec := newRecord(fmt.Sprintf("sub_%02d", i))
		must(eng.Insert(ctx, pns, rec))
		listed = append(listed, rec.Token)
	}
	must(eng.Insert(ctx, pns, newRecord("rcp_00")))
	must(eng.Forget(ctx, pns, "sub_03", now))
	var got []string
	var cursor *string
	for pages := 0; ; pages++ {
		if pages > 10 {
			t.Fatal("ListTokens: paging does not end")
		}
		page, err := eng.ListTokens(ctx, pns, core.ListTokensQuery{Prefix: "sub_", Limit: 3, Cursor: cursor})
		must(err)
		if len(page.Records) > 3 {
			t.Fatalf("ListTokens: page of %d records, limit 3", len(page.Records))
		}
		for _, rec := range page.Records {
			got = append(got, rec.Token)
			want := core.TokenActive
			if rec.Token == "sub_03" {
				want = core.TokenForgotten
			}
			if rec.State != want {
				t.Fatalf("ListTokens: %s state %s, want %s", rec.Token, rec.State, want)
			}
		}
		if page.Cursor == nil {
			break
		}
		cursor = page.Cursor
	}
	if !slices.Equal(got, listed) {
		t.Fatalf("ListTokens: got %v, want %v", got, listed)
	}

	// Erasure by the grace period, without EraseForgotten.
	if cfg.GracePeriod > 0 {
		c := newRecord("tok-expired-" + randomID())
		must(eng.Insert(ctx, ns, c))
		must(eng.Forget(ctx, ns, c.Token, time.Now().Add(-cfg.GracePeriod-2*time.Second)))
		got, err := eng.GetRecords(ctx, ns, []string{c.Token})
		must(err)
		if r := got[c.Token]; r.State != core.TokenErased || len(r.Sealed) != 0 {
			t.Fatalf("forgotten past the grace period: got state %s with %d sealed bytes, want ERASED with none", r.State, len(r.Sealed))
		}
		if _, err := eng.Restore(ctx, ns, c.Token); !errors.Is(err, core.ErrTokenErased) {
			t.Fatalf("Restore past the grace period: expect ErrTokenErased, got %v", err)
		}
		if indexOf(c.Index) != "" {
			t.Fatal("a record past the grace period still holds its index entry")
		}
		page, err := eng.ListTokens(ctx, ns, core.ListTokensQuery{Prefix: "tok-expired-"})
		must(err)
		if len(page.Records) != 1 || page.Records[0].State != core.TokenErased || len(page.Records[0].Sealed) != 0 {
			t.Fatalf("ListTokens past the grace period: got %+v", page.Records)
		}
		must(eng.Erase(ctx, ns, c.Token)) // still a no-op, and now physically gone
		noSealed(ns, c.Token, "Erase")
	}

	// PurgeNamespace: everything gone, sibling intact, idempotent.
	sibling := ns + "-other"
	s := newRecord("tok-sibling-" + randomID())
	must(eng.Insert(ctx, sibling, s))
	must(eng.PurgeNamespace(ctx, ns))
	must(eng.PurgeNamespace(ctx, ns))
	all, err := eng.ListTokens(ctx, ns, core.ListTokensQuery{})
	must(err)
	if len(all.Records) != 0 || indexOf(reuse.Index) != "" {
		t.Fatalf("PurgeNamespace left %d records", len(all.Records))
	}
	noSealed(ns, reuse.Token, "PurgeNamespace")
	if got, err := eng.GetRecords(ctx, sibling, []string{s.Token}); err != nil || len(got) != 1 {
		t.Fatalf("PurgeNamespace touched a sibling namespace: %v, %v", got, err)
	}
	must(eng.Insert(ctx, ns, newRecord("tok-after-purge-"+randomID())))
}
