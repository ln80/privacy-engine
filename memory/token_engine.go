package memory

import (
	"bytes"
	"context"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/ln80/privacy-engine/core"
)

// TokenEngine is an in-memory core.TokenEngine, mainly for tests. It stores
// opaque records and index entries, never values.
type TokenEngine struct {
	mu sync.Mutex
	ns map[string]*vault
}

var _ core.TokenEngine = &TokenEngine{}

type vault struct {
	records map[string]core.VaultRecord // by token
	index   map[string]string           // string(index) -> token
}

// NewTokenEngine returns an empty in-memory token vault.
func NewTokenEngine() *TokenEngine {
	return &TokenEngine{ns: make(map[string]*vault)}
}

// vaultOf returns the namespace's vault, creating it. Caller holds t.mu.
func (t *TokenEngine) vaultOf(namespace string) *vault {
	v, ok := t.ns[namespace]
	if !ok {
		v = &vault{records: map[string]core.VaultRecord{}, index: map[string]string{}}
		t.ns[namespace] = v
	}
	return v
}

func cloneRecord(r core.VaultRecord) core.VaultRecord {
	r.Index = bytes.Clone(r.Index)
	r.Sealed = bytes.Clone(r.Sealed)
	return r
}

// unindex removes the record's index entry if it still points to it.
func (v *vault) unindex(r core.VaultRecord) {
	if v.index[string(r.Index)] == r.Token {
		delete(v.index, string(r.Index))
	}
}

// LookupIndex implements core.TokenEngine.
func (t *TokenEngine) LookupIndex(ctx context.Context, namespace string, indexes [][]byte) (map[string]string, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	v := t.vaultOf(namespace)
	out := make(map[string]string, len(indexes))
	for _, idx := range indexes {
		if tok, ok := v.index[string(idx)]; ok {
			out[string(idx)] = tok
		}
	}
	return out, nil
}

// GetRecords implements core.TokenEngine.
func (t *TokenEngine) GetRecords(ctx context.Context, namespace string, tokens []string) (map[string]core.VaultRecord, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	v := t.vaultOf(namespace)
	out := make(map[string]core.VaultRecord, len(tokens))
	for _, tok := range tokens {
		if r, ok := v.records[tok]; ok {
			out[tok] = cloneRecord(r)
		}
	}
	return out, nil
}

// Insert implements core.TokenEngine.
func (t *TokenEngine) Insert(ctx context.Context, namespace string, record core.VaultRecord) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	v := t.vaultOf(namespace)
	if _, ok := v.records[record.Token]; ok {
		return core.ErrTokenExists
	}
	if tok, ok := v.index[string(record.Index)]; ok {
		return &core.IndexTakenError{Token: tok}
	}
	record = cloneRecord(record)
	record.State = core.TokenActive
	record.ForgottenAt = 0
	v.records[record.Token] = record
	v.index[string(record.Index)] = record.Token
	return nil
}

// Forget implements core.TokenEngine.
func (t *TokenEngine) Forget(ctx context.Context, namespace, token string, at time.Time) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	v := t.vaultOf(namespace)
	r, ok := v.records[token]
	if !ok {
		return core.ErrTokenNotFound
	}
	if r.State != core.TokenActive {
		return nil
	}
	v.unindex(r)
	r.State = core.TokenForgotten
	r.ForgottenAt = at.Unix()
	v.records[token] = r
	return nil
}

// Restore implements core.TokenEngine.
func (t *TokenEngine) Restore(ctx context.Context, namespace, token string) (bool, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	v := t.vaultOf(namespace)
	r, ok := v.records[token]
	switch {
	case !ok:
		return false, core.ErrTokenNotFound
	case r.State == core.TokenErased:
		return false, core.ErrTokenErased
	case r.State == core.TokenActive:
		return false, nil
	}
	r.State = core.TokenActive
	r.ForgottenAt = 0
	v.records[token] = r
	if _, taken := v.index[string(r.Index)]; taken {
		return false, nil
	}
	v.index[string(r.Index)] = token
	return true, nil
}

// Erase implements core.TokenEngine.
func (t *TokenEngine) Erase(ctx context.Context, namespace, token string) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	v := t.vaultOf(namespace)
	r, ok := v.records[token]
	if !ok {
		return core.ErrTokenNotFound
	}
	v.erase(r)
	return nil
}

// erase removes the sealed value and the index entry. Caller holds t.mu.
func (v *vault) erase(r core.VaultRecord) {
	v.unindex(r)
	clear(r.Sealed)
	r.Sealed = nil
	r.State = core.TokenErased
	v.records[r.Token] = r
}

// EraseForgotten implements core.TokenEngine.
func (t *TokenEngine) EraseForgotten(ctx context.Context, namespace string, before time.Time) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	v := t.vaultOf(namespace)
	n := 0
	for _, r := range v.records {
		if r.State == core.TokenForgotten && r.ForgottenAt < before.Unix() {
			v.erase(r)
			n++
		}
	}
	return n, nil
}

// DeleteToken implements core.TokenEngine.
func (t *TokenEngine) DeleteToken(ctx context.Context, namespace string, token string) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	v := t.vaultOf(namespace)
	if r, ok := v.records[token]; ok {
		v.unindex(r)
		clear(r.Sealed)
		delete(v.records, token)
	}
	return nil
}

// ListTokens implements core.TokenEngine.
func (t *TokenEngine) ListTokens(ctx context.Context, namespace string, query core.ListTokensQuery) (*core.ListRecordsResult, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	v := t.vaultOf(namespace)

	tokens := make([]string, 0, len(v.records))
	for tok := range v.records {
		if strings.HasPrefix(tok, query.Prefix) && (query.Cursor == nil || tok > *query.Cursor) {
			tokens = append(tokens, tok)
		}
	}
	slices.Sort(tokens)

	res := &core.ListRecordsResult{Records: []core.VaultRecord{}}
	if query.Limit > 0 && len(tokens) > query.Limit {
		tokens = tokens[:query.Limit]
		last := tokens[len(tokens)-1]
		res.Cursor = &last
	}
	for _, tok := range tokens {
		res.Records = append(res.Records, cloneRecord(v.records[tok]))
	}
	return res, nil
}

// PurgeNamespace implements core.TokenEngine.
func (t *TokenEngine) PurgeNamespace(ctx context.Context, namespace string) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if v, ok := t.ns[namespace]; ok {
		for _, r := range v.records {
			clear(r.Sealed)
		}
	}
	delete(t.ns, namespace)
	return nil
}
