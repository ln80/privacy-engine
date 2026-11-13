package privacy

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/ln80/privacy-engine/core"
)

// Token vault v2: the protector's side (privacy-engine.elastic
// docs/token-vault-v2.md). The token engine only stores opaque records; the
// protector seals each value with a key derived from the namespace's "@vault"
// DEK, finds existing tokens through a keyed blind index, and decides what a
// record's state means.

// maxTokenAttempts bounds retries when a generated token already exists.
const maxTokenAttempts = 5

var errVaultKeyMissing = errors.New("vault key is missing for a namespace that has active tokens")

// vaultKeysFor returns the namespace's derived vault keys. With create, the
// "@vault" DEK is created on first use; without it, ok is false when the
// namespace has never tokenized (or was purged).
func (p *protector) vaultKeysFor(ctx context.Context, create bool) (vk vaultKeys, ok bool, err error) {
	var keys core.KeyMap
	if create {
		keys, err = p.KeyEngine.GetOrCreateKeys(ctx, p.namespace, []string{vaultKeyID}, p.Encryptor.KeyGen())
	} else {
		keys, _, err = p.KeyEngine.GetKeys(ctx, p.namespace, []string{vaultKeyID})
	}
	if err != nil {
		return vaultKeys{}, false, err
	}
	defer zeroKeyMap(keys)
	dek, ok := keys[vaultKeyID]
	if !ok {
		if create {
			// Only Forget or DeleteKey could have removed it, and both refuse
			// reserved IDs: a missing key here is a broken store.
			return vaultKeys{}, false, errVaultKeyMissing
		}
		return vaultKeys{}, false, nil
	}
	vk, err = deriveVaultKeys(dek)
	if err != nil {
		return vaultKeys{}, false, err
	}
	return vk, true, nil
}

// Tokenize implements Protector.
func (p *protector) Tokenize(ctx context.Context, values []core.TokenData, opts ...func(*core.TokenizeConfig)) (result core.ValueTokenMap, err error) {
	if p.TokenEngine == nil {
		return nil, core.ErrTokenEngineNotConfigured
	}
	defer func() {
		if err != nil {
			result = nil
			err = errors.Join(core.ErrTokenizeFailure, err)
		}
	}()

	cfg := core.TokenizeConfig{TokenGenFunc: core.DefaultTokenGen}
	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}
	if cfg.TokenGenFunc == nil {
		return nil, core.ErrTokenGenFuncNotFound
	}
	if isReservedID(cfg.Prefix) {
		return nil, ErrReservedSubjectID
	}

	result = make(core.ValueTokenMap, len(values))
	uniq := slices.Clone(values)
	slices.Sort(uniq)
	uniq = slices.Compact(uniq)
	if len(uniq) == 0 {
		return result, nil
	}

	vk, _, err := p.vaultKeysFor(ctx, true)
	if err != nil {
		return nil, err
	}
	defer vk.zero()

	indexes := make([][]byte, len(uniq))
	for i, v := range uniq {
		indexes[i] = vk.blindIndex([]byte(v))
	}
	hits, err := p.TokenEngine.LookupIndex(ctx, p.namespace, indexes)
	if err != nil {
		return nil, err
	}

	for i, v := range uniq {
		if tok, ok := hits[string(indexes[i])]; ok {
			result[v] = core.TokenRecord{Token: tok, Value: v, State: core.TokenActive}
			continue
		}
		tok, err := p.insertToken(ctx, vk, cfg, v, indexes[i])
		if err != nil {
			return nil, err
		}
		result[v] = core.TokenRecord{Token: tok, Value: v, State: core.TokenActive}
	}
	return result, nil
}

// insertToken creates the vault record of a value the namespace has no token
// for. A generated token that already exists is replaced (PX-20); if another
// Tokenize of the same value won the race, its token is returned (PX-21).
func (p *protector) insertToken(ctx context.Context, vk vaultKeys, cfg core.TokenizeConfig, value core.TokenData, index []byte) (string, error) {
	for range maxTokenAttempts {
		gen, err := cfg.TokenGenFunc(ctx, p.namespace)
		if err != nil {
			return "", err
		}
		tok := cfg.Prefix + gen
		if tok == "" || isReservedID(tok) {
			return "", fmt.Errorf("%w: generated token %q", ErrReservedSubjectID, tok)
		}

		plain := []byte(value)
		sealed, err := vk.seal(p.namespace, tok, plain)
		clear(plain)
		if err != nil {
			return "", err
		}
		err = p.TokenEngine.Insert(ctx, p.namespace, core.VaultRecord{
			Token:     tok,
			Index:     index,
			Sealed:    sealed,
			State:     core.TokenActive,
			CreatedAt: time.Now().Unix(),
		})
		var taken *core.IndexTakenError
		switch {
		case err == nil:
			return tok, nil
		case errors.As(err, &taken):
			return taken.Token, nil
		case errors.Is(err, core.ErrTokenExists):
			continue
		default:
			return "", err
		}
	}
	return "", fmt.Errorf("no unique token after %d attempts", maxTokenAttempts)
}

// openRecords returns the value of each active record. Others are skipped.
func (p *protector) openRecords(ctx context.Context, records []core.VaultRecord) (map[string]core.TokenData, error) {
	active := 0
	for _, r := range records {
		if r.State == core.TokenActive {
			active++
		}
	}
	values := make(map[string]core.TokenData, active)
	if active == 0 {
		return values, nil
	}

	vk, ok, err := p.vaultKeysFor(ctx, false)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, errVaultKeyMissing
	}
	defer vk.zero()

	for _, r := range records {
		if r.State != core.TokenActive {
			continue
		}
		plain, err := vk.open(p.namespace, r.Token, r.Sealed)
		if err != nil {
			return nil, err
		}
		values[r.Token] = core.TokenData(plain)
		clear(plain)
	}
	return values, nil
}

// Detokenize implements Protector.
func (p *protector) Detokenize(ctx context.Context, tokens []string) (result core.TokenValueMap, err error) {
	if p.TokenEngine == nil {
		return nil, core.ErrTokenEngineNotConfigured
	}
	defer func() {
		if err != nil {
			result = nil
			err = errors.Join(core.ErrDetokenizeFailure, err)
		}
	}()

	result = core.TokenValueMap{}
	if len(tokens) == 0 {
		return result, nil
	}
	stored, err := p.TokenEngine.GetRecords(ctx, p.namespace, tokens)
	if err != nil {
		return nil, err
	}
	records := make([]core.VaultRecord, 0, len(stored))
	for _, r := range stored {
		records = append(records, r)
	}
	values, err := p.openRecords(ctx, records)
	if err != nil {
		return nil, err
	}
	for tok, v := range values {
		result[tok] = core.TokenRecord{Token: tok, Value: v, State: core.TokenActive}
	}
	return result, nil
}

// DeleteToken implements Protector. It removes the token and its index entry;
// it does not erase the subject's data (decision V8): Forget does.
func (p *protector) DeleteToken(ctx context.Context, token string) error {
	if p.TokenEngine == nil {
		return core.ErrTokenEngineNotConfigured
	}
	if err := p.TokenEngine.DeleteToken(ctx, p.namespace, token); err != nil {
		return errors.Join(core.ErrDeleteTokenFailure, err)
	}
	return nil
}

// ListTokens implements Protector. Forgotten and erased tokens are listed with
// their state and no value (decision V9).
func (p *protector) ListTokens(ctx context.Context, query core.ListTokensQuery) (*core.ListTokensResult, error) {
	if p.TokenEngine == nil {
		return nil, core.ErrTokenEngineNotConfigured
	}
	page, err := p.TokenEngine.ListTokens(ctx, p.namespace, query)
	if err != nil {
		return nil, err
	}
	values, err := p.openRecords(ctx, page.Records)
	if err != nil {
		return nil, errors.Join(core.ErrDetokenizeFailure, err)
	}
	res := &core.ListTokensResult{Tokens: make([]core.TokenRecord, 0, len(page.Records)), Cursor: page.Cursor}
	for _, r := range page.Records {
		res.Tokens = append(res.Tokens, core.TokenRecord{Token: r.Token, Value: values[r.Token], State: r.State})
	}
	return res, nil
}
