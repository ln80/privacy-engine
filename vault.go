package privacy

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/ln80/privacy-engine/core"
)

// Token vault: the protector's side (docs/token-vault.md). The token engine only stores opaque records; the
// protector seals each value with a key derived from the namespace's "@vault"
// DEK, finds existing tokens through a keyed blind index, and decides what a
// record's state means.

// maxTokenAttempts bounds retries when a generated token already exists.
const maxTokenAttempts = 5

var errVaultKeyMissing = errors.New("vault key is missing for a namespace that has active tokens")

// Errors returned by the Protector's token methods. Each wraps the cause:
// core.ErrTokenEngineNotConfigured, an engine error, or a vault error
// (core.ErrDecryptionFailure for a sealed value that does not authenticate).
var (
	ErrTokenizeFailure    = newErr("failed to tokenize")
	ErrDetokenizeFailure  = newErr("failed to detokenize")
	ErrDeleteTokenFailure = newErr("failed to delete token")
	ErrListTokensFailure  = newErr("failed to list tokens")
)

// wrapTokenErr wraps a token method's error in its category, with the namespace.
func (p *Protector) wrapTokenErr(category Error, err error) error {
	if err == nil {
		return nil
	}
	return category.withBase(err).withNamespace(p.namespace)
}

// vaultKeysFor returns the namespace's derived vault keys. With create, the
// "@vault" DEK is created on first use; without it, ok is false when the
// namespace has never tokenized (or was purged).
func (p *Protector) vaultKeysFor(ctx context.Context, create bool) (vk vaultKeys, ok bool, err error) {
	var keys core.KeyMap
	if create {
		keys, err = p.cfg.KeyEngine.GetOrCreateKeys(ctx, p.namespace, []string{vaultKeyID}, p.cfg.Encryptor.KeyGen())
	} else {
		keys, _, err = p.cfg.KeyEngine.GetKeys(ctx, p.namespace, []string{vaultKeyID})
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

// Tokenize returns the token of each value, creating one for a value the
// namespace has never seen (or whose token was forgotten). The vault stores
// each value sealed and looked up through a keyed blind index: never in
// clear (token vault v2, see vault.go).
func (p *Protector) Tokenize(ctx context.Context, values []core.TokenData, opts ...func(*core.TokenizeConfig)) (result core.ValueTokenMap, err error) {
	defer func() {
		if err != nil {
			result = nil
			err = p.wrapTokenErr(ErrTokenizeFailure, err)
		}
	}()
	if p.cfg.TokenEngine == nil {
		return nil, core.ErrTokenEngineNotConfigured
	}

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
	hits, err := p.cfg.TokenEngine.LookupIndex(ctx, p.namespace, indexes)
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
// for. A generated token that already exists is replaced; if another
// Tokenize of the same value won the race, its token is returned.
func (p *Protector) insertToken(ctx context.Context, vk vaultKeys, cfg core.TokenizeConfig, value core.TokenData, index []byte) (string, error) {
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
		err = p.cfg.TokenEngine.Insert(ctx, p.namespace, core.VaultRecord{
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
func (p *Protector) openRecords(ctx context.Context, records []core.VaultRecord) (map[string]core.TokenData, error) {
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

// detokenize implements Protector.Detokenize.
func (p *Protector) detokenize(ctx context.Context, tokens []string) (result core.TokenValueMap, err error) {
	defer func() {
		if err != nil {
			result = nil
			err = p.wrapTokenErr(ErrDetokenizeFailure, err)
		}
	}()
	if p.cfg.TokenEngine == nil {
		return nil, core.ErrTokenEngineNotConfigured
	}

	result = core.TokenValueMap{}
	if len(tokens) == 0 {
		return result, nil
	}
	stored, err := p.cfg.TokenEngine.GetRecords(ctx, p.namespace, tokens)
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

// deleteToken implements Protector.DeleteToken. It removes the token and its index entry;
// it does not erase the subject's data: Forget does.
func (p *Protector) deleteToken(ctx context.Context, token string) error {
	if p.cfg.TokenEngine == nil {
		return p.wrapTokenErr(ErrDeleteTokenFailure, core.ErrTokenEngineNotConfigured)
	}
	return p.wrapTokenErr(ErrDeleteTokenFailure, p.cfg.TokenEngine.DeleteToken(ctx, p.namespace, token))
}

// listTokens implements Protector.ListTokens. Forgotten and erased tokens are listed with
// their state and no value.
func (p *Protector) listTokens(ctx context.Context, query core.ListTokensQuery) (*core.ListTokensResult, error) {
	if p.cfg.TokenEngine == nil {
		return nil, p.wrapTokenErr(ErrListTokensFailure, core.ErrTokenEngineNotConfigured)
	}
	page, err := p.cfg.TokenEngine.ListTokens(ctx, p.namespace, query)
	if err != nil {
		return nil, p.wrapTokenErr(ErrListTokensFailure, err)
	}
	values, err := p.openRecords(ctx, page.Records)
	if err != nil {
		return nil, p.wrapTokenErr(ErrListTokensFailure, err)
	}
	res := &core.ListTokensResult{Tokens: make([]core.TokenRecord, 0, len(page.Records)), Cursor: page.Cursor}
	for _, r := range page.Records {
		res.Tokens = append(res.Tokens, core.TokenRecord{Token: r.Token, Value: values[r.Token], State: r.State})
	}
	return res, nil
}
