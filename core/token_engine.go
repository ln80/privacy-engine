package core

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
)

var (
	ErrTokenNotFound            = errors.New("token not found")
	ErrTokenErased              = errors.New("token is erased")
	ErrTokenExists              = errors.New("token already exists")
	ErrTokenGenFuncNotFound     = errors.New("token gen function is not found")
	ErrDetokenizeFailure        = errors.New("failed to detokenize token(s)")
	ErrTokenizeFailure          = errors.New("failed to tokenize value(s)")
	ErrDeleteTokenFailure       = errors.New("failed to delete token")
	ErrPurgeTokenFailure        = errors.New("failed to purge tokens")
	ErrTokenEngineNotConfigured = errors.New("token engine is not configured")
)

// IndexTakenError is returned by TokenEngine.Insert when the record's index
// already points to another token: another Tokenize of the same value won.
// Token is that winning token.
type IndexTakenError struct {
	Token string
}

func (e *IndexTakenError) Error() string {
	return "index already points to another token"
}

// TokenData presents a sensitive data that should be tokenized.
//
// TokenData redacts itself in fmt (every verb), log/slog, encoding/json and
// encoding text (see redact.go). Use Reveal to get the value.
type TokenData string

// Reveal returns the string value of token data as the `String` method redacts
// data by default.
func (t TokenData) Reveal() string {
	return string(t)
}

// TokenState is the lifecycle state of a token's vault entry.
type TokenState string

const (
	// TokenActive: the value can be read and the token is found by its value.
	TokenActive TokenState = "ACTIVE"
	// TokenForgotten: the token was forgotten. Its value is hidden and no
	// longer finds the token, but stays sealed so Recover can restore it.
	TokenForgotten TokenState = "FORGOTTEN"
	// TokenErased: the sealed value is gone. The token can never resolve again.
	TokenErased TokenState = "ERASED"
)

// ValueTokenMap maps token data to tokens
type ValueTokenMap map[TokenData]TokenRecord

// Get the token of the given value
func (m ValueTokenMap) Get(v string) TokenRecord {
	return m[TokenData(v)]
}

func (m ValueTokenMap) Tokens() []string {
	tokens := []string{}
	for _, r := range m {
		tokens = append(tokens, r.Token)
	}
	return tokens
}

// ValueTokenMap maps token to token data
type TokenValueMap map[string]TokenRecord

// Get the value of the given token
func (m TokenValueMap) Get(t string) TokenRecord {
	return m[t]
}

func (m TokenValueMap) Values() []TokenData {
	values := []TokenData{}
	for _, r := range m {
		values = append(values, r.Value)
	}
	return values
}

// TokenRecord contains a token, its value and its state. Value is empty
// unless State is TokenActive.
type TokenRecord struct {
	Token string
	Value TokenData
	State TokenState
}

// TokenizeConfig configures one Tokenize call.
type TokenizeConfig struct {
	// Prefix is prepended to every new token, e.g. "sub_".
	Prefix string

	// TokenGenFunc generates the random part of a new token. It does not
	// receive the value: a token must never be derived from it, as hashed
	// emails can be reversed by brute force (PX-23).
	TokenGenFunc func(ctx context.Context, namespace string) (string, error)
}

// DefaultTokenGen generates a random UUID (v4) token.
func DefaultTokenGen(ctx context.Context, namespace string) (string, error) {
	return uuid.New().String(), nil
}

// VaultRecord is a token's entry as stored. Index and Sealed are opaque to
// storage: the protector computes them, and no engine ever sees a value.
type VaultRecord struct {
	Token string

	// Index is the blind index of the value (an HMAC). The record is found
	// through it while active.
	Index []byte

	// Sealed is the encrypted value. It is nil once the record is erased.
	Sealed []byte

	State TokenState

	// CreatedAt and ForgottenAt are Unix seconds; ForgottenAt is 0 unless the
	// record is forgotten or was erased after being forgotten.
	CreatedAt   int64
	ForgottenAt int64
}

// TokenEngine stores a namespace's token vault: token records and the index
// entries that map a value's blind index to its token. It never receives a
// value in clear. Every method is safe for concurrent use, and every record
// or slice it returns is a copy the caller owns.
type TokenEngine interface {
	// LookupIndex returns, for each index that has an entry, the token it
	// points to, keyed by string(index). Indexes without an entry are omitted.
	LookupIndex(ctx context.Context, namespace string, indexes [][]byte) (map[string]string, error)

	// GetRecords returns the records of the given tokens. Unknown tokens are
	// omitted.
	GetRecords(ctx context.Context, namespace string, tokens []string) (map[string]VaultRecord, error)

	// Insert stores an active record and the index entry pointing to it, both
	// or neither. It returns ErrTokenExists when the token already exists, and
	// *IndexTakenError when the index already points to another token.
	Insert(ctx context.Context, namespace string, record VaultRecord) error

	// Forget marks an active record forgotten at the given time and removes
	// the index entry if it still points to the token. A record already
	// forgotten or erased is left as is (the first time is kept). It returns
	// ErrTokenNotFound for an unknown token.
	Forget(ctx context.Context, namespace, token string, at time.Time) error

	// Restore makes a forgotten record active again and recreates its index
	// entry if no other token holds that index; reindexed reports whether it
	// did. An active record is left as is. It returns ErrTokenErased for an
	// erased record and ErrTokenNotFound for an unknown token.
	Restore(ctx context.Context, namespace, token string) (reindexed bool, err error)

	// Erase removes a record's sealed value and its index entry (if it still
	// points to the token) and marks it erased. Erasing an erased record is a
	// no-op. It returns ErrTokenNotFound for an unknown token.
	Erase(ctx context.Context, namespace, token string) error

	// EraseForgotten erases every record forgotten strictly before the given
	// time and returns how many it erased.
	EraseForgotten(ctx context.Context, namespace string, before time.Time) (erased int, err error)

	// DeleteToken deletes a record and its index entry if it still points to
	// the token. Deleting an unknown token is a no-op.
	DeleteToken(ctx context.Context, namespace string, token string) error

	// ListTokens returns records whose token starts with query.Prefix, in
	// token order, at most query.Limit of them (all when Limit is 0), after
	// query.Cursor. The result's Cursor is nil on the last page.
	ListTokens(ctx context.Context, namespace string, query ListTokensQuery) (*ListRecordsResult, error)

	// PurgeNamespace hard-deletes every record and index entry in the
	// namespace. Idempotent.
	PurgeNamespace(ctx context.Context, namespace string) error
}

// ListTokensQuery selects a page of tokens. There is no search on values:
// the vault does not hold them in clear.
type ListTokensQuery struct {
	Prefix string
	Limit  int
	Cursor *string
}

// ListRecordsResult is a page of stored records.
type ListRecordsResult struct {
	Records []VaultRecord
	Cursor  *string
}

// ListTokensResult is a page of tokens as the protector returns them.
type ListTokensResult struct {
	Tokens []TokenRecord
	Cursor *string
}
