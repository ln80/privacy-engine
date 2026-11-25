package privacy

import (
	"context"
	"io"

	"github.com/ln80/privacy-engine/core"
)

// Role interfaces: each is a part of *Protector that code can depend on
// instead of the whole. They keep fakes small and make least privilege
// visible: a service handed a Tokenizer can create pseudonyms but not reveal
// them. They are not a security boundary (a caller can type-assert back to
// *Protector); separate credentials are.

// Encrypter encrypts and decrypts personal data under subjects' keys.
type Encrypter interface {
	Encrypt(ctx context.Context, structPtrs ...any) error
	Decrypt(ctx context.Context, structPtrs ...any) error
	EncryptStream(ctx context.Context, subID string, r io.Reader) (io.Reader, error)
	DecryptStream(ctx context.Context, subID string, r io.Reader) (io.Reader, error)
}

// Shredder erases and recovers subjects, and deletes tokens and namespaces.
type Shredder interface {
	Forget(ctx context.Context, subID string, opts ...ForgetOption) error
	Recover(ctx context.Context, subID string) error
	DeleteToken(ctx context.Context, token string) error
	Purge(ctx context.Context) error
}

// Tokenizer replaces values with pseudonymous tokens. It cannot reveal them.
type Tokenizer interface {
	Tokenize(ctx context.Context, values []core.TokenData, opts ...TokenizeOption) (core.ValueTokenMap, error)
}

// Reidentifier reveals the values behind tokens. Every call is audited when
// the Protector has an Auditor.
type Reidentifier interface {
	Detokenize(ctx context.Context, tokens []string) (core.TokenValueMap, error)
	ListTokens(ctx context.Context, query core.ListTokensQuery) (*core.ListTokensResult, error)
}

var (
	_ Encrypter    = (*Protector)(nil)
	_ Shredder     = (*Protector)(nil)
	_ Tokenizer    = (*Protector)(nil)
	_ Reidentifier = (*Protector)(nil)
)
