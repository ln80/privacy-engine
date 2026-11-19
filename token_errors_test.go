package privacy

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/ln80/privacy-engine/core"
	"github.com/ln80/privacy-engine/memory"
)

// brokenTokenStore fails every call a token method makes first.
type brokenTokenStore struct{ core.TokenEngine }

var errStoreDown = errors.New("store down")

func (brokenTokenStore) LookupIndex(context.Context, string, [][]byte) (map[string]string, error) {
	return nil, errStoreDown
}
func (brokenTokenStore) GetRecords(context.Context, string, []string) (map[string]core.VaultRecord, error) {
	return nil, errStoreDown
}
func (brokenTokenStore) DeleteToken(context.Context, string, string) error { return errStoreDown }
func (brokenTokenStore) ListTokens(context.Context, string, core.ListTokensQuery) (*core.ListRecordsResult, error) {
	return nil, errStoreDown
}

// Token methods fail like the other Protector methods: a privacy.Error of
// their category, with the namespace, wrapping the cause, on one line.
func TestTokenMethodErrors(t *testing.T) {
	ctx := context.Background()
	broken := NewProtector("tenant-e", memory.NewKeyEngine(), func(pc *ProtectorConfig) {
		pc.TokenEngine = brokenTokenStore{memory.NewTokenEngine()}
	})
	none := NewProtector("tenant-e", memory.NewKeyEngine())

	calls := map[string]struct {
		category Error
		call     func(Protector) error
	}{
		"Tokenize": {ErrTokenizeFailure, func(p Protector) error {
			_, err := p.Tokenize(ctx, TokenDataSlice("a@example.com"))
			return err
		}},
		"Detokenize": {ErrDetokenizeFailure, func(p Protector) error {
			_, err := p.Detokenize(ctx, []string{"tok"})
			return err
		}},
		"DeleteToken": {ErrDeleteTokenFailure, func(p Protector) error {
			return p.DeleteToken(ctx, "tok")
		}},
		"ListTokens": {ErrListTokensFailure, func(p Protector) error {
			_, err := p.ListTokens(ctx, core.ListTokensQuery{})
			return err
		}},
	}
	for name, c := range calls {
		t.Run(name, func(t *testing.T) {
			for cause, p := range map[error]Protector{errStoreDown: broken, core.ErrTokenEngineNotConfigured: none} {
				err := c.call(p)
				var perr Error
				if !errors.Is(err, c.category) || !errors.Is(err, cause) || !errors.As(err, &perr) {
					t.Fatalf("expect %v wrapping %v, got %v", c.category, cause, err)
				}
				if perr.Namespace() != "tenant-e" {
					t.Fatalf("expect the namespace on the error, got %q", perr.Namespace())
				}
				if strings.Contains(err.Error(), "\n") {
					t.Fatalf("expect a one-line message, got %q", err.Error())
				}
			}
		})
	}
}
