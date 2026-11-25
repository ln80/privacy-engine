package privacy

import (
	"context"

	"github.com/google/uuid"
	"github.com/ln80/privacy-engine/core"
)

// TokenDataSlice returns the given values as a `core.TokenData` slice.
//
// It's mainly used as a helper function to simplify the interaction with the Tokenizer service.
func TokenDataSlice(values ...string) []core.TokenData {
	tokenValues := make([]core.TokenData, len(values))
	for i, v := range values {
		tokenValues[i] = core.TokenData(v)
	}
	return tokenValues
}

// tokenizeConfig is set by TokenizeOption.
type tokenizeConfig struct {
	prefix   string
	generate func(ctx context.Context, namespace string) (string, error)
}

// newUUIDToken generates a random UUID (v4) token.
func newUUIDToken(context.Context, string) (string, error) {
	return uuid.New().String(), nil
}
