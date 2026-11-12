package privacytest

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/ln80/privacy-engine/core"
)

type TokenEngineTestConfig struct {
	Namespace string
}

func RunTokenEngineTest(t *testing.T, ctx context.Context, eng core.TokenEngine, opts ...func(*TokenEngineTestConfig)) {
	cfg := &TokenEngineTestConfig{}
	for _, opt := range opts {
		if opt == nil {
			continue
		}
		opt(cfg)
	}
	namespace := "tenant-dcm30oI"
	if cfg.Namespace != "" {
		namespace = cfg.Namespace
	}

	values := []core.TokenData{
		core.TokenData(randomID()),
		core.TokenData(randomID()),
		core.TokenData(randomID()),
	}

	tokens_1, err := eng.Tokenize(ctx, namespace, values)
	if err != nil {
		t.Fatalf("expect err be nil, got: %v", err)
	}
	if got, want := len(tokens_1), 3; got != want {
		t.Fatalf("expect result map length be %d, got %d", want, got)
	}

	// assert idempotency
	tokens_2, err := eng.Tokenize(ctx, namespace, values)
	if err != nil {
		t.Fatalf("expect err be nil, got: %v", err)
	}
	if want, got := tokens_1, tokens_2; !reflect.DeepEqual(want, got) {
		t.Fatalf("expect %v, %v be equals", want, got)
	}

	result_3, err := eng.Detokenize(ctx, namespace, tokens_1.Tokens())
	if err != nil {
		t.Fatalf("expect err be nil, got: %v", err)
	}
	values_3 := result_3.Values()

	// assert detokenized values are the same as original
	if want, got := values, values_3; !keysEqual(want, got) {
		t.Fatalf("expect %v, %v be equals", want, got)
	}

	var tokenToDelete core.TokenRecord
	for _, token := range tokens_1 {
		tokenToDelete = token
		break
	}
	if err := eng.DeleteToken(ctx, namespace, tokenToDelete.Token); err != nil {
		t.Fatalf("expect err be nil, got: %v", err)
	}

	// assert tokenize a deleted token returns a new fresh one.
	result_4, err := eng.Tokenize(ctx, namespace, values)
	if err != nil {
		t.Fatalf("expect err be nil, got: %v", err)
	}
	if want, got := tokens_1, result_4; reflect.DeepEqual(want, got) {
		t.Fatalf("expect %v, %v not be equals", want, got)
	}

	// PurgeNamespace: create tokens in a sibling namespace, purge the primary,
	// assert sibling intact, primary empty, and purge is idempotent.
	otherNS := namespace + "-other"
	otherTokens, err := eng.Tokenize(ctx, otherNS, values)
	if err != nil {
		t.Fatalf("expect err be nil, got: %v", err)
	}
	if got, want := len(otherTokens), 3; got != want {
		t.Fatalf("expect result map length be %d, got %d", want, got)
	}

	if err := eng.PurgeNamespace(ctx, namespace); err != nil {
		t.Fatalf("expect err be nil, got: %v", err)
	}
	if err := eng.PurgeNamespace(ctx, namespace); err != nil {
		t.Fatalf("expect err be nil, got: %v", err)
	}

	listed, err := eng.ListTokens(ctx, namespace, core.ListTokensQuery{})
	if err != nil {
		t.Fatalf("expect err be nil, got: %v", err)
	}
	if got, want := len(listed.Tokens), 0; got != want {
		t.Fatalf("expect %d tokens after purge, got %d", want, got)
	}

	otherListed, err := eng.ListTokens(ctx, otherNS, core.ListTokensQuery{})
	if err != nil {
		t.Fatalf("expect err be nil, got: %v", err)
	}
	if got, want := len(otherListed.Tokens), 3; got != want {
		t.Fatalf("expect sibling namespace keep %d tokens, got %d", want, got)
	}

	// Fresh tokens can be created after purge
	fresh, err := eng.Tokenize(ctx, namespace, values[:1])
	if err != nil {
		t.Fatalf("expect err be nil, got: %v", err)
	}
	if got, want := len(fresh), 1; got != want {
		t.Fatalf("expect result map length be %d, got %d", want, got)
	}

	// WithPrefix (PE-16): a new token starts with the prefix; an existing
	// value keeps the token it already has.
	prefixed := core.TokenData(randomID())
	withPrefix := func(c *core.TokenizeConfig) { c.Prefix = "sub_" }
	tokens, err := eng.Tokenize(ctx, namespace, []core.TokenData{prefixed}, withPrefix)
	if err != nil {
		t.Fatalf("expect err be nil, got: %v", err)
	}
	if token := tokens.Get(string(prefixed)).Token; !strings.HasPrefix(token, "sub_") || len(token) <= len("sub_") {
		t.Fatalf("expect a token starting with %q, got %q", "sub_", token)
	}
	again, err := eng.Tokenize(ctx, namespace, []core.TokenData{prefixed}, withPrefix)
	if err != nil {
		t.Fatalf("expect err be nil, got: %v", err)
	}
	if again.Get(string(prefixed)).Token != tokens.Get(string(prefixed)).Token {
		t.Fatalf("expect the same token on a second Tokenize")
	}
}
