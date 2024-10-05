package privacytest

import (
	"context"
	"reflect"
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
}
