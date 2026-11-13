package memory

import (
	"context"
	"testing"

	"github.com/ln80/privacy-engine/privacytest"
)

func TestTokenEngine(t *testing.T) {
	privacytest.RunTokenEngineTest(t, context.Background(), NewTokenEngine())
}
