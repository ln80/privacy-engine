package memory

import (
	"testing"

	"github.com/ln80/privacy-engine/privacytest"
)

func TestKeyWrapper(t *testing.T) {
	privacytest.TestKeyWrapper(t, NewKeyWrapper())
}
