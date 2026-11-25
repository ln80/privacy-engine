package memory

import (
	"testing"
	"time"

	"github.com/ln80/privacy-engine/privacytest"
)

func TestKeyEngine(t *testing.T) {
	grace := 200 * time.Millisecond
	privacytest.TestKeyEngine(t, NewKeyEngine(WithGracePeriod(grace)), func(c *privacytest.KeyEngineTestConfig) {
		c.GracePeriod = grace
	})
}
