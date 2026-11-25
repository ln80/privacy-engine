package memory

import (
	"time"

	"github.com/ln80/privacy-engine/core"
	"github.com/ln80/privacy-engine/internal/keyengine"
)

// WithGracePeriod sets how long a key disabled by a graceful Forget stays
// recoverable (default 7 days). Zero or less keeps the default.
func WithGracePeriod(d time.Duration) func(*core.KeyEngineConfig) {
	return func(c *core.KeyEngineConfig) { c.GracePeriod = d }
}

// NewKeyEngine returns an in-memory core.KeyEngine, for tests and local
// development only: it loses every key on restart.
//
// A key disabled for longer than the grace period (core.NewKeyEngineConfig,
// 7 days by default) is reported DELETED and cannot be re-enabled;
// DeleteUnusedKeys wipes its material. A zero or negative GracePeriod keeps
// the default.
func NewKeyEngine(opts ...func(*core.KeyEngineConfig)) core.KeyEngine {
	cfg := core.NewKeyEngineConfig()
	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}
	return keyengine.NewStore(cfg.GracePeriod)
}
