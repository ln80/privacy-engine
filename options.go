package privacy

import (
	"time"

	"github.com/ln80/privacy-engine/core"
)

// ProtectorOption configures NewProtector. Use the With* options below; a
// func(*ProtectorConfig) that sets fields directly is the same type and
// works too.
type ProtectorOption = func(*ProtectorConfig)

// WithTokenEngine enables tokenization, storing the token vault in engine.
// Without it the token methods fail with core.ErrTokenEngineNotConfigured.
func WithTokenEngine(engine core.TokenEngine) ProtectorOption {
	return func(c *ProtectorConfig) { c.TokenEngine = engine }
}

// WithEncryptor replaces the default AES-256-GCM encryptor.
func WithEncryptor(enc core.Encryptor) ProtectorOption {
	return func(c *ProtectorConfig) { c.Encryptor = enc }
}

// WithCacheTTL caches keys in memory for ttl (default 20s). The TTL bounds how
// long a subject forgotten through another instance stays readable here. A
// ttl of zero or less keeps the default.
func WithCacheTTL(ttl time.Duration) ProtectorOption {
	return func(c *ProtectorConfig) {
		c.CacheEnabled = true
		c.CacheTTL = max(ttl, 0)
	}
}

// WithoutCache reads every key from the key engine: a Forget made elsewhere
// applies at once, at the cost of one key engine call per operation.
func WithoutCache() ProtectorOption {
	return func(c *ProtectorConfig) { c.CacheEnabled = false }
}

// WithImmediateErasure makes every Forget erase at once, with no grace period
// and no Recover. By default Forget is graceful; Immediately() erases at once
// for a single call.
func WithImmediateErasure() ProtectorOption {
	return func(c *ProtectorConfig) { c.GracefulMode = false }
}

// WithMultipleSubjects lets Encrypt accept a struct whose data belongs to
// several subjects, each field encrypted under its nearest subject. By
// default a struct must use one subject.
func WithMultipleSubjects() ProtectorOption {
	return func(c *ProtectorConfig) { c.MultipleSubjects = true }
}

// WithForgottenValue sets what Decrypt puts in a field whose subject is
// forgotten, when the field's tag has no replace= option. Default "".
func WithForgottenValue(v string) ProtectorOption {
	return func(c *ProtectorConfig) { c.ForgottenValue = v }
}

// WithAuditor sends an AuditEvent to a for every erasure and
// re-identification (docs/audit-events.md).
func WithAuditor(a Auditor) ProtectorOption {
	return func(c *ProtectorConfig) { c.Auditor = a }
}

// FactoryOption configures NewFactory. A func(*FactoryConfig) works too.
type FactoryOption = func(*FactoryConfig)

// WithIdleTimeout sets how long a Protector may go unused before Monitor
// evicts it (default 20 minutes).
func WithIdleTimeout(d time.Duration) FactoryOption {
	return func(c *FactoryConfig) { c.IDLE = d }
}

// WithMonitorPeriod sets how often Monitor clears expired cache entries and
// evicts idle Protectors (default 5s).
func WithMonitorPeriod(d time.Duration) FactoryOption {
	return func(c *FactoryConfig) { c.MonitorPeriod = d }
}
