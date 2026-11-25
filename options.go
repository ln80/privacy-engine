package privacy

import (
	"context"
	"time"

	"github.com/ln80/privacy-engine/core"
)

// ProtectorOption configures NewProtector. The With* functions below build
// them.
type ProtectorOption func(*protectorConfig)

// WithTokenEngine enables tokenization, storing the token vault in engine.
// Without it the token methods fail with core.ErrTokenEngineNotConfigured.
func WithTokenEngine(engine core.TokenEngine) ProtectorOption {
	return func(c *protectorConfig) { c.TokenEngine = engine }
}

// WithEncryptor replaces the default AES-256-GCM encryptor.
func WithEncryptor(enc core.Encryptor) ProtectorOption {
	return func(c *protectorConfig) { c.Encryptor = enc }
}

// WithCacheTTL caches keys in memory for ttl (default 20s). The TTL bounds how
// long a subject forgotten through another instance stays readable here. A
// ttl of zero or less keeps the default.
func WithCacheTTL(ttl time.Duration) ProtectorOption {
	return func(c *protectorConfig) {
		c.CacheEnabled = true
		c.CacheTTL = max(ttl, 0)
	}
}

// WithoutCache reads every key from the key engine: a Forget made elsewhere
// applies at once, at the cost of one key engine call per operation.
func WithoutCache() ProtectorOption {
	return func(c *protectorConfig) { c.CacheEnabled = false }
}

// WithImmediateErasure makes every Forget erase at once, with no grace period
// and no Recover. By default Forget is graceful; Immediately() erases at once
// for a single call.
func WithImmediateErasure() ProtectorOption {
	return func(c *protectorConfig) { c.GracefulMode = false }
}

// WithMultipleSubjects lets Encrypt accept a struct whose data belongs to
// several subjects, each field encrypted under its nearest subject. By
// default a struct must use one subject.
func WithMultipleSubjects() ProtectorOption {
	return func(c *protectorConfig) { c.MultipleSubjects = true }
}

// WithForgottenValue sets what Decrypt puts in a field whose subject is
// forgotten, when the field's tag has no replace= option. Default "".
func WithForgottenValue(v string) ProtectorOption {
	return func(c *protectorConfig) { c.ForgottenValue = v }
}

// WithAuditor sends an AuditEvent to a for every erasure and
// re-identification (docs/audit-events.md).
func WithAuditor(a Auditor) ProtectorOption {
	return func(c *protectorConfig) { c.Auditor = a }
}

// FactoryOption configures NewFactory. WithIdleTimeout and WithMonitorPeriod
// build them.
type FactoryOption func(*factoryConfig)

// WithIdleTimeout sets how long a Protector may go unused before Monitor
// evicts it (default 20 minutes).
func WithIdleTimeout(d time.Duration) FactoryOption {
	return func(c *factoryConfig) { c.idleTimeout = d }
}

// WithMonitorPeriod sets how often Monitor clears expired cache entries and
// evicts idle Protectors (default 5s).
func WithMonitorPeriod(d time.Duration) FactoryOption {
	return func(c *factoryConfig) { c.monitorPeriod = d }
}

// ForgetOption configures one Forget call. Immediately builds one.
type ForgetOption func(*forgetConfig)

// Immediately makes one Forget call erase at once instead of gracefully: use
// it where the product promises erasure without a recovery window, such as
// account deletion.
func Immediately() ForgetOption {
	return func(c *forgetConfig) { c.immediate = true }
}

// TokenizeOption configures one Tokenize call. WithPrefix and
// WithTokenGenerator build them.
type TokenizeOption func(*tokenizeConfig)

// WithPrefix prepends prefix to every new token, e.g. "cus_". A prefix
// starting with "@" is refused with ErrReservedSubjectID.
func WithPrefix(prefix string) TokenizeOption {
	return func(c *tokenizeConfig) { c.prefix = prefix }
}

// WithTokenGenerator replaces the random UUID (v4) that forms a new token,
// after its prefix. gen does not receive the value: a token must never be
// derived from it, as hashed emails can be reversed by brute force. A nil gen
// keeps the default.
func WithTokenGenerator(gen func(ctx context.Context, namespace string) (string, error)) TokenizeOption {
	return func(c *tokenizeConfig) {
		if gen != nil {
			c.generate = gen
		}
	}
}
