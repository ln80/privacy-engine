package privacy

import (
	"context"
	"errors"
	"slices"
	"time"

	"github.com/ln80/privacy-engine/core"
)

// ErrAuditFailure means the protector's Auditor failed to record an event.
//
// For Forget, Recover, DeleteToken and Purge the operation itself has been
// applied: retry it, as each is idempotent. Detokenize, ListTokens and
// DeriveSubjectKey return nothing when their event is not recorded.
var ErrAuditFailure = newErr("failed to record audit event")

// Auditor records the audit events of a Protector (see docs/audit-events.md).
//
// Audit is called synchronously, once per call of an audited method, after
// the operation and before the method returns, with the caller's ctx: read
// the actor, the reason or a request ID from it. An event never holds
// personal data in clear or key material.
type Auditor interface {
	Audit(ctx context.Context, e AuditEvent) error
}

// AuditorFunc adapts a function to Auditor.
type AuditorFunc func(ctx context.Context, e AuditEvent) error

// Audit implements Auditor.
func (f AuditorFunc) Audit(ctx context.Context, e AuditEvent) error { return f(ctx, e) }

// AuditOp names an audited operation. Values are stable: store and filter on them.
type AuditOp string

// Audited operations.
const (
	OpForget      AuditOp = "subject.forget"
	OpRecover     AuditOp = "subject.recover"
	OpDeriveKey   AuditOp = "subject.derive_key"
	OpDetokenize  AuditOp = "token.detokenize" // #nosec G101 -- an operation name, not a credential
	OpListTokens  AuditOp = "token.list"
	OpDeleteToken AuditOp = "token.delete"
	OpPurge       AuditOp = "namespace.purge"
)

// AuditEvent describes one call of an audited method, successful or not.
// Fields that do not apply to the operation are zero. Fields may be added.
type AuditEvent struct {
	Op        AuditOp
	Namespace string
	// At is when the call started.
	At time.Time

	// Subject is the subject ID or token the call is about; empty for
	// namespace-wide operations and for Detokenize and ListTokens.
	Subject string

	// Err is the error the method returns, nil on success.
	Err error

	// Immediate (Forget): erased at once rather than gracefully.
	Immediate bool
	// FinalAt (Forget): when the erasure is final at the latest. It is At
	// for an immediate Forget, and At plus the grace period of the engines
	// that held something for the subject for a graceful one. Zero when an
	// engine does not report its grace period (core.GracePeriodReporter),
	// or when nothing was forgotten.
	FinalAt time.Time
	// HadKey (Forget): a key, active or disabled, existed for the subject.
	HadKey bool
	// HadToken (Forget): a vault entry existed for the subject.
	HadToken bool

	// Revealed (Detokenize, ListTokens): the tokens whose values the call
	// returned, sorted. Tokens are pseudonymous; their values never appear.
	Revealed []string

	// Purpose (DeriveSubjectKey): the caller's purpose label. Callers must
	// not put personal data in it.
	Purpose string
}

// audit hands ev to the Auditor, if any, with err as the call's outcome. It
// returns the auditor's error wrapped in ErrAuditFailure, or nil.
func (p *Protector) audit(ctx context.Context, ev AuditEvent, err error) error {
	if p.cfg.Auditor == nil {
		return nil
	}
	ev.Namespace = p.namespace
	ev.Err = err
	if aerr := p.cfg.Auditor.Audit(ctx, ev); aerr != nil {
		return ErrAuditFailure.withBase(aerr).withNamespace(p.namespace)
	}
	return nil
}

// auditChange audits an operation that changed state: the change stands, and
// an audit failure is added to the method's error.
func (p *Protector) auditChange(ctx context.Context, ev AuditEvent, err error) error {
	if aerr := p.audit(ctx, ev, err); aerr != nil {
		return errors.Join(err, aerr)
	}
	return err
}

// Forget removes the associated encryption materials of the given subject,
// and crypto-erases its Personal data.
//
// In graceful mode (the default) the key is disabled and the vault entry
// hidden; both are erased once the grace period ends, and Recover works
// until then. Immediately() erases both at once for this call, whatever
// the protector's GracefulMode.
func (p *Protector) Forget(ctx context.Context, subID string, opts ...func(*ForgetConfig)) error {
	cfg := ForgetConfig{}
	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}
	ev := AuditEvent{Op: OpForget, At: time.Now(), Subject: subID}
	err := p.forget(ctx, subID, cfg, &ev)
	if err == nil && p.cfg.Auditor != nil {
		ev.FinalAt = p.finalAt(ev)
	}
	return p.auditChange(ctx, ev, err)
}

// finalAt returns when a Forget described by ev is final at the latest.
func (p *Protector) finalAt(ev AuditEvent) time.Time {
	if !ev.HadKey && !ev.HadToken {
		return time.Time{}
	}
	if ev.Immediate {
		return ev.At
	}
	var grace time.Duration
	for _, held := range []struct {
		ok     bool
		engine any
	}{{ev.HadKey, p.cfg.KeyEngine}, {ev.HadToken, p.cfg.TokenEngine}} {
		if !held.ok {
			continue
		}
		g := core.GracePeriodOf(held.engine)
		if g <= 0 {
			return time.Time{}
		}
		grace = max(grace, g)
	}
	return ev.At.Add(grace)
}

// Recover allows to recover encryption materials of the given subject.
//
// It fails if the grace period was exceeded, and encryption materials were hard deleted.
func (p *Protector) Recover(ctx context.Context, subID string) error {
	ev := AuditEvent{Op: OpRecover, At: time.Now(), Subject: subID}
	return p.auditChange(ctx, ev, p.recoverSubject(ctx, subID))
}

// DeleteToken deletes the given token.
//
// It removes the token and its index entry; it does not erase the subject's
// data: Forget does.
func (p *Protector) DeleteToken(ctx context.Context, token string) error {
	ev := AuditEvent{Op: OpDeleteToken, At: time.Now(), Subject: token}
	return p.auditChange(ctx, ev, p.deleteToken(ctx, token))
}

// Purge hard-deletes every encryption key and token in the protector's
// namespace, then clears caches. Idempotent.
func (p *Protector) Purge(ctx context.Context) error {
	ev := AuditEvent{Op: OpPurge, At: time.Now()}
	return p.auditChange(ctx, ev, p.purge(ctx))
}

// Detokenize returns the value of each active token. Unknown, forgotten
// and erased tokens are omitted.
//
// When the Auditor fails to record the call, nothing is returned.
func (p *Protector) Detokenize(ctx context.Context, tokens []string) (core.TokenValueMap, error) {
	ev := AuditEvent{Op: OpDetokenize, At: time.Now()}
	result, err := p.detokenize(ctx, tokens)
	if p.cfg.Auditor != nil {
		ev.Revealed = sortedKeys(result)
	}
	if aerr := p.audit(ctx, ev, err); aerr != nil {
		return nil, errors.Join(err, aerr)
	}
	return result, err
}

// ListTokens lists a page of tokens with their state. Values are set for
// active tokens only.
//
// Forgotten and erased tokens are listed with their state and no value. When
// the Auditor fails to record the call, nothing is returned.
func (p *Protector) ListTokens(ctx context.Context, query core.ListTokensQuery) (*core.ListTokensResult, error) {
	ev := AuditEvent{Op: OpListTokens, At: time.Now()}
	result, err := p.listTokens(ctx, query)
	if p.cfg.Auditor != nil && result != nil {
		for _, r := range result.Tokens {
			if r.State == core.TokenActive {
				ev.Revealed = append(ev.Revealed, r.Token)
			}
		}
		slices.Sort(ev.Revealed)
	}
	if aerr := p.audit(ctx, ev, err); aerr != nil {
		return nil, errors.Join(err, aerr)
	}
	return result, err
}

// DeriveSubjectKey derives a purpose-scoped key from the subject's DEK without exposing it.
// purpose is mixed into the derivation (e.g. a client ref hash for attachments).
//
// When the Auditor fails to record the call, the derived key is wiped and not
// returned.
func (p *Protector) DeriveSubjectKey(ctx context.Context, subID, purpose string) (core.Key, error) {
	ev := AuditEvent{Op: OpDeriveKey, At: time.Now(), Subject: subID, Purpose: purpose}
	key, err := p.deriveSubjectKey(ctx, subID, purpose)
	if aerr := p.audit(ctx, ev, err); aerr != nil {
		core.ZeroKey(key)
		return nil, errors.Join(err, aerr)
	}
	return key, err
}

func sortedKeys(m core.TokenValueMap) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}
