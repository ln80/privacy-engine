# Audit events

| | |
|---|---|
| Status | **Implemented** (`audit.go`) |
| Scope | `privacy` (events, `Auditor`, emission points), `core` (optional `GracePeriodReporter`), backends (implement it) |
| Compatibility | Additive: no existing signature changes |

## 1. Why the library emits events

Crypto-shredding and tokenization are privacy-by-design measures. GDPR asks
the controller to be able to show they work (Art. 5(2), accountability), and
some operations exist only to be shown:

- an **erasure** (Art. 17) must be provable: who asked, for which subject,
  when, and when it became final;
- a **re-identification** (detokenizing a pseudonym, Art. 4(5)) must be
  traceable: pseudonymisation is only a safeguard if access to the additional
  information is controlled and recorded (EDPB Guidelines 01/2025);
- a **key leaving the engine** (`DeriveSubjectKey`) escapes crypto-shredding
  and should leave a trace.

The library is the only place that sees every one of these operations, so it
emits an event for each. It does **not** store them: where audit records go
(an event store, a log pipeline, a SIEM) and who the actor is belong to the
application.

## 2. Principles

1. **No values, no keys.** An event never carries personal data in clear or
   key material. Subject IDs and tokens are pseudonymous by rule (README,
   "Subject IDs must be pseudonymous") and may appear.
2. **Attempts, not only successes.** A failed Forget is an audit fact.
3. **The application owns identity.** The library does not know the actor or
   the reason; the `Auditor` reads them from `ctx`, which every event is
   delivered with.
4. **Fail closed on disclosure, report on mutation.** If the event of an
   operation that reveals data cannot be recorded, the data is not returned.
   An operation that changes state cannot be undone, so its event failure is
   returned to the caller, who retries (every such operation is idempotent).
5. **Opt-in and cheap.** No `Auditor`, no cost. Encrypt and Decrypt emit
   nothing: they are the data path, and their volume belongs to application
   logs, not to an audit trail.

## 3. API

```go
package privacy

// Auditor records audit events. Audit is called synchronously, after the
// operation and before its method returns, with the caller's ctx.
type Auditor interface {
    Audit(ctx context.Context, e AuditEvent) error
}

// AuditorFunc adapts a function to Auditor.
type AuditorFunc func(ctx context.Context, e AuditEvent) error

type AuditOp string

const (
    OpForget        AuditOp = "subject.forget"
    OpRecover       AuditOp = "subject.recover"
    OpDeriveKey     AuditOp = "subject.derive_key"
    OpDetokenize    AuditOp = "token.detokenize"
    OpListTokens    AuditOp = "token.list"
    OpDeleteToken   AuditOp = "token.delete"
    OpPurge         AuditOp = "namespace.purge"
)

type AuditEvent struct {
    Op        AuditOp
    Namespace string
    At        time.Time

    // Subject is the subject ID or token the operation is about; empty for
    // namespace-wide operations.
    Subject string

    // Err is the operation's error, nil on success.
    Err error

    // Forget only.
    Immediate bool      // erased at once rather than gracefully
    FinalAt   time.Time // when erasure is final at the latest; zero if unknown
    HadKey    bool      // a key existed for the subject
    HadToken  bool      // a vault entry existed for the subject

    // Detokenize and ListTokens: the tokens whose values were returned,
    // sorted. Requested tokens that were not returned are not listed.
    Revealed []string

    // DeriveSubjectKey: the caller's purpose label. It must not hold
    // personal data.
    Purpose string
}

// ProtectorConfig gains:
//     Auditor Auditor // nil: no events
```

Named constants keep `Op` stable for storage and filtering. `AuditEvent` is a
struct, not an interface per operation: one type to persist, fields unused by
an operation are zero. New fields may be added; a new `Op` may be added.

## 4. When each event is emitted

| Method | Event | If `Audit` fails |
|---|---|---|
| `Forget` | `subject.forget`, success or failure | The method returns `ErrAuditFailure` joined with the operation's own error, if any. The subject **is** forgotten; retrying is safe |
| `Recover` | `subject.recover` | As Forget |
| `DeleteToken` | `token.delete` | As Forget |
| `Purge` | `namespace.purge` | As Forget |
| `Detokenize` | `token.detokenize`, with `Revealed` | **Nothing is returned**: the method fails with `ErrAuditFailure` |
| `ListTokens` | `token.list`, with the active tokens of the page in `Revealed` | As Detokenize |
| `DeriveSubjectKey` | `subject.derive_key` | As Detokenize: the key is wiped and not returned |
| `Tokenize`, `Encrypt`, `Decrypt`, streams, `Clear` | none | – |

- `Tokenize` reveals nothing (the caller already holds the values) and
  creates only pseudonyms, so it is not an audit event. Applications that want
  "token created" can record it from `Tokenize`'s result.
- A `Detokenize` call that reveals nothing (all tokens unknown or forgotten)
  still emits an event with an empty `Revealed`: the attempt is the fact.
- Events are emitted once per call, not per token.

## 5. Erasure deadline: `FinalAt`

A graceful Forget is not erasure yet; it becomes final when the grace period
ends. An auditor needs that date, and only the key and token engines know
their grace period. An optional interface exposes it:

```go
package core

// GracePeriodReporter is implemented by key and token engines that erase
// what was forgotten after a fixed grace period. Wrappers forward it.
type GracePeriodReporter interface {
    GracePeriod() time.Duration
}
```

The protector looks for it on the key engine (through `Origin()` of each
wrapper) and on the token engine, and sets:

- nothing was forgotten (no key, no vault entry): `FinalAt` is zero;
- immediate Forget: `FinalAt = At`;
- graceful Forget: `FinalAt = At + ` the longest grace period of the engines
  that held something for the subject (the key engine if it had a key, the
  token engine if it had a vault entry);
- one of those engines reports no grace period: `FinalAt` is zero (unknown).

`FinalAt` is "at the latest": a subject already forgotten keeps its first
time, so its real deadline may be earlier. Engines that erase by reading the
deadline (as the conformance suites require) make the date exact for every
reader, whether or not a janitor or a storage TTL has run.

The in-memory key engine and the cache wrapper implement it. The in-memory
token engine does not: it erases only when `EraseForgotten` runs, so a
graceful Forget of a token on it has an unknown `FinalAt`.

## 6. What this does not cover

| Item | Why |
|---|---|
| Physical deletion by a janitor or a storage TTL | Happens outside the protector. `FinalAt` is the provable date: from then on no reader gets the data |
| Decrypt and Encrypt access | Volume. An application that must trace every decrypt can wrap `Protector` |
| Tamper-evidence of the audit trail | The sink's job (append-only store, object lock, hash chain) |
| Actor, reason, request ID | The application's, through `ctx` |

## 7. Example

```go
auditor := privacy.AuditorFunc(func(ctx context.Context, e privacy.AuditEvent) error {
    slog.InfoContext(ctx, "privacy audit",
        "op", e.Op, "ns", e.Namespace, "subject", e.Subject,
        "final_at", e.FinalAt, "revealed", len(e.Revealed), "err", e.Err,
        "actor", actorFrom(ctx))
    return nil
})

p := privacy.NewProtector("tenant", engine, func(pc *privacy.ProtectorConfig) {
    pc.Auditor = auditor
})
```

## 8. Decisions

| ID | Question | Decision |
|---|---|---|
| A1 | Fail closed on disclosure (Detokenize, ListTokens, DeriveSubjectKey) when the sink fails? | Yes. A best-effort sink can return nil |
| A2 | List revealed tokens, or only a count? | Tokens: they are pseudonymous and let an auditor answer "who saw subject X" (Art. 15(1)(c), recipients) |
| A3 | Emit on Decrypt? | No (section 6) |
| A4 | `FinalAt` through an optional `GracePeriodReporter` | Yes, rather than changing `DisableKey` to return a deadline (breaking) |
| A5 | Event type: one struct with optional fields, or one type per operation | One struct |
