# Audit events

| | |
|---|---|
| Status | **Normative.** Requirements R-AU in [architecture.md](architecture.md#audit) |
| Code | `audit.go`, `core.GracePeriodReporter` |

GDPR asks you to show that erasure works (Art. 5(2), 17) and that
re-identification is controlled (Art. 4(5)). The library sees every such
operation, so it emits an event for each. Storing events, and knowing the
actor, are the application's job.

## 1. Principles

1. **No values, no keys.** Pseudonymous subject IDs and tokens may appear.
2. **Attempts count**: failures are emitted too.
3. **The application owns identity**: the `Auditor` reads actor and reason
   from `ctx`.
4. **Fail closed on disclosure, report on mutation** (R-AU-2). Mutations are
   idempotent, so retry them.
5. **Opt-in.** Encrypt and Decrypt emit nothing: they are the data path.

## 2. Events

`WithAuditor(a)` makes the protector call `a.Audit(ctx, event)`
synchronously, once per call. `AuditEvent` is one struct; fields an operation
does not use are zero.

| Method | `Op` | Extra fields | If `Audit` fails |
|---|---|---|---|
| `Forget` | `subject.forget` | `Immediate`, `FinalAt`, `HadKey`, `HadToken` | Applied; returns `ErrAuditFailure` |
| `Recover` | `subject.recover` | – | Applied; `ErrAuditFailure` |
| `DeleteToken` | `token.delete` | – | Applied; `ErrAuditFailure` |
| `Purge` | `namespace.purge` | – | Applied; `ErrAuditFailure` |
| `Detokenize` | `token.detokenize` | `Revealed` | **Returns nothing** |
| `ListTokens` | `token.list` | `Revealed` (active tokens of the page) | **Returns nothing** |
| `DeriveSubjectKey` | `subject.derive_key` | `Purpose` | **Key wiped, not returned** |

Every event has `Op`, `Namespace`, `At`, `Subject` (empty for `Purge`) and
`Err`. `Revealed` lists returned tokens only, and is empty when nothing was
revealed. `Tokenize` emits nothing: it reveals nothing.

## 3. `FinalAt`

When erasure becomes final, at the latest:

| Case | `FinalAt` |
|---|---|
| Nothing was forgotten | zero |
| Immediate | `At` |
| Graceful | `At` + the longest grace period of the engines that held something |
| An engine reports no grace period | zero (unknown) |

Engines report theirs through `core.GracePeriodReporter`, found through
wrappers' `Origin()`. The in-memory token engine reports none.

## 4. Not covered

| Item | Where |
|---|---|
| Physical deletion by a job or TTL | Outside the protector; `FinalAt` is the provable date |
| Decrypt access | Volume; wrap the `Protector` if you must trace it |
| Tamper-evidence of the trail | The sink (append-only store, object lock) |

## 5. Example

```go
p := privacy.NewProtector("tenant", engine, privacy.WithAuditor(
    privacy.AuditorFunc(func(ctx context.Context, e privacy.AuditEvent) error {
        slog.InfoContext(ctx, "privacy audit", "op", e.Op, "subject", e.Subject,
            "final_at", e.FinalAt, "revealed", len(e.Revealed), "err", e.Err,
            "actor", actorFrom(ctx))
        return nil
    }),
))
```
