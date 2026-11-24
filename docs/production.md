# Production guidelines

## Deployment

- **No `memory` engines**: they lose keys on restart.
- **Wrap DEKs with a KEK in a KMS or HSM** (R-KW). Plaintext DEKs in a store
  make every DBA a reader.
- **Keep encryption at rest on too**; it does not replace this
  ([threat-model.md](threat-model.md#3-encryption-at-rest-is-not-enough)).
- **Separate duties**; DBAs get no unwrap rights
  ([threat-model.md](threat-model.md#4-separation-of-duties)).
- **One namespace per tenant**, ideally one KEK per tenant.
- **Pseudonymous subject IDs**: they appear in clear in values, key IDs and
  KMS logs.

## Configuration

| Setting | Recommended | Trade-off |
|---|---|---|
| `WithCacheTTL` | 20 s (default) | Lower: faster cross-instance erasure, more KMS calls |
| Erasure mode | Graceful (default) | Undoable mistakes; use `Immediately()` for confirmed requests |
| Grace period | 7 days (default) | Erasure is final only at its end; GDPR allows a month |
| `WithAuditor` | Always, for regulated data | A failing sink blocks reveals |
| Role interfaces | Narrowest per service | Back each with its own credentials |

## Erasure

- **Complete it**: a daily job calls `DeleteUnusedKeys` and `EraseForgotten`
  per namespace, or the store erases by TTL. Monitor it.
- **Answer with `FinalAt`** from the audit event.
- **Retry on `ErrAuditFailure`**: the erasure applied; the retry records it.
- **Delete plaintext copies yourself**: logs, caches, search, analytics.
- **Don't store derived keys**: they would outlive the DEK.

## Backups

Key store backups hold wrapped DEKs of subjects forgotten since.

- **State a retention.** Erasure is complete when the last backup older than
  `FinalAt` expires.
- **After a restore, replay erasures** recorded in your audit trail since the
  backup.
- Data store backups hold ciphertext only: nothing to do.

## Monitoring

| Signal | Likely cause |
|---|---|
| `ErrKeyUnknown` | Wrong namespace or store, or a purge |
| `ErrValueNotAuthentic`, `core.ErrDecryptionFailure` | Tampering or a misconfigured wrapper |
| `DISABLED` keys past grace | Erasure job not running |
| `ErrAuditFailure` | Audit sink down |
| KMS call spike | Cache off by mistake, or a compromised process |

## Upgrades

Pin the version. Before v1.0, minor releases may break the API; stored data
follows [wire-format.md §8](wire-format.md#8-versioning-and-compatibility).
