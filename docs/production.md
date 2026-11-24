# Production guidelines

| | |
|---|---|
| Status | **Recommended practice.** Assumes backends that meet [implementing-backends.md](implementing-backends.md) |

## Deployment

- **Never use the `memory` engines in production.** They keep keys in process
  memory and lose them on restart.
- **Wrap every DEK with a KEK in a KMS or HSM** (R-KW). A key store holding
  plaintext DEKs makes every DBA a reader of all data.
- **Keep storage encryption at rest on as well.** It is complementary, not a
  substitute ([threat-model.md](threat-model.md#3-database-encryption-at-rest-is-not-enough)).
- **Separate duties** between data store, key store and KMS
  ([threat-model.md](threat-model.md#4-separation-of-duties)). Database
  administrators get no unwrap rights.
- **One namespace per tenant.** Consider one KEK per tenant: offboarding then
  shreds the tenant's backups too.
- **Subject IDs must be pseudonymous**: random IDs or tokens, never emails or
  names. They appear in clear in values, key IDs and KMS logs.

## Configuration

| Setting | Recommendation | Why |
|---|---|---|
| Cache TTL (`WithCacheTTL`) | Default 20 s; lower if cross-instance erasure must be faster | Bounds how long other instances keep decrypting a forgotten subject (R-CS-4), and how long plaintext DEKs stay in memory. Lower means more KMS calls |
| Erasure mode | Graceful (default) | Lets you undo a mistaken `Forget`. Use `Immediately()` for confirmed erasure requests that must take effect now |
| Grace period (key and token engines) | Days, not weeks: default 7 days | Erasure is final only at its end. GDPR expects requests answered within a month |
| Auditor (`WithAuditor`) | Always, for regulated data | Proves erasure and re-identification (R-AU). A failing sink blocks reveals |
| Role interfaces | Give each service the narrowest one | A service holding a `Tokenizer` cannot reveal. Back it with separate credentials |
| `WithMultipleSubjects` | Off unless records embed other subjects | Keeps "forget the subject, erase the record" true |

## Erasure

- **Complete it.** Either run a job that calls `KeyEngine.DeleteUnusedKeys`
  and `TokenEngine.EraseForgotten` for each namespace, at least daily, or rely
  on a store that erases by itself. Monitor that it runs.
- **Answer with `FinalAt`.** The audit event of a `Forget` states when erasure
  becomes final; that is the date to give the data subject.
- **Retry on `ErrAuditFailure`.** The erasure was applied; the retry records it.
- **Delete plaintext copies yourself**: logs, caches, search indexes,
  analytics, message queues. Crypto-shredding only reaches ciphertext.
- **Derived keys** (`DeriveSubjectKey`) die with the DEK unless you stored
  them. Do not store them.

## Backups

A backup of the key store holds wrapped DEKs, including those of subjects
forgotten since. While the backup and the KEK both exist, that data can be
recovered.

- **State a retention** for key store backups. Erasure is complete when the
  last backup taken before `FinalAt` expires; say so in your privacy notice.
- **After restoring a key store backup, replay erasures**: `Forget` again
  every subject forgotten since the backup was taken. Your audit trail is the
  list.
- Data store backups need no special handling: they hold only ciphertext.

## Monitoring

| Signal | Likely cause |
|---|---|
| `ErrKeyUnknown` rising | Wrong namespace, wrong key store, or a purge |
| `ErrValueNotAuthentic`, `core.ErrDecryptionFailure` | Tampering, a value copied across namespaces, or a misconfigured wrapper |
| Erasure job not running, or `DISABLED` keys past the grace period | Erasure not completing (reads still enforce the deadline) |
| `ErrAuditFailure` | Audit sink down: reveals are blocked |
| KMS calls far above normal | A cache disabled by mistake, or a compromised process (T4) |

## Upgrades

Pin the module version. Before v1.0, minor releases may break the API; the
release notes say so. Stored data stays readable across releases under the
rules in [wire-format-v2.md](wire-format-v2.md#9-versioning-and-compatibility).

## Checklist

- [ ] Backends pass the conformance suites against real storage.
- [ ] DEKs are wrapped by a KEK in a KMS or HSM; DBAs cannot unwrap.
- [ ] Subject IDs are pseudonymous.
- [ ] An auditor is set, and its sink is monitored.
- [ ] Erasure completes (job or TTL), and is monitored.
- [ ] Key store backup retention is stated, and restores replay erasures.
- [ ] Plaintext copies outside the library have their own deletion path.
