# Hardening plan: privacy-engine → privacy-engine.elastic → doconvoy

The single place to see where the audit work stands, across the three repos. Details live in the documents linked from each section; this file holds the order, the decisions and the status.

| Document | What it holds |
|---|---|
| [`audit-readiness.md`](audit-readiness.md) | privacy-engine findings PE-01 to PE-30, with status per ID |
| [`wire-format-v2.md`](wire-format-v2.md) | Agreed field wire format v2 and its six implementation steps |
| `privacy-engine.elastic/docs/audit-readiness.md` | Backend findings PX-01 to PX-23 (DynamoDB, KMS, stack, vault) |
| `doconvoy/docs/privacy/posture.md` | doconvoy's privacy claims, to be corrected in phase 3 |

## Ground rules

- **No backward compatibility.** Fresh deploy: old wire and stream formats are dropped, not migrated, and existing data is not kept.
- **Iterative.** One finding or step at a time, discussed before the next.
- **One branch per repo, one commit per fix.** privacy-engine: `fix/audit-hardening`. Each commit says what was wrong, why, and what changed. No co-author lines.
- **Always green:** `GOWORK=off go test -race ./...`, with a regression test per finding ID.

## Decisions

| ID | Decision |
|---|---|
| D1 | Encryption context for wrapped DEKs is a pluggable function (elastic) |
| D2 | One CMK at this stage; the resolver keeps per-tenant CMKs possible later |
| D3 | `Forget` is graceful by default (disable, then delete after the grace period); immediate deletion when forced |
| D-C | A value that looks encrypted but does not authenticate under an active key fails `Encrypt` |
| D-D | Wire prefix `ENC.`; only the v2 format is parsed |
| – | Subject ID stays in field values; subject IDs must be pseudonymous (PE-06 as a rule) |
| – | No field subkey; field AAD binds namespace + header only; PE-11 accepted as a documented risk |
| – | After `PurgeNamespace`, keys report `Unknown`, so decrypting a purged tenant's data is an error, not a placeholder |
| E1–E5 | elastic: Forget of an unknown subject is `ErrKeyNotFound`; default KMS context `{v, ns, sid}`, pluggable; tombstones kept; v0.7.0 numbering; `dynamodb` and `kms` stay independent (see elastic `docs/hardening-plan.md`) |
| V1–V12 | Token vault v2, revision 2 (elastic `docs/token-vault-v2.md`): one table, one `@vault` key with derived keys, KMS optional, a new token after Forget, forgotten tokens listed by state, `@` reserved |
| E6 | Erasure after the grace period by DynamoDB TTL instead of a janitor: the secret of a forgotten subject moves to its own item with `_ttl`, reads enforce the deadline, the janitor is optional (elastic v0.9.0) |
| D3-a | `Forget(id, Immediately())` forces immediate erasure for one call (v0.9.0); doconvoy uses it for account purge only |

## Phase 1: privacy-engine (`fix/audit-hardening`)

| Step | Finding | Status |
|---|---|---|
| Cache eviction zeroed keys in use | PE-01 | Done |
| Reject non-256-bit and all-zero keys | PE-08 | Done |
| Encrypt fetches a key for every subject a record uses | – | Done |
| Stream format v2 (STREAM construction), no goroutines | PE-02, PE-19 | Done |
| Short ciphertext no longer panics | PE-03 | Done |
| Require struct-sensitive v0.8.0; builds without `go.work` | PE-22 | Done |
| Wire format v2, step 2: `GetKeys` reports missing-key states | PE-10 (contract) | Done |
| Wire format v2, step 3: `Encryptor` takes `{namespace, keyVersion}` and `[]byte`; header-bound AAD; key version in stream header | PE-23 | Done |
| Wire format v2, step 4: new field format, no regex, v1 removed | PE-23 | Done |
| Wire format v2, step 5: idempotency by authentication, Decrypt state table, `ForgottenValue` | PE-05, PE-10 | Done |
| Wire format v2, step 6: format spec, pseudonymous-subject rule, statuses | PE-06 | Done |
| Forget/Recover no longer fail after cache eviction | PE-04 | Done |
| Factory clear func no longer panics after eviction | PE-07 | Done |
| Keys and token data redact in fmt, slog and JSON | PE-09 | Done |
| In-memory token store survives `Clear` | PE-15 | Done |
| In-memory store honours `WithPrefix` | PE-16 | Done |
| Token vault v2, core (branch `feat/token-vault-v2`): crypto, reserved `@` IDs, opaque storage contract and in-memory store, protector flows, `Forget`/`Recover` lifecycle, conformance suite. Release v0.8.0 | PE-25, 27, 28, 29, 30 | Done on branch |
| `TestFactory` polls instead of sleeping (it failed once under full parallel load) | – | Done |
| `Forget(id, Immediately())`: immediate erasure per call, whatever `GracefulMode` | D3 | Done |
| Conformance: unknown subjects (E1), raw-storage probes for key material and sealed values, erasure without a janitor (`ErasesWithoutJanitor`, token `GracePeriod`). Release v0.9.0 | E1, D3 | Done |
| Then, before the external audit | tests (section 3), API cleanup (section 2), hygiene and security docs (sections 5–6), caches PE-20/21, PE-12, PE-14 | |

Vault findings PE-25 to PE-30 move to elastic as PX-18 to PX-23.

## Phase 2: privacy-engine.elastic

**Done, released as elastic v0.9.0** (no v0.8.0), on privacy-engine v0.9.0. Status per step is in elastic `docs/hardening-plan.md`; only step 12 (SAM reference stack) remains.

Requires a privacy-engine release with phase 1 (new `GetKeys` signature, Purge API).

1. **Build:** require the new privacy-engine, re-enable CI (PX-16).
2. **Before anything uses KMS:**
   - PX-02: the KMS wrapper returns the key that was actually stored. Without this, concurrent first use loses data silently once KMS is on.
   - PX-05: no items for unknown subjects; never a zero-length key.
   - PX-12: always 32-byte DEKs from KMS.
3. **Erasure:**
   - PX-01: `DeleteKey` removes the key material.
   - PX-11: re-disabling no longer postpones deletion.
   - PX-06: the janitor that runs `DeleteUnusedKeys`, for D3.
4. **Envelope:**
   - PX-03: encryption context from a pluggable function (D1), versioned, binding the subject.
   - PX-04: a single safe constructor, with KMS required.
5. **Contract:** implement `GetKeys` states in the DynamoDB engine; conformance suite run against KMS over DynamoDB, plus the cache wrapper.
6. **Scale:** PX-09 (batches over 100), PX-10 (read amplification).
7. **Stack:**
   - PX-07: split IAM roles, CMK and key policy with encryption-context conditions.
   - PX-08, PX-14.
8. **Vault redesign:** PX-18 to PX-23.

## Phase 3: doconvoy (KMS envelope integration)

**Done** on doconvoy branch `feat/e2eev2` (2026-11-13), against privacy-engine and elastic v0.9.0. Before it, doconvoy wired `dynamodb.NewKeyEngine` without the KMS wrapper (plaintext DEKs in the table), left `GracefulMode` at its default with nothing completing erasure, and `posture.md` claimed immediate crypto-shredding.

| Step | Outcome | doconvoy commits |
|---|---|---|
| Compile against v0.8.0+ | Only break: `GetKeys` in the identity purge test. Decrypting a purged tenant is now `ErrKeyUnknown` (test updated) | `1f3f898c`, `114ecada` |
| Wiring | KMS over DynamoDB, token engine on the same table, required (no path back to clear keys). **Changed:** protector cache **on**, TTL 30 s, since PE-04 made it safe for Forget. `ForgottenValue` left `""` | `8cbafdc3` |
| CDK: CMK and grants | One CMK per environment, rotation on, RETAIN in prod. `kms:GenerateDataKey` and `kms:Decrypt` conditioned on context keys exactly `v`, `ns`, `sid` and `v = "1"`. **Changed:** the scheduler gets KMS too (reminders decrypt, `PurgeUser` forgets); cron and export-lifecycle get none | `fae1d6e8` |
| Forget and erasure | Graceful by default, one grace period (7 days) on both engines. **Changed:** a janitor was built, then replaced by TTL (E6), as the privacy table already has TTL on `_ttl`. Immediate only for account purge (`Immediately()`) | `c7e6da0b`, `6ce54727`, `5e83550d`, `241d233c`, `0df0647b` |
| Fresh deploy | No migration: the privacy table is reset | – |
| Integration checks | Streams valid only at `io.EOF`: downloads now abort instead of truncating. "Anonymous" fallbacks correct for omitted tokens, now tested for graceful Forget. Subject list shows `State`. The `ENC.` prefix test already matched v2. Subject IDs never start with `@`. e2eev2 items (`e2eev2.*` partitions) cannot collide with engine items | `c9b25551`, `9276a9b2`, `50ddb485` |
| Found during review | Session cookies were signed only and carried derived attachment keys: now encrypted. Those keys had no time limit: now 15 minutes. The worker retried events of purged tenants forever: now dropped and logged | `6b948ea3`, `55301d1c`, `808ba385` |
| `posture.md` | Erasure timeline, KMS, vault, cookies, attachment keys; remaining gaps listed | `b8bc655c` |

**Open:**
- Least-privilege privacy-table actions per role (deferred; roles still get read/write on the table).
- A CMK key policy restricted to the runtime roles (default IAM-delegated policy today).
- Pin released library versions in doconvoy and bundle Lambdas with `GOWORK=off`, after event-store is released with struct-sensitive v0.8.0 support.
- S3 objects of deleted secrets are kept until tenant purge (unreadable once the secret's key is erased).
