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
| Wire format v2, step 3: `Encryptor` takes `{namespace, keyVersion}` and `[]byte`; header-bound AAD; key version in stream header | PE-23 | Next |
| Wire format v2, step 4: new field format, no regex, v1 removed | PE-23 | |
| Wire format v2, step 5: idempotency by authentication, Decrypt state table, `ForgottenValue` | PE-05, PE-10 | |
| Wire format v2, step 6: format spec, pseudonymous-subject rule, statuses | PE-06 | |
| Remaining hotfixes | PE-04, PE-07, PE-09, PE-15, PE-16 | |
| Then, before the external audit | tests (section 3), API cleanup (section 2), hygiene and security docs (sections 5–6), caches PE-20/21, PE-12, PE-14 | |

Vault findings PE-25 to PE-30 move to elastic as PX-18 to PX-23.

## Phase 2: privacy-engine.elastic

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

Today doconvoy wires `dynamodb.NewKeyEngine` **without** the KMS wrapper (plaintext DEKs in the table) and leaves `GracefulMode` at its default with no janitor, while `posture.md` claims immediate crypto-shredding.

1. **CDK:**
   - One CMK (D2): rotation on, RETAIN in prod.
   - Runtime Lambdas get `kms:GenerateDataKey` and `kms:Decrypt`, conditioned on encryption-context keys.
   - Purge and scheduler roles get no KMS access.
2. **Wiring:** use the safe elastic constructor (KMS required). Keep the cache off at first; parallel KMS decrypts with a bound.
3. **Forget:** graceful by default plus the janitor schedule, or forced immediate where the product promises it (D3). Correct `posture.md` to match.
4. **Fresh deploy:** no migration of plaintext DEKs, since the data is reset.
5. **Integration checks:**
   - Stream consumers treat output as valid only at `io.EOF` (attachments).
   - No ciphertext is copied between structs with different subjects.
   - Update the one test asserting the `ENC.` prefix shape.
