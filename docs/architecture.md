# Architecture and requirements

| | |
|---|---|
| Status | **Normative.** Requirement IDs are stable; specs, tests and issues cite them |

## 1. Scope

The library protects personal data in a Go application before it reaches
storage: per-subject field encryption, crypto-shredding, tokenization,
streams, derived keys and audit events. It ships the logic, the storage
contracts (`core`), test engines (`memory`) and conformance suites
(`privacytest`). **Production backends are yours to build.**

| Not covered | Where it belongs |
|---|---|
| Key storage, KMS, HSM | Your backends ([implementing-backends.md](implementing-backends.md)) |
| Who may call the library | Your access control. Role interfaces are not a boundary |
| Plaintext copies: logs, caches, search, analytics | Your data flows. Shredding reaches ciphertext only |
| Key store backups | Your retention ([production.md](production.md#backups)) |
| Anonymisation | Tokens are pseudonyms: still personal data |
| A compromised process | [threat-model.md](threat-model.md#5-out-of-scope) |
| Key rotation | Not built ([key-lifecycle.md](key-lifecycle.md#5-rotation-not-supported)) |

## 2. Requirements

Guaranteed when the backends meet theirs ([implementing-backends.md](implementing-backends.md)).

### Crypto-shredding

| ID | Requirement |
|---|---|
| R-CS-1 | Every value, stream and derived key depends on one DEK: one subject in one namespace |
| R-CS-2 | Once a DEK is deleted and out of every cache, nobody can decrypt its data, the operator included |
| R-CS-3 | `Forget` is graceful by default: decryption stops at once, `Recover` works until the grace period ends, then the key is deleted. Immediate mode deletes at once |
| R-CS-4 | Other instances stop decrypting a forgotten subject within their cache TTL |
| R-CS-5 | Forgotten fields decrypt to a placeholder; new data for the subject is refused; no key is ever recreated for it |
| R-CS-6 | An unknown subject (never created, purged, wrong namespace) fails with `ErrKeyUnknown`; it is never taken for a forgotten one |
| R-CS-7 | A value moved to another namespace fails authentication. `Purge` removes every key of a namespace |
| R-CS-8 | Any change to a value or stream fails authentication; a value that fails is never accepted or overwritten |
| R-CS-9 | Keys, plaintext and token values never appear in errors, logs or `fmt` output |

### Tokenization

| ID | Requirement |
|---|---|
| R-TK-1 | Tokens are random, never derived from the value |
| R-TK-2 | One live token per value per namespace, also under concurrent `Tokenize` |
| R-TK-3 | The token store never sees a value: values are sealed and found by a keyed blind index |
| R-TK-4 | A sealed value opens only for its token in its namespace |
| R-TK-5 | `Forget(token)` hides the value at once and erases it after the grace period, with any data encrypted under the token |
| R-TK-6 | `Detokenize` and `ListTokens` reveal active tokens' values only |

### Audit

| ID | Requirement |
|---|---|
| R-AU-1 | Every erase, recover or reveal call emits one `AuditEvent`, success or failure, without values or keys |
| R-AU-2 | If the auditor fails, reveals return nothing; erasures apply and return `ErrAuditFailure` |

Details: [wire-format.md](wire-format.md), [token-vault.md](token-vault.md),
[audit-events.md](audit-events.md).

## 3. Components

```
┌─ application process ───────────────────────────┐
│ *privacy.Protector, one per namespace           │
│ Encryptor: AES-256-GCM    key cache: DEKs, TTL  ├──► Auditor ──► audit sink
└────────┬─────────────────────────────┬──────────┘
         │ core.KeyEngine              │ core.TokenEngine
┌────────▼─────────┐    ┌──────────┐   │
│ key wrapper      │◄──►│ KMS/HSM  │   │
│ (envelope)       │    │ holds KEK│   │
└────────┬─────────┘    └──────────┘   │
┌────────▼─────────┐          ┌────────▼─────────┐
│ key store        │          │ token store      │
│ wrapped DEKs,    │          │ sealed values,   │
│ key states       │          │ blind index      │
└──────────────────┘          └──────────────────┘

data store (yours): ciphertext and pseudonymous subject IDs only
```

Reading a subject's data takes the ciphertext, its wrapped DEK and the right
to unwrap it. Give the three to different principals
([threat-model.md](threat-model.md#4-separation-of-duties)).

| Package | Holds |
|---|---|
| `privacy` | `Protector`, options, role interfaces, audit, token vault |
| `core` | Contracts (`KeyEngine`, `TokenEngine`, `Encryptor`) and types |
| `aes` | Default `Encryptor`: AES-256-GCM fields, STREAM streams |
| `memory` | In-memory engines and key cache, for tests |
| `privacytest` | Conformance suites and test doubles |
