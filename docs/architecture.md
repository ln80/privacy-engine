# Architecture, scope and requirements

| | |
|---|---|
| Status | **Normative.** Requirement IDs are stable: specs, conformance tests and issues cite them |
| Read next | [threat-model.md](threat-model.md), [key-lifecycle.md](key-lifecycle.md), [implementing-backends.md](implementing-backends.md) |

## 1. Scope

privacy-engine protects personal data inside a Go application, before it
reaches storage:

- **Field encryption** of tagged struct fields, under one data encryption key
  (DEK) per data subject and namespace.
- **Crypto-shredding**: deleting a subject's DEK makes all of its data
  unreadable, wherever the ciphertext was copied (event logs, backups,
  exports).
- **Tokenization**: a random pseudonym per value, with the values kept in a
  sealed vault.
- **Streams** and **derived keys** for payloads that do not fit in a field.
- **Audit events** for every erasure and re-identification.

The module ships the core logic, the storage contracts (`core`), in-memory
engines for tests (`memory`) and conformance suites (`privacytest`).
**Production key, token and audit backends are yours to build**: the
contracts and suites are how you check them.

### Non-goals

| Not covered | Where it belongs |
|---|---|
| Key storage, KMS or HSM integration | Your `KeyEngine` and key wrapper ([implementing-backends.md](implementing-backends.md)) |
| Who may call the library | Your authentication and authorization. Role interfaces document intent; they are not a boundary |
| Plaintext outside the library: logs, caches, search indexes, analytics, queues | Your data flows. Crypto-shredding only reaches ciphertext |
| Erasure from backups of the key store | Your backup retention ([production.md](production.md)) |
| Anonymisation | Tokens are pseudonyms: tokenized data is still personal data |
| A compromised application process | It holds DEKs while it runs. Limit what it can reach ([threat-model.md](threat-model.md)) |
| Key rotation | Not built yet ([key-lifecycle.md](key-lifecycle.md#5-rotation-not-supported)) |

## 2. Requirements

What the library guarantees, provided its backends meet their own
requirements (`R-KE`, `R-KW`, `R-TE`, `R-EN` in
[implementing-backends.md](implementing-backends.md)).

### Crypto-shredding

| ID | Requirement |
|---|---|
| R-CS-1 | Every field value, stream and derived key depends on exactly one DEK: one subject in one namespace |
| R-CS-2 | Once a DEK is deleted from the key engine and has left every cache, nobody can decrypt data encrypted under it, the operator included |
| R-CS-3 | `Forget` is graceful by default: the key is disabled and stops decrypting at once, `Recover` restores it within the grace period, and it is deleted when the period ends. Immediate mode deletes it at once |
| R-CS-4 | Another instance stops decrypting a forgotten subject within its key cache TTL |
| R-CS-5 | A forgotten subject's fields decrypt to a placeholder. New data for it is refused (`ErrSubjectForgotten`), and no new key is ever created for a disabled or deleted subject |
| R-CS-6 | A subject the key engine has no record of (never created, purged, wrong namespace) fails with `ErrKeyUnknown` and leaves fields untouched: it is never mistaken for a forgotten one |
| R-CS-7 | A value moved to another namespace fails authentication, even if a backend returns a key for it. `Purge` removes every key of a namespace |
| R-CS-8 | Any change to a value or a stream fails authentication. A value that does not authenticate under an active key is never accepted, re-encrypted or overwritten (fail closed) |
| R-CS-9 | Keys, plaintext and token values never appear in errors, logs or `fmt` output: `core.Key` and `core.TokenData` redact themselves, and errors name field paths, never values |

### Tokenization

| ID | Requirement |
|---|---|
| R-TK-1 | Tokens are random. A token is never derived from its value |
| R-TK-2 | A namespace has one live token per value. Concurrent `Tokenize` calls for the same value return the same token |
| R-TK-3 | The token store never receives a value in clear: values are sealed, and found through a keyed blind index (HMAC) |
| R-TK-4 | A sealed value only opens for its own token in its own namespace |
| R-TK-5 | `Forget(token)` hides the value at once and erases it when the grace period ends, together with any data encrypted under the token as a subject |
| R-TK-6 | `Detokenize` and `ListTokens` reveal values of active tokens only |

### Audit

| ID | Requirement |
|---|---|
| R-AU-1 | Every call that erases, recovers or reveals emits one `AuditEvent`, success or failure. Events never carry values or keys |
| R-AU-2 | If the auditor fails, calls that reveal return nothing; calls that erase are applied and return `ErrAuditFailure`, so they can be retried |

Details: [wire-format-v2.md](wire-format-v2.md) (R-CS-1, 5 to 8),
[token-vault.md](token-vault.md) (R-TK), [audit-events.md](audit-events.md)
(R-AU).

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

Reading one subject's data takes three separate things: the ciphertext (data
store), its wrapped DEK (key store) and the right to unwrap it (KMS). Give
them to different principals ([threat-model.md](threat-model.md#4-separation-of-duties)).

| Package | Holds |
|---|---|
| `privacy` | `Protector`, options, role interfaces, audit, the token vault logic |
| `core` | Contracts: `KeyEngine`, `TokenEngine`, `Encryptor`; key and token types |
| `aes` | The default `Encryptor`: AES-256-GCM fields, STREAM streams |
| `memory` | In-memory engines and the key cache. Tests and examples only |
| `privacytest` | Conformance suites every backend must pass, and test doubles |

### Data flow

- **Encrypt**: read the subject from the struct, `GetOrCreateKeys`, seal each
  field with the namespace and key version as AAD, write `ENC.<subject>.<payload>`.
- **Decrypt**: read the subject from each value, `GetKeys`, open; a forgotten
  subject gives the placeholder, an unknown one an error.
- **Tokenize**: compute the blind index under the namespace's `@vault` key,
  look it up, else insert a new random token with the value sealed.
- **Forget**: disable (or delete) the subject's key and forget its vault
  entry, then emit an audit event.
