# Token vault

| | |
|---|---|
| Status | **Normative.** Sealed format `0x01` since v0.8.0 |
| Code | `vault.go`, `vault_crypto.go`, `core/token_engine.go`, `memory/token_engine.go` |
| Requirements | R-TK in [architecture.md](architecture.md#tokenization); store contract R-TE in [implementing-backends.md](implementing-backends.md#4-token-store-coretokenengine) |

The vault maps a value (an email) to a random token (`sub_3f2c…`). It is the
*additional information* of GDPR Art. 4(5): kept apart and protected, since
pseudonymised data is still personal data. A token is usually also a subject
ID, so `Forget(token)` shreds both the vault entry and the data encrypted
under it.

## 1. Principles

1. The store never sees a value in clear: the `Protector` seals it and
   computes its lookup key.
2. Lookups by key only: a value by its blind index, a token by its ID.
3. One live token per value, enforced by the store's conditional insert.
4. Tokens are random: a `WithTokenGenerator` function never receives the value.
5. Erasure follows the key lifecycle.

## 2. Cryptography

```
vaultKey = the namespace's DEK under the reserved ID "@vault"
indexKey = HKDF-SHA256(vaultKey, info = "privacy-engine/vault/index/v1")
sealKey  = HKDF-SHA256(vaultKey, info = "privacy-engine/vault/value/v1")

index    = HMAC-SHA256(indexKey, value)                                      32 bytes
sealed   = 0x01 | nonce (12) | AES-256-GCM(sealKey, nonce, value, aad)
aad      = "privacy-engine/vault/v1" | 0x01 | len16(namespace) | namespace | len16(token) | token
```

- **Keyed index**: a plain hash of a guessable value (an email) could be
  matched by anyone holding the store.
- **Exact bytes are indexed**: normalise values (case, spaces) before
  `Tokenize`.
- **Token in the AAD**: a sealed value moved onto another token fails to open.
- **Namespace in key and AAD**: nothing links or moves across namespaces.
- The index reveals equal values within a namespace, as `Tokenize` promises.
- `@vault` is read once per call, or not at all when cached.

Sealing is only as strong as the key engine holding `@vault`. With wrapped
keys, a reader of the store without unwrap rights sees tokens and ciphertext
only: that is the pseudonymisation boundary. With unwrapped keys next to the
vault, sealing is **not** a boundary.

## 3. States

| State | Index entry | Sealed value | `Detokenize` | `ListTokens` |
|---|---|---|---|---|
| `ACTIVE` | yes | yes | value | value |
| `FORGOTTEN` | removed | kept for `Recover` | omitted | state only |
| `ERASED` | removed | deleted | omitted | state only |

## 4. Operations

| Call | Effect |
|---|---|
| `Tokenize` | Look up each index. On a miss, insert a new token with its sealed value. A token collision retries (5×); an index taken by a concurrent call returns the winner's token. No subject key is created |
| `Detokenize` | Opens active records; omits unknown, forgotten and erased tokens. A value that fails to open is an error |
| `ListTokens` | A page in token order, by prefix. Inactive records show their state only |
| `Forget(id)` graceful | Entry `FORGOTTEN`; the value no longer finds the token, so tokenizing it again gives a **new**, unlinkable token |
| `Forget(id)` immediate | Entry `ERASED` |
| `Recover(id)` | Entry `ACTIVE`, re-indexed unless a newer token took the value |
| `DeleteToken` | Removes the entry; keys untouched (use `Forget` to erase a person) |
| `Purge` | Removes every entry; the key engine removes `@vault` |

`Forget` returns `ErrKeyNotFound` only if the ID has neither a key nor an
entry. Erasure after the grace period: `EraseForgotten(ns, now − grace)` next
to `DeleteUnusedKeys`, or a store TTL that still reports `ERASED` on time.

## 5. Accepted risks

| Risk | Why accepted |
|---|---|
| Vault plus `@vault` reveals the namespace | The same boundary as all encrypted data; the wrapping key's policy is the control |
| Backups keep sealed values until they expire | Bounded by backup retention ([production.md](production.md#backups)) |
| Equal values are visible within a namespace | Inherent to deterministic tokenization; split namespaces that must not link |
| No `@vault` rotation | Needs re-sealing and re-indexing; comes with key versions |
