# Implementing backends

| | |
|---|---|
| Status | **Normative.** R-KE and R-TE are checked by the `privacytest` suites; R-KW is a specification, its interface and suite are not built yet (§3) |
| Audience | Developers and coding agents building a production key store, key wrapper or token store |

The module ships contracts and in-memory engines only. For production you
build:

| Piece | Contract | Needed |
|---|---|---|
| Key store | `core.KeyEngine` | Always |
| Key wrapper | `core.KeyWrapper` (§3, planned) | Always in production. Without it, whoever reads the key store reads all data |
| Token store | `core.TokenEngine` | If you tokenize |
| Audit sink | `privacy.Auditor` | For regulated data ([audit-events.md](audit-events.md)) |
| Encryptor | `core.Encryptor` | Rarely. Prefer the default AES-256-GCM (§5) |

Compose them as `cache (Protector) → key wrapper → key store`. The
`Protector` adds the cache itself.

## 1. Rules for every backend

1. **Pass the conformance suite** of the contract, in CI, against the real
   storage (an emulator is fine). It checks the requirements below by ID.
2. **Never log, wrap into errors or export** key material, sealed values or
   blind indexes. `core.Key` redacts itself; raw `[]byte` does not.
3. **Return copies.** Callers zero the keys they receive.
4. **Be safe for concurrent use**, across goroutines and across processes.
5. **Treat the namespace as part of every key.** Nothing in one namespace may
   be read, changed or listed through another.
6. **Report your grace period** through `core.GracePeriodReporter`, so audit
   events can say when erasure is final.

## 2. Key store: `core.KeyEngine`

The store keeps, per (namespace, key ID): the key bytes it is given (wrapped
by the wrapper), a state, and the time the key was disabled.

| ID | Requirement |
|---|---|
| R-KE-1 | `GetKeys` puts every requested ID in exactly one of `keys` or `missing`; `missing` holds `DISABLED`, `DELETED` or `UNKNOWN` |
| R-KE-2 | An ID without a record is `UNKNOWN`. `UNKNOWN` is never stored |
| R-KE-3 | `GetOrCreateKeys` creates a key only if no record exists, atomically: concurrent calls for one ID, in any process, all return the same key. Use a conditional write and read the winner on conflict |
| R-KE-4 | `GetOrCreateKeys` never creates a key for a `DISABLED` or `DELETED` ID; it leaves it out of the result |
| R-KE-5 | `DisableKey` and `ReEnableKey` return `ErrKeyNotFound` for a deleted or unknown ID and write nothing. Disabling twice keeps the first time |
| R-KE-6 | A key disabled for the grace period or longer is reported `DELETED` on every read and cannot be re-enabled, whether or not its material is removed yet |
| R-KE-7 | `DeleteKey`, `DeleteUnusedKeys` (or your storage TTL) and `PurgeNamespace` remove key material from storage, not just flag it. `DeleteKey` keeps a `DELETED` record |
| R-KE-8 | `PurgeNamespace` removes every record of the namespace and is idempotent; purged IDs read `UNKNOWN` and may be created again |
| R-KE-9 | `DeleteKey` and `PurgeNamespace` on an unknown ID or empty namespace succeed and write nothing |

Erasure after the grace period can run two ways: a scheduled job calls
`DeleteUnusedKeys`, or the store expires material by itself (a storage TTL).
With a TTL, keep the material in its own record so the `DELETED` marker
survives, and still enforce R-KE-6 on read: TTLs fire late.

## 3. Key wrapper: `core.KeyWrapper` (planned)

Envelope encryption: a KEK held in a KMS or HSM wraps each DEK; the key store
only ever holds wrapped DEKs. This is the production pattern. The library will
ship the interface, a generic engine that turns a wrapper and a store into a
`core.KeyEngine`, and a conformance suite. Until then, implement the same
behaviour as a `core.KeyEngineWrapper`.

```go
// Planned. Names may change before release.
type KeyWrapper interface {
    // GenerateKey returns a new 32-byte DEK and its wrapped form, bound to
    // namespace and keyID.
    GenerateKey(ctx context.Context, namespace, keyID string) (plain Key, wrapped []byte, err error)
    // UnwrapKey returns the DEK, only for the namespace and keyID it was
    // generated for.
    UnwrapKey(ctx context.Context, namespace, keyID string, wrapped []byte) (Key, error)
}
```

| ID | Requirement |
|---|---|
| R-KW-1 | A wrapped DEK unwraps only under the namespace and key ID it was generated for (KMS encryption context, or AAD for a local AEAD wrap) |
| R-KW-2 | The KEK never leaves the KMS or HSM. Plaintext DEKs exist only in the application's memory, never in storage or logs |
| R-KW-3 | DEKs are 32 bytes from the KMS, the HSM or `crypto/rand`, never derived from the key ID |
| R-KW-4 | Unwrapping a tampered, truncated or foreign blob fails. It never returns other bytes |
| R-KW-5 | The binding never changes for stored keys. Version it (a `v` entry) so a new layout can be told apart |
| R-KW-6 | When two processes create the same key at once, only the stored blob's DEK is used: the loser unwraps the winner's blob rather than keeping its own plaintext |

R-KW-6 is the subtle one. The generic engine will handle it once for every
wrapper; a hand-written wrapper must compare the blob the store returns with
the one it generated.

Deployment rules ([threat-model.md](threat-model.md#4-separation-of-duties)):

- Grant the application unwrap and generate rights **scoped to the binding**
  (for example a KMS condition on the namespace), not on the whole KEK.
- KMS logs record the binding in clear. Subject IDs are pseudonymous by rule;
  map them to an opaque reference if your logs must not hold them.
- A KEK per tenant turns tenant offboarding into one KEK deletion, which also
  shreds the tenant's key store backups.
- KEK deletion is irreversible mass erasure: protect it with the KMS's
  deletion window and alerting.

## 4. Token store: `core.TokenEngine`

The store keeps vault records (token, blind index, sealed value, state, times)
and index entries mapping a blind index to its token. It never sees a value.

| ID | Requirement |
|---|---|
| R-TE-1 | Store `Index` and `Sealed` as opaque bytes. Look values up by `Index` only; never derive, log or index anything from `Sealed` |
| R-TE-2 | `Insert` writes the record and its index entry together or not at all, on two conditions: the token is new (`ErrTokenExists`) and the index is free (`*IndexTakenError` naming the winner) |
| R-TE-3 | `Forget`, `Erase` and `DeleteToken` remove the index entry only if it still points to the token |
| R-TE-4 | `Forget` keeps the first forget time; `Restore` re-indexes only if the index is free and fails with `ErrTokenErased` on an erased record; `Erase` removes the sealed value |
| R-TE-5 | A record forgotten for the grace period or longer is reported `ERASED`, without its sealed value, and cannot be restored, whether or not `EraseForgotten` ran |
| R-TE-6 | `ListTokens` returns tokens in order, filtered by prefix and paged; cursors hold tokens, never values or indexes |
| R-TE-7 | `PurgeNamespace` removes every record and index entry of the namespace and is idempotent |

The vault's design is in [token-vault.md](token-vault.md).

## 5. Encryptor: `core.Encryptor`

Replace the default only for a construction you must use (a FIPS module, say).

| ID | Requirement |
|---|---|
| R-EN-1 | `Algorithm()` is a unique, stable ID: one ID, one exact construction, forever. `0x01` is the default, `0xFF` is for test doubles |
| R-EN-2 | Encryption is authenticated, and the whole `core.Binding` (namespace, key version) and the algorithm ID are authenticated with it |
| R-EN-3 | Every encryption uses a fresh nonce; `Decrypt` fails on any change to the ciphertext, binding or key |
| R-EN-4 | Keys of the wrong size or all zeros are refused |
| R-EN-5 | Streams fail on truncation, reordering, duplication or appended data |

## 6. Conformance suites

```go
func TestKeyStore(t *testing.T) {
    privacytest.RunKeyEngineTest(t, t.Context(), mystore.NewKeyEngine(client),
        func(c *privacytest.KeyEngineTestConfig) {
            c.GracePeriod = 2 * time.Second
            c.KeyMaterialProbe = mystore.ProbeKeyMaterial(client) // reads storage directly
        })
}

func TestTokenStore(t *testing.T) {
    privacytest.RunTokenEngineTest(t, t.Context(), mystore.NewTokenEngine(client))
}
```

Set `KeyMaterialProbe`: without it the suite cannot check R-KE-7. Set
`ErasesWithoutJanitor` if your store erases through a TTL. Run the suite once
per composition you deploy (store alone, and wrapper over store).

## 7. Checklist

- [ ] Every requirement above holds, and the suite passes against real storage.
- [ ] `GetOrCreateKeys` and `Insert` use conditional writes, not read-then-write.
- [ ] The grace deadline is checked on every read, not left to a TTL.
- [ ] Key material and sealed values never reach logs, metrics or errors.
- [ ] The application's KMS rights are scoped to the binding; DBAs have none.
- [ ] Backups of the key store have a retention you can state.
- [ ] A job or a TTL completes erasure, and you monitor that it runs.
