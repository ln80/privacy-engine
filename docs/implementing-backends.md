# Implementing backends

| | |
|---|---|
| Status | **Normative.** Checked by the `privacytest` suites (§6) |

| You build | Contract | When |
|---|---|---|
| Key store | `core.KeyEngine` | Always |
| Key wrapper | `core.KeyWrapper` | Always in production |
| Token store | `core.TokenEngine` | If you tokenize |
| Audit sink | `privacy.Auditor` | Regulated data ([audit-events.md](audit-events.md)) |
| Encryptor | `core.Encryptor` | Rarely (§5) |

Combine them with `envelope.NewKeyEngine(wrapper, store)`; the `Protector` adds its cache.

## 1. Every backend

1. Passes its conformance suite in CI, against real storage or an emulator.
2. Never logs or returns in errors key material, sealed values or indexes.
3. Is safe for concurrent use, across goroutines and processes.

## 2. Key store: `core.KeyEngine`

Stores per (namespace, key ID) the bytes it is given, a state and the
disable time.

| ID | Requirement |
|---|---|
| R-KE-1 | `GetKeys` puts each requested ID in exactly one of `keys` or `missing` (`DISABLED`, `DELETED`, `UNKNOWN`). Returned keys are copies the caller may zero |
| R-KE-2 | An ID without a record is `UNKNOWN`, never stored |
| R-KE-3 | `GetOrCreateKeys` creates only if no record exists, atomically: concurrent callers in any process get the same key. Use a conditional write; on conflict, read the winner |
| R-KE-4 | `GetOrCreateKeys` never creates a key for a `DISABLED` or `DELETED` ID; it omits it |
| R-KE-5 | `DisableKey` and `ReEnableKey` return `ErrKeyNotFound` for a deleted or unknown ID and write nothing. A second disable keeps the first time |
| R-KE-6 | A key disabled for the grace period or longer reads `DELETED` and cannot be re-enabled, whether or not its material is gone |
| R-KE-7 | `DeleteKey`, `DeleteUnusedKeys` (or a TTL) and `PurgeNamespace` remove material, not just flag it. `DeleteKey` keeps a `DELETED` record |
| R-KE-8 | `PurgeNamespace` removes every record, idempotently; purged IDs read `UNKNOWN` |
| R-KE-9 | `DeleteKey` on an unknown ID writes nothing |
| R-KE-10 | Namespaces are isolated: one key ID in two namespaces is two independent keys |
| R-KE-11 | An engine with a grace period reports it through `core.GracePeriodReporter`, so audit events can state `FinalAt` |

To expire material with a storage TTL, keep it in its own record so the
`DELETED` marker survives, and still enforce R-KE-6 on read: TTLs fire late.

## 3. Key wrapper: `core.KeyWrapper`

A KEK in a KMS or HSM wraps every DEK; the store holds wrapped DEKs only. You
implement two methods; `envelope.NewKeyEngine(wrapper, store)` does the rest,
including R-KW-6. `memory.NewKeyWrapper` is a reference for tests.

```go
type KeyWrapper interface {
    // GenerateKey returns a new 32-byte DEK and its wrapped form, bound to namespace and keyID.
    GenerateKey(ctx context.Context, namespace, keyID string) (plain Key, wrapped []byte, err error)
    // UnwrapKey returns the DEK, only for the namespace and keyID it was generated for.
    UnwrapKey(ctx context.Context, namespace, keyID string, wrapped []byte) (Key, error)
}
```

| ID | Requirement |
|---|---|
| R-KW-1 | A wrapped DEK unwraps only under its namespace and key ID (KMS encryption context, or AEAD AAD) |
| R-KW-2 | The KEK never leaves the KMS or HSM; plaintext DEKs never reach storage or logs |
| R-KW-3 | DEKs are 32 bytes from the KMS, HSM or `crypto/rand` |
| R-KW-4 | A tampered or truncated blob never unwraps to another key: it fails, or yields the original key if only non-secret metadata changed. Another key's blob fails |
| R-KW-5 | The binding of stored keys never changes; version it |
| R-KW-6 | When two processes create one key at once, only the stored blob's DEK is used: the loser unwraps the winner's blob. `envelope.KeyEngine` does this |

Deployment:

- Scope the application's KMS rights to the binding (for example a condition
  on the namespace).
- KMS logs show the binding in clear; map subject IDs to opaque references if
  that matters.
- A KEK per tenant lets one KEK deletion shred a tenant, backups included.
  Guard KEK deletion with the KMS's waiting period and alerts.

## 4. Token store: `core.TokenEngine`

Stores vault records and index entries (blind index → token). Never sees a
value. Design: [token-vault.md](token-vault.md).

| ID | Requirement |
|---|---|
| R-TE-1 | `Index` and `Sealed` are stored as given; look up by `Index` only, derive nothing from `Sealed`. Returned records are copies |
| R-TE-2 | `Insert` writes record and index entry together or not at all, if the token is new (`ErrTokenExists`) and the index free (`*IndexTakenError`) |
| R-TE-3 | `Forget`, `Erase` and `DeleteToken` remove the index entry only if it still points to the token |
| R-TE-4 | `Forget` keeps the first time; `Restore` re-indexes only a free index and fails with `ErrTokenErased` on an erased record; `Erase` removes the sealed value |
| R-TE-5 | The store has a grace period: a record forgotten for it or longer reads `ERASED`, without sealed value, whether or not `EraseForgotten` ran. It reports the period through `core.GracePeriodReporter`, so a token's Forget event states `FinalAt` |
| R-TE-6 | `ListTokens` is ordered, prefix-filtered and paged; cursors hold tokens only |
| R-TE-7 | `PurgeNamespace` removes every record and index entry, idempotently |
| R-TE-8 | Namespaces are isolated |

## 5. Encryptor: `core.Encryptor`

Keep the default unless you must use another construction (FIPS, say), and
run `privacytest.TestEncryptor` on it.

| ID | Requirement |
|---|---|
| R-EN-1 | `Algorithm()` is unique and permanent; `0xFF` is for test doubles |
| R-EN-2 | Authenticated encryption covering the `core.Binding` and the algorithm ID |
| R-EN-3 | A fresh nonce per encryption; any change to ciphertext, binding or key fails |
| R-EN-4 | Wrong-size and all-zero keys are refused |
| R-EN-5 | Streams fail on truncation, reordering, duplication or appended data |

## 6. Conformance

```go
func TestKeyStore(t *testing.T) {
    privacytest.TestKeyEngine(t, mystore.NewKeyEngine(client), func(c *privacytest.KeyEngineTestConfig) {
        c.GracePeriod = 2 * time.Second
        c.KeyMaterialProbe = mystore.ProbeKeyMaterial(client) // reads storage directly, for R-KE-7
    })
}

func TestKeyWrapper(t *testing.T) {
    privacytest.TestKeyWrapper(t, mykms.NewKeyWrapper(client))
    privacytest.TestKeyEngine(t, envelope.NewKeyEngine(mykms.NewKeyWrapper(client), mystore.NewKeyEngine(client)))
}

func TestTokenStore(t *testing.T) {
    privacytest.TestTokenEngine(t, mystore.NewTokenEngine(client, mystore.WithGracePeriod(7*24*time.Hour)),
        func(c *privacytest.TokenEngineTestConfig) {
            c.GracePeriod = 7 * 24 * time.Hour             // R-TE-5; must exceed three hours
            c.SealedProbe = mystore.ProbeSealed(client) // reads storage directly
        })
}
```

Each requirement is a subtest named after its ID: `go test -run
'TestKeyStore/R-KE-3'` runs one. A subtest whose option is not set is
skipped with the option to set. Set `ErasesWithoutJanitor` if a TTL erases,
or `Janitor` to trigger your own job. Run the suite for every composition you
deploy.
