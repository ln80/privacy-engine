---
name: privacy-engine-backend
description: Build and verify a production storage backend for the Go library github.com/ln80/privacy-engine. Covers a core.KeyEngine key store, a core.KeyWrapper for a KMS or HSM such as AWS KMS, HashiCorp Vault Transit, Google Cloud KMS or Azure Key Vault (envelope encryption), and a core.TokenEngine token store, on any database (Postgres, MySQL, SQLite, DynamoDB, Redis, and others). Use when asked to implement a key engine, key store, key wrapper, KMS or HSM integration, token vault or token store for privacy-engine, or to fix failing privacytest conformance tests (subtests named R-KE-*, R-KW-*, R-TE-*, R-EN-*).
license: Apache-2.0
compatibility: Requires Go 1.25 or later and a Go module depending on github.com/ln80/privacy-engine v0.13.0 or later.
metadata:
  author: ln80
  version: "0.13"
---

# Build a privacy-engine backend

privacy-engine ships its logic and storage contracts, not production storage.
A backend is correct when it passes the library's conformance suite against
real storage: the suite checks every numbered requirement (`R-KE-3`) of the
specification. Work test-first and let failing requirement IDs drive the code.

## 1. Read the specification for the version in use

Run the bundled script from the user's Go module:

```sh
sh scripts/locate-docs.sh /path/to/user/module
```

It prints the `docs/` directory of the exact privacy-engine version the
module uses. Read, in this order:

1. `implementing-backends.md`: the requirements (R-KE, R-KW, R-TE, R-EN) and
   the suites. **Normative**: the code must meet it.
2. `key-lifecycle.md`: key states and the erasure timeline.
3. `token-vault.md`: only when building a token store.

If the script says the module does not depend on privacy-engine, run the
`go get` command it prints first.

## 2. Decide what to build

| Component | Contract | Build it when |
|---|---|---|
| Key store | `core.KeyEngine` | Always |
| Key wrapper | `core.KeyWrapper` | Always in production; it keeps the store free of plaintext keys |
| Token store | `core.TokenEngine` | The application tokenizes |
| Encryptor | `core.Encryptor` | Almost never; keep AES-256-GCM |

Compose keys as `envelope.NewKeyEngine(wrapper, store)`. Never hand-write the
envelope logic: `envelope` already handles concurrent creation (R-KW-6).
Never use the `memory` package outside tests.

## 3. Write the conformance tests first

Place them next to the backend, run against real storage (a container, an
emulator such as DynamoDB Local or LocalStack, or a SQLite file):

```go
func TestKeyStore(t *testing.T) {
    store := mystore.NewKeyEngine(db, mystore.WithGracePeriod(2*time.Second))
    privacytest.TestKeyEngine(t, store, func(c *privacytest.KeyEngineTestConfig) {
        c.GracePeriod = 2 * time.Second                 // enables R-KE-6, R-KE-11
        c.KeyMaterialProbe = mystore.ProbeKeyMaterial(db) // reads storage directly, for R-KE-7
    })
}

func TestKeyWrapper(t *testing.T) {
    w := mykms.NewKeyWrapper(kmsClient, keyID)
    privacytest.TestKeyWrapper(t, w)
    // The composition needs the same options: the store under it holds wrapped bytes.
    store := mystore.NewKeyEngine(db, mystore.WithGracePeriod(2*time.Second))
    privacytest.TestKeyEngine(t, envelope.NewKeyEngine(w, store), func(c *privacytest.KeyEngineTestConfig) {
        c.GracePeriod = 2 * time.Second
        c.KeyMaterialProbe = mystore.ProbeKeyMaterial(db)
    })
}

func TestTokenStore(t *testing.T) {
    grace := 7 * 24 * time.Hour // must exceed three hours
    store := mystore.NewTokenEngine(db, mystore.WithTokenGracePeriod(grace))
    privacytest.TestTokenEngine(t, store, func(c *privacytest.TokenEngineTestConfig) {
        c.GracePeriod = grace                      // R-TE-5
        c.SealedProbe = mystore.ProbeSealed(db) // reads storage directly
    })
}
```

A **skipped** subtest means an option is unset: its message names the
option. Set `GracePeriod` and the probes on every suite, compositions
included; a backend is not done while anything is skipped. Both stores take
a grace period, enforce it on read and report it. Set `ErasesWithoutJanitor`
only if storage expires keys by itself (a TTL).

## 4. Implement, one component at a time

Follow the reference for the component; each section is keyed by
requirement ID:

- Key store: [references/key-store.md](references/key-store.md)
- Key wrapper: [references/key-wrapper.md](references/key-wrapper.md)
- Token store: [references/token-store.md](references/token-store.md)

## 5. Fix failures by requirement ID

```sh
go test -race -run 'TestKeyStore' ./...
go test -race -run 'TestKeyStore/R-KE-3' ./...   # one requirement
```

For each failing subtest: read its row in `implementing-backends.md`, then
the matching section of the reference, fix the code, re-run that subtest,
then the whole suite. Never change, skip or weaken the suite to make it
pass: a failing requirement is a data-protection bug.

## 6. Definition of done

- Every suite passes with `-race` against real storage, nothing skipped for
  lack of configuration.
- Key material, sealed values and blind indexes never appear in logs,
  metrics or error messages.
- Creation and insertion use conditional writes, not read-then-write.
- The grace-period deadline is checked on every read.
- The user knows the remaining deployment steps in `production.md`: scope
  the application's KMS rights, deny DBAs unwrap rights, state backup
  retention, run or monitor the erasure job.
