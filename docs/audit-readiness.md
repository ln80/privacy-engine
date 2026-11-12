# privacy-engine: audit-readiness review

| | |
|---|---|
| Scope | `github.com/ln80/privacy-engine` at `a41621a` plus the uncommitted Purge work |
| Started | 2026-10-22 |
| Goal | Harden, document and publish under the ln80 org, then request an external audit (open-security NGOs) |
| Focus | Security hardening first; API design, Go idioms, developer experience, tests, docs and OSS hygiene second |
| Status | Living document: findings are tracked by ID (`PE-xx`) and get a status as fixes land |

## Contents

- [How this review was done](#how-this-review-was-done)
- [Summary](#summary) (all findings by ID)
- [1. Security findings](#1-security-findings)
- [2. API design, Go idioms and developer experience](#2-api-design-go-idioms-and-developer-experience)
- [3. Tests and coverage](#3-tests-and-coverage)
- [4. Against the requested references](#4-against-the-requested-references) (OWASP key management, Go memory protection)
- [5. Docs and open-source hygiene](#5-docs-and-open-source-hygiene)
- [6. Plan](#6-plan)
- [7. Tokenization and the token vault](#7-tokenization-and-the-token-vault)
- [8. Hotfix PR (step 1): scope and plan](#8-hotfix-pr-step-1-scope-and-plan)
- [9. Limits of this review and next round](#9-limits-of-this-review-and-next-round)
- [10. struct-sensitive contract to adopt](#10-struct-sensitive-contract-to-adopt)
- [References](#references)

## How this review was done

- Full read of all ~3.6k lines of Go in the module.
- `go vet`, `go test -race`, coverage, `govulncheck`, `gosec`, `staticcheck`.
- Every finding marked **Confirmed** was reproduced with a proof-of-concept (PoC) test in a scratch copy of the repo built with `GOWORK=off`, so results do not depend on the local `go.work`.
- Spot check of `privacy-engine.elastic` (DynamoDB/KMS backends) to judge real-world impact: its engines do **not** implement `core.KeyEngineCache`, so `NewProtector` always wraps them in `memory.NewCacheWrapper`. Bugs in the cache wrapper therefore apply in production, not just in tests.

Scanners are clean: govulncheck reports 0 reachable vulnerabilities, gosec and staticcheck report nothing, race tests pass. The findings below are design and logic issues that scanners do not catch.

---

## Summary

| ID | Severity | Area | Title | Status |
|---|---|---|---|---|
| PE-01 | Critical | Keys | Cache eviction zeroes keys still in use (and the store's own key) | Fixed |
| PE-02 | Critical | Crypto | Stream truncation is not detected | Fixed |
| PE-03 | High | Crypto | Short ciphertext panics `Decrypt` | Fixed |
| PE-04 | High | Keys | `Forget`/`Recover` report failure after cache expiry although they succeeded | Fixed |
| PE-05 | High | Crypto | Values that look encrypted are never encrypted | Fixed |
| PE-06 | High | Privacy | Subject ID is stored in clear in every ciphertext | Accepted: documented rule |
| PE-07 | High | Factory | Clear func panics after eviction (data race) | Fixed |
| PE-08 | High | Crypto | Key length not enforced (AES-128 silently accepted) | Fixed |
| PE-09 | High | Leakage | Keys and PII leak through `%#v`, `encoding/json` and `log/slog` | Fixed |
| PE-10 | High | Integrity | Decrypting with the wrong namespace silently wipes PII | Fixed |
| PE-11 | Medium | Crypto | Field swap not detected (AAD binds namespace only) | Accepted risk (narrowed) |
| PE-12 | Medium | API | Encrypt/Decrypt are not atomic over a batch | Open |
| PE-13 | Medium | Keys | Erasure latency across instances is undocumented | Open |
| PE-14 | Medium | Keys | `DeriveSubjectKey` output escapes crypto-shredding | Open |
| PE-15 | Medium | Tokens | In-memory TokenEngine deletes its own data on `Clear` | Fixed |
| PE-16 | Medium | Tokens | `WithPrefix` ignored by in-memory engine | Fixed |
| PE-17 | Medium | Tokens | Token collisions not checked | Open |
| PE-18 | Medium | Tokens | `ListTokens` returns all PII in clear, ignores paging | Open |
| PE-19 | Medium | Streams | Abandoned streams leak goroutines | Fixed |
| PE-20 | Medium | Cache | Encrypt path never uses the cache; global lock held during remote calls | Open |
| PE-21 | Medium | Cache | Caches are unbounded | Open |
| PE-22 | Medium | Build | Uncommitted `go.sum` incomplete; local tests depend on `go.work` | Fixed |
| PE-23 | Medium | Keys | No key versioning, so no rotation and no crypto agility | Fixed (format; rotation itself not built) |
| PE-24 | Low | various | See "Low" list | Partly fixed |
| PE-25 | High | Vault | Token vault stores PII in plaintext in three attributes, one of them an index key (elastic) | Open |
| PE-26 | High | Vault | Vault, DEKs and their access policy share one table and one IAM policy (elastic) | Open |
| PE-27 | High | Vault | Token collision returns a token that maps to someone else (elastic) | Open |
| PE-28 | Medium | Vault | Concurrent `Tokenize` of the same value can create two tokens (elastic) | Open |
| PE-29 | Medium | Vault | Vault values survive crypto-shredding in backups and PITR | Open |
| PE-30 | Medium | Tokens | Custom `TokenGenFunc` receives the value, inviting hash-based tokens | Open |

---

## 1. Security findings

### Critical

#### PE-01 Cache eviction zeroes keys still in use. Fixed.
`memory/key_engine.go` used to hand callers the cache's own `[]byte`, and `ClearCache`, `DeleteKey` and `PurgeNamespace` called `core.ZeroKey` on that same backing array.
- PoC: after `ClearCache(force)`, a key the caller already holds becomes 32 zero bytes. AES accepts an all-zero key, so a `Factory.Monitor` tick (every 5 s by default) that lands during `Encrypt` writes PII encrypted under a publicly known key, with no error.
- PoC: with `NewCacheWrapper(memory.NewKeyEngine())`, eviction also zeroes the **origin store's** key (shared slice), making the subject's data undecryptable.
- Fix: `GetKeys` and `GetOrCreateKeys` return `bytes.Clone` copies, and the cache stores a separate clone. `ZeroKey` runs only on a slice the cache owns. `Protector` zeros its copies after encrypt, decrypt, stream, and key derivation. Rejecting an all-zero key remains PE-08.

#### PE-02 Stream truncation is not detected. Fixed.
The end-of-stream marker (`aes/256_gcm.go:156`, check at `:216`) is four unauthenticated zero bytes. Anyone can drop all chunks after a boundary and append `00 00 00 00`; `DecryptStream` returns the shorter plaintext with `err == nil`. PoC: a 20-byte stream cut to header + marker decrypts to an empty body without error. The header (version, base nonce) is also outside the AAD.
- Fix: STREAM construction (as in Tink and age): a "final chunk" flag in each chunk's nonce or AAD, header bound into the AAD, EOF before the final chunk is an error. New stream format version.
- Done (stream format v2, `aes/stream.go`; v1 is no longer readable, by decision: no deployed data to keep). Header `version | alg | key version | segment size | salt | nonce prefix` (key version added in the PE-23 work; full layout in `wire-format-v2.md` section 5). Per-stream key `HKDF-SHA256(DEK, salt, "privacy-engine/stream/v2" | len16(namespace) | namespace)`, so field and stream encryption no longer share a key and the namespace is length-prefixed (two PE-24 items). Segment nonce `prefix | index | final flag`; the header is every segment's AAD. Segments are filled with `io.ReadFull`, so boundaries no longer depend on the source reader (PE-24). Regression tests in `aes/stream_test.go`: every truncation offset, the v1 marker forgery, drop/swap/duplicate/append, every single-bit flip, wrong key and namespace, bad headers; `FuzzDecryptStream` checks that any change to a valid stream fails.

### High

#### PE-03 Short ciphertext panics `Decrypt`. Fixed.
`aes/256_gcm.go:89` slices `cipherTxt[:12]` with no length check. The field value `ENC..dTE=.AQID` (3-byte ciphertext) crashes the process: `slice bounds out of range [:12] with capacity 3`. Anyone who can write one field value can take the service down.
- Done: `Decrypt` rejects anything shorter than nonce + tag before slicing. Regression: `TestAES256DecryptShortCiphertext`, `TestProtector_DecryptShortCiphertext`; `FuzzDecrypt` added.

#### PE-04 `Forget`/`Recover` report failure after cache expiry. Fixed.
The cache wrapper's `DisableKey`/`ReEnableKey` call the origin first, then return `ErrKeyNotFound` if the key is not in the local cache (`memory/key_engine.go:200`, `:228`). PoC with a real wrapper: `Forget` returns "encryption key not found" while the origin key *was* disabled; `Recover` returns "cannot recover subject" while the origin key *was* re-enabled. For an erasure API this is the worst error mode: callers retry or escalate a GDPR request that already happened, or tell a user recovery failed when it worked. Since production engines are always wrapped (see method), this hits production.
- Done: as a cache, `DisableKey` and `ReEnableKey` return the origin's result. On success the cached entry is dropped and its key wiped, so the next read follows the origin and a disabled key no longer stays in memory. Store mode (no origin) is unchanged. Regression: `TestCacheWrapperDisableReEnableFollowOrigin`, `TestProtector_ForgetRecoverAfterCacheClear`, and a cache block in the `privacytest` conformance suite that runs for any `KeyEngineCache` with an origin; all three fail without the fix with the PoC's `encryption key not found`.

#### PE-05 Values that look encrypted are never encrypted. Fixed.
The idempotency check `protector.go:219` skips any value matching `ENC.<v>.<b64>.<b64>`. PoC: user input `ENC..YQ==.YQ==` is stored as-is. An attacker can also plant a value naming another subject's ID.
- Fix: do not infer "already encrypted" from the value alone. Either require the value to authenticate under the struct's subject key before skipping, or track state outside the value; never trust the embedded subject ID over the struct's `subjectID` field.
- Done: `Encrypt` keeps a value in wire format only if it authenticates under its own subject's active key, or if that subject is forgotten (a shredded value). Any other look-alike fails with `ErrValueNotAuthentic`; a value naming an unknown subject fails with `ErrKeyUnknown`. The embedded subject ID is kept and trusted only through authentication (decision in `wire-format-v2.md` section 3). Regression: `key_state_test.go`.

#### PE-06 Subject ID in clear in every ciphertext. Accepted, with a documented rule.
`wire_format.go:48` base64-encodes the subject ID into the value (PoC: `ENC..dTE=.` is `u1`). Subject IDs are often emails or account IDs, so every "encrypted" record still says whose it is, keeps saying so after crypto-shredding, and enables linkage across datasets. This conflicts with data minimisation and will be a headline item for a privacy-focused auditor.
- Fix (format v2): store an opaque key reference instead, e.g. a random key ID kept by the KeyEngine, or `HMAC(namespace secret, subjectID)`.
- Resolution: not applied, after review. The subject stays in the value because it makes values self-describing (they decrypt into any type, copies keep following their owner's key and are shredded with it, rotation and audit jobs need no domain types), while the record already stores the same subject in clear in its `subjectID` field. An opaque reference would hide nothing the record does not show. The real risk, a direct identifier used as subject, is closed by a rule in the README, the package godoc and `wire-format-v2.md` section 6: subject IDs must be pseudonymous (random IDs or tokenizer tokens). The rationale is recorded for the auditor in `wire-format-v2.md` sections 6 and 8.

#### PE-07 Factory clear func panics after eviction. Fixed.
`factory.go:96` reads `f.reg[namespace]` without the lock and dereferences it. After `Monitor` evicts the entry, the documented `defer clear()` panics with a nil-pointer dereference. It is also a data race on the map.
- Done: the clear func captures the protector handed out by `Instance` and never reads the registry. Clearing an evicted protector only wipes its own cache. Regression: `TestFactory_ClearFuncAfterEviction` (panics without the fix; concurrent Instance, eviction and clear funcs are clean under `-race`).

#### PE-08 Key length not enforced. Fixed.
`aes.NewCipher` accepts 16/24/32-byte keys, so a 16-byte key from a custom `KeyGen`, a backend bug, or `EncryptStreamWithKey` used to silently give AES-128 while the docs promise AES-256. A 32-byte all-zero key was accepted too. `Encrypt`, `Decrypt`, `EncryptStream`, and `DecryptStream` now reject any key that is not 32 bytes or is all zeros.

#### PE-09 Keys and PII leak through `%#v`, JSON and slog. Fixed.
`core.Key.String()` and `core.TokenData.String()` redact only `%v`/`%s`. PoC output:
- `fmt.Sprintf("%#v", key)` prints `core.Key{0x1, 0x2, 0x3}`.
- `json.Marshal` prints the key as base64 and `TokenData` in clear.
- `slog` JSON handler logs `"key":"AQID","data":"alice@x.io"` and the same for `TokenRecord`.
- Fix: implement `GoString`, `slog.LogValuer` (`LogValue`) and `MarshalJSON`/`MarshalText` (redact, or return an error) on `Key` and `TokenData`; add tests per format.
- Done (`core/redact.go`): `Key`, `IDKey` and `TokenData` implement `fmt.Formatter` (every verb, not only `%#v`: `%d` also printed key bytes), `GoString`, `LogValue`, `MarshalText` and `MarshalJSON`, all printing a fixed placeholder. Marshaling redacts rather than fails, so log lines holding these values still render. Two leaks beyond the PoC were found and closed: `IDKey` keeps its key in an unexported field, which `fmt` prints without calling any method; and `encoding/json` uses a string-kind map key directly, so `ValueTokenMap` put every token value in clear in its keys (it now encodes as a sorted list of redacted records). Explicit access is unchanged: `Reveal()`, `[]byte(key)`, `IDKey.Key()`. Regression: `core/redact_test.go` checks 11 fmt verbs plus Sprint, JSON (direct, nested, map keys) and both slog handlers for the secret in raw, hex, base64 and decimal form. Limit: a map keyed by `TokenData` declared outside this package, or an unexported field of these types in caller structs, can still leak through JSON or fmt; documented in `redact.go`.

#### PE-10 Wrong namespace silently wipes PII. Fixed.
`Decrypt` treats "no key for this subject" as "subject forgotten" and replaces the field with the `replace` value. PoC: data encrypted by `tenant-a` and decrypted by a `tenant-b` protector returns `err == nil` and an empty email. If the caller then saves the struct, data is lost. The same happens with a mis-configured backend or a transient empty response.
- Fix: distinguish "deleted/disabled" (engine knows the state) from "unknown key", and return an error for unknown. Consider binding the namespace into the wire value so mismatches are detected before key lookup.
- Progress: `KeyEngine.GetKeys` now reports `Disabled`, `Deleted` or `Unknown` for every requested ID without an active key, tested in `privacytest` for every backend. Done: `Decrypt` applies the placeholder only for disabled or deleted keys; an unknown key is `ErrKeyUnknown` and leaves the struct untouched (wrong namespace, purged tenant, misconfigured backend). Streams and `DeriveSubjectKey` report the same distinction. Regression: `key_state_test.go`.

### Medium

- **PE-11 Field swap not detected. Accepted risk (narrowed).** AAD was only `ns:<namespace>` (`aes/util.go`). Ciphertexts can be moved between fields or records of the same subject without detection. Bind subject and field path into the AAD in format v2. Resolution: the AAD now binds namespace, algorithm and key version, and per-subject keys already reject moves across subjects; only a swap between two values of the same subject and namespace remains. Binding Go field paths was rejected because a refactor would make old data unreadable (a real hazard for event-sourced callers). A stable `bind=<name>` tag option can come later as a new algorithm ID. See `wire-format-v2.md` section 7.
- **PE-12 Batch Encrypt/Decrypt not atomic.** If struct #3 fails, structs #1-2 are already mutated; on `Encrypt` that leaves a batch half plaintext. Encrypt into copies, commit on success.
- **PE-13 Erasure latency.** Other processes keep serving a forgotten subject's cached key until their TTL. Acceptable, but must be documented as a bounded erasure delay, with the TTL as the bound.
- **PE-14 `DeriveSubjectKey` escapes crypto-shredding.** If callers persist the derived key, `Forget` no longer erases data encrypted with it. Document clearly; consider an API that never returns raw derived bytes.
- **PE-15 In-memory TokenEngine deletes its own data. Fixed:** as a store (no origin) `ClearCache` is a no-op, forced or not, as for the key engine; regression `TestTokenStoreSurvivesClearCache`. Was: `memory/token_engine.go:162` lacks the "store vs cache" guard the key engine has. PoC: with `memory.NewTokenEngine()`, a non-forced `Clear` (what `Monitor` does) deletes all tokens after ~1 s.
- **PE-16 `WithPrefix` ignored. Fixed:** the in-memory store prepends the prefix to the generated token, as the DynamoDB engine does; the `privacytest` token suite now checks `Prefix` for every backend. Was: by the in-memory engine (PoC: plain UUID returned), while the README and example advertise it.
- **PE-17 Token collisions not checked.** A custom `TokenGenFunc` that collides overwrites another person's mapping, so `Detokenize` returns the wrong person's data. Check-and-retry on insert.
- **PE-18 `ListTokens` is a bulk PII export.** It returns every value in clear, and the memory implementation ignores `Limit`, `Cursor`, `Prefix` and `SearchText` (`memory/token_engine.go:20`). Needs paging, a clearly privileged name, and an audit hook.
- **PE-19 Abandoned streams leak goroutines. Fixed** by the PE-02 rewrite: both stream readers are pull-based and start no goroutine (regression: `TestStreamAbandonedLeaksNoGoroutine`). Was confirmed: `EncryptStream`/`DecryptStream` return `io.Reader`; a caller that stops reading leaves the writer goroutine blocked forever (PoC: 50 abandoned streams leave 50 goroutines and their 4 MB buffers). Return `io.ReadCloser` and close the pipe on `Close`, and honour `ctx`.
- **PE-20 Encrypt path bypasses the cache.** Confirmed: with the cache on, 5 `Encrypt` calls for the same subject make 5 origin `GetOrCreateKeys` calls (`memory/key_engine.go`, origin branch). The wrapper also holds the global write lock across that remote call, serialising all namespaces and ignoring `ctx` cancellation while waiting. Cost and availability issue for the KMS backend.
- **PE-21 Caches are unbounded.** Key and token caches grow with every subject seen until TTL; a burst of unique subjects is a memory DoS and keeps more PII and keys resident. Add a size bound (LRU).
- **PE-22 Build depends on `go.work`.** The uncommitted `go.sum` lacks `/go.mod` hashes for litter, testify, go-spew, go-difflib and yaml.v3. With `GOWORK=off`, the root package fails to build its tests; CI will fail. Locally, tests run against the workspace's struct-sensitive rather than v0.7.0. Run `GOWORK=off go mod tidy && GOWORK=off go test ./...` before committing, and in CI.
- **PE-23 No key versioning.** The wire format has no key version or algorithm ID, so DEKs can never rotate, and swapping the `Encryptor` silently breaks old data. Add both in format v2 (see OWASP section). Progress: `core.Encryptor` takes a `core.Binding{Namespace, KeyVersion}` and reports an algorithm ID; both are authenticated in field and stream ciphertexts, and the stream header carries the key version. Field values now record them (`ENC.<subject>.<alg | keyVersion | ciphertext>`) and Decrypt rejects an unknown algorithm or key version before the key lookup. Rotation itself (several DEK versions per subject) is not built; the format no longer stands in its way.

### Low (PE-24)

- AES-GCM with random 96-bit nonces is fine per subject; document the ~2^32 messages-per-key bound. Field and stream encryption share one DEK; derive separate subkeys. **Done:** bound documented (`wire-format-v2.md` section 3); streams use a per-stream HKDF key.
- AAD `ns + "|chunk:" + n` is ambiguous if a namespace contains `|chunk:`; use length-prefixed encoding. **Done:** field AAD and stream key derivation length-prefix the namespace.
- Cache TTL is compared in whole Unix seconds, so a TTL under 1 s behaves as 0 (tests use `CacheTTL = 1`, i.e. 1 ns).
- Decrypted PII and `TokenData` are Go `string`s and cannot be wiped (see section 4).
- `NewProtector("")` silently uses the shared namespace `"default"`; in multi-tenant code an error is safer.
- `Clear` tags the namespace as the subject in its error (`protector.go:487`).
- `Monitor` never stops its ticker and can be started twice.
- Stream chunk size depends on the source reader's `Read` behaviour; use `io.ReadFull` for deterministic chunks. **Done** in stream format v2.

---

## 2. API design, Go idioms and developer experience

### Interfaces
- **`Protector` is a 16-method interface returned by `NewProtector`.** It mixes field encryption, streams, key derivation, tokenization, lifecycle and cache control. Every addition (like `Purge` now) is a breaking change for anyone who implements or wraps it (the repo's own `spyProtector` embeds it). Go convention is "accept interfaces, return structs": return `*Protector`, and let consumers define the small interfaces they need. If shared interfaces are wanted, split them (`FieldEncrypter`, `StreamEncrypter`, `Shredder`, `Tokenizer`).
- **`core.KeyEngine` and `core.TokenEngine` grow by adding methods.** `PurgeNamespace` breaks every third-party backend. For a published module, add new capabilities as optional interfaces discovered by type assertion, or accept the break only with a major version bump. Write the policy down.
- **`core.Encryptor` takes plaintext as `string` and no `ctx`.** Binary payloads must be converted, and the plaintext can never be wiped. Prefer `[]byte` in and out. `KeyGen` receives `namespace, keyID` that no implementation uses.
- **Streams return `io.Reader`**; return `io.ReadCloser` (PE-19) and take `ctx`.

### Wrapper and cache logic
- `memory.engine` is both a store (`origin == nil`) and a cache (`origin != nil`), switched by `if` in every method. That dual role is the root cause of PE-01 (store and cache share key slices), PE-15 (token store wipes itself) and the differing `ClearCache` semantics between the key and token types. Split into `memory.KeyStore`/`memory.TokenStore` (test backends) and a `cache` package with `cache.KeyEngine`/`cache.TokenEngine` decorators.
- `NewProtector` decides to wrap by checking whether the engine implements `KeyEngineCache`. That is implicit: passing the in-memory store silently disables caching, and any backend that happens to have `ClearCache` changes behaviour. Prefer an explicit option such as `WithCache(ttl)` / `WithoutCache()`.
- Cache coherence rules (what happens on Disable/ReEnable/Delete across instances, TTL as erasure bound) are not documented and not covered by the `privacytest` conformance suites, which is how PE-04 slipped through.

### Configuration
- Options are anonymous `func(*ProtectorConfig)` that poke at a public, mutable config struct, while tokenization has a named `WithPrefix`. Pick one style: named options (`WithCacheTTL`, `WithTokenEngine`, `WithHardDelete`) are more discoverable in godoc and editors.
- Hidden defaults: `CacheTTL: 0` means 20 s, `CacheEnabled` defaults to `true`, and `GracefulMode` defaults to `true` with the grace period configured elsewhere (`KeyEngineConfig`). Document defaults on the fields, or make the zero value meaningful.
- Constructors panic on `nil` engines. Acceptable for programmer errors, but say so in godoc; `NewFactory` panics too.

### Errors
- Two error styles: `core` uses sentinels via `errors.New`; the root package uses a custom `Error` value type whose `Is` matches by message only. Token methods return raw `core` errors, so callers get `privacy.Error` from `Encrypt` but not from `Tokenize`. Make every public method wrap consistently.
- `Error.Err` is exported, so callers can mutate it; `Error()` correctly omits namespace and subject (good for logs).
- Unsupported wire version or a single tampered field aborts the whole batch; consider per-field error reporting (`errors.Join` with field paths, never values).

### Naming
- One concept, three names: `subID`, `subjectID`, `keyID`. Pick `subjectID` in the public API.
- `GracefulMode` reads like shutdown behaviour; `SoftDelete` or `RecoverableForget` says what it does.
- `FactoryConfig.IDLE` (all caps) is not idiomatic; `IdleTimeout`.
- `aES265KeySize` (typo: 265 vs 256, odd casing); `New256GCMEncryptor` / `Key256GenFn` read better as `aes.NewGCM256()` / `aes.GenerateKey256`.
- `CheckFormat` is vague; `ValidateWireFormat` or `IsEncrypted`.
- `memory.NewKeyEngine` returns an interface while `memory.NewTokenEngine` returns the exported struct `*TokenEngine`; keep the two consistent.
- Package name `privacy` differs from the module path `privacy-engine`. Fine in Go, but say it in the README import example (it already uses `privacy.`).
- Godoc wording: "presents" is used for "represents" throughout; typos "renable", "KetEngine", "does clears", "Encryption Keys are sensitive..." comment on the wrong type. A pass with `misspell` already in CI won't catch these.

### Developer experience
- `ValueTokenMap.Get(v string)` takes `string` while keys are `TokenData`, which is convenient but hides the type that carries redaction.
- No way to ask "is this subject forgotten?" or "is this value encrypted for subject X?" without decrypting.
- `privacytest` is a good idea (conformance suites for backends). Document it as the contract third-party backends must pass and add cache-wrapper and concurrency cases.
- Example output depends on `litter`, a third-party pretty-printer, which also ends up as a direct `require` of the library. Use `fmt` in the example or move it to a separate example module.
- README promises features that are broken today (`WithPrefix`, stream integrity). Fixes or caveats must land before publishing.

---

## 3. Tests and coverage

- Total 41% (root 66%, memory 79%). **`aes` has no tests**: the crypto core, the streaming codec shipped in "Fix: wire format + streaming codec", `EncryptStream`/`DecryptStream`, `DeriveSubjectKey` and the `*WithKey` methods are all at 0%.
- Missing: known-answer tests, tamper tests (bit flip, chunk swap, chunk drop, truncation, header edit), fuzz targets for `parseWireFormat`, `Decrypt` and `DecryptStream` (Go's `testing.F` would have found PE-03 in seconds), concurrency tests between `Monitor` and `Encrypt` (PE-01), redaction tests (PE-09).
- `make test` excludes `privacytest`, and gosec excludes it; fine for mocks, but the conformance suites themselves should run against the in-memory engines (they do) and the cache wrapper (they don't).
- Proposed bar before audit: `aes` ≥ 90%, overall ≥ 80%, a regression test per finding ID, fuzzing in CI.

---

## 4. Against the requested references

### OWASP Key Management Cheat Sheet
| Area | Status |
|---|---|
| Approved algorithms and sizes | AES-256-GCM and HKDF-SHA256 are right; size not enforced (PE-08) |
| Key generation | `crypto/rand`: good |
| Key hierarchy / KEK wrapping | Delegated to KeyEngine (DynamoDB + KMS in privacy-engine.elastic); this library holds plaintext DEKs only. State it in the threat model |
| Key separation | Partial: one DEK for field and stream encryption; HKDF derivation is good |
| Cryptoperiod and rotation | Missing (PE-23) |
| Compromise and destruction | Disable → grace → delete exists; correctness broken by PE-01 and PE-04 |
| Keys in memory | Zeroing exists but is unsafe (PE-01); see Go section |
| Accountability and audit logging | Missing: no hook for key access, Forget, Recover, Detokenize, ListTokens |
| Lifecycle documentation | Missing |

### Tokenization under privacy by design
See section 7 for the full assessment against GDPR Art. 4(5), EDPB Guidelines 01/2025 and ENISA, and for the vault encryption question.

### In-memory keys in Go
Go gives memory safety (no reading past a buffer), not secret-memory protection:
- The GC can copy stack data and leaves freed heap memory un-wiped until reuse, so `ZeroKey` clears one copy at best. `aes.NewCipher` expands the key into a schedule inside `crypto/aes` that you cannot zero.
- No `mlock`: keys can be swapped to disk or land in core dumps.
- `string` is immutable: decrypted PII and `TokenData` can never be wiped.
- **`runtime/secret`** (Go 1.26, experimental): `secret.Do(f)` erases registers, stack and, once unreachable, heap allocations made inside `f`. It only exists when building with `GOEXPERIMENT=runtimesecret`, is outside the Go 1 compatibility promise, and only does real work on linux/amd64 and linux/arm64 (elsewhere `Do` just calls `f`). Go 1.27 only extended it (goroutines started inside secret mode inherit it); it is still experimental. No graduation date has been announced.
- **FIPS 140-3 mode** (`GODEBUG=fips140=on`, Go 1.24+) gives a validated module for AES-GCM and HKDF; document support for it.
- Recommendations: make keys owned and short-lived (PE-01), use `[]byte` not `string` for secrets and plaintext where the API allows, document that an attacker with access to process memory is out of scope, offer `runtime/secret` behind a build tag, and optionally a `memguard`-backed store (mlock, guard pages, encrypted enclave) for high-assurance users rather than by default.

---

## 5. Docs and open-source hygiene

| Item | Status |
|---|---|
| LICENSE file | **Missing** (README says MIT). Blocker for publishing |
| SECURITY.md (disclosure contact, supported versions, response times) | Missing |
| Threat model / security design | Missing: assets, attackers, trust boundaries (KeyEngine, storage, process memory), what crypto-shredding does and does not guarantee, erasure latency |
| Wire and stream format spec | **Done:** `docs/wire-format-v2.md` (byte layouts, AAD, key states, behaviour, accepted risks) |
| CONTRIBUTING, CODE_OF_CONDUCT, CODEOWNERS | Missing |
| CHANGELOG and semver/compat policy | Missing; interface additions are breaking for backends |
| CI supply chain | Actions pinned by tag, not SHA; `securego/gosec@master` unpinned; no `permissions:` block; no govulncheck, fuzz job, Dependabot/Renovate or OpenSSF Scorecard; CI uses the module without `go.work` (good) but local dev doesn't (PE-22) |
| Test-only dependency in main module | `litter` only used by `example_main_test.go` |
| README | Good overview; fix `WithPrefix` and stream claims, link the threat model, drop "MIT" until the file exists |

---

## 6. Plan

Small, separate PRs, in this order. Steps 1-3 are what an auditor would block on.

1. **Hotfixes, no format change:** PE-01, 03, 04, 07, 08, 09, 10, 15, 16, 19, 22, each with a regression test. Detailed in section 8.
2. **Format v2 (one breaking change). Done** on `fix/audit-hardening`, see `wire-format-v2.md`: STREAM construction (PE-02), key version + algorithm ID (PE-23), length-prefixed AAD, safe idempotency (PE-05), key states (PE-10). Changed after review: the subject ID stays (PE-06 becomes a rule), field binding is an accepted risk (PE-11), and v1 is not kept at all (no deployed data).
3. **Tests:** `aes` unit, known-answer and tamper tests; fuzz targets; cache-wrapper and concurrency cases in `privacytest`; coverage gate in CI.
4. **API cleanup (before v1.0, while breaking is cheap):** return `*Protector`, split store vs cache, named options, consistent errors and naming (section 2).
5. **Hygiene:** LICENSE, SECURITY.md, CONTRIBUTING, CODEOWNERS, CHANGELOG, pinned actions, `permissions:`, govulncheck, Scorecard, Dependabot, move `litter` out.
6. **Security docs:** threat model, key lifecycle mapped to OWASP, memory-protection statement (wire format spec done).
7. **Token vault redesign (privacy-engine.elastic, with the core contract changes it needs):** PE-25 to PE-30, following section 7.3.
8. **Later:** atomic batches (PE-12), audit hooks, paginated `ListTokens`, bounded caches, optional `runtime/secret` and memguard builds.

The same review should then run on struct-sensitive (PE-05 and PE-06 partly live in its contract), crypto-convoy and struct-avro.

## 7. Tokenization and the token vault

### 7.1 The pattern, from authoritative sources

- **GDPR Art. 4(5)** defines pseudonymisation as processing personal data so it can no longer be attributed to a specific person *without additional information*, provided that information is **kept separately** and subject to **technical and organisational measures**. Art. 25 (data protection by design) and Art. 32(1)(a) name pseudonymisation and encryption as measures.
- **EDPB Guidelines 01/2025 on pseudonymisation** (adopted 16 Jan 2025 for consultation) read the definition as three parts: the pseudonymised data, the *additional information* (typically a table mapping pseudonyms to identifiers, or cryptographic keys), and its separation under technical and organisational measures. They introduce the **pseudonymisation domain**: the people and systems that handle only pseudonymised data and have no access to the additional information. They also confirm that **pseudonymised data is still personal data**, even when someone else holds the additional information.
- **ENISA, "Pseudonymisation techniques and best practices" (2019)** describes techniques (counter, random number generator with a mapping table, hash, keyed hash, encryption) and pseudonymisation **policies**: *deterministic* (same identifier, same pseudonym), *document-randomised* and *fully randomised*. Deterministic pseudonyms keep records linkable; hash-based pseudonyms of small-domain identifiers such as emails can be reversed by brute force. ENISA recommends choosing by risk, purpose and utility.
- **PCI DSS** (the most mature tokenization regime) treats the token vault as the crown jewel. PCI DSS v4.0.1 Req. 3.5.1.2 allows disk- or partition-level encryption to protect stored PAN only on removable media; on other media the PAN must also be made unreadable by a mechanism such as field-level encryption, because disk encryption does nothing once the system is running. This is the clearest industry rule on "at rest is not enough".

In these terms, privacy-engine's tokenizer is an **RNG-plus-mapping-table pseudonymisation with a deterministic policy per namespace**. The token vault is the GDPR "additional information" and must be kept separately, under its own measures.

### 7.2 Does the tokenizer follow privacy by design?

| Principle (source) | Status | Notes |
|---|---|---|
| Pseudonym not derivable from the value (ENISA) | **Yes** | `DefaultTokenGen` is UUIDv4 from a CSPRNG and ignores the value. Strongest choice against brute-force reversal |
| Additional information kept separately (Art. 4(5), EDPB) | **No** | Vault shares a table and an IAM policy with the DEKs (PE-26), and the same application role can tokenize, detokenize, list and read keys |
| Technical measures on the additional information (Art. 4(5), Art. 32) | **Partial** | Only DynamoDB encryption at rest with an AWS-owned key; values are plaintext to anyone who can query the table (PE-25) |
| Pseudonymisation domain (EDPB) | **Not modelled** | No split between "tokenize-only" callers and "detokenize" callers; no audit of re-identification |
| Policy chosen deliberately (ENISA) | **Undocumented** | Deterministic per namespace is right for a surrogate subject ID (joins work), but it is linkable within the namespace. Document it; offer a per-purpose scope (namespace + purpose) for other uses |
| Data minimisation (Art. 5(1)(c), Art. 25) | **No** | Vault also stores a normalised plaintext copy for substring search (`_search`) and the plaintext as an index key (`_lsik`) |
| Integrity of the mapping | **No** | Collisions return a token mapped to someone else (PE-27, PE-17); races create duplicate tokens (PE-28) |
| Erasure | **Partial** | `DeleteToken` deletes the item, but the plaintext stays in backups and point-in-time recovery (PE-29) |
| Pseudonymised data is personal data (EDPB) | **Doc gap** | README calls tokens "opaque"; it should say tokens remain personal data and the vault is in GDPR scope |

Short answer: the token *generation* follows the pattern well; the *vault* does not yet, because the additional information is neither separated nor protected beyond encryption at rest.

### 7.3 App-side encryption or encryption at rest?

**Both, and app-side encryption is the one that counts.**

DynamoDB encryption at rest (`SSEEnabled: true` in `stack/basic/template.yaml`) protects against someone reading AWS's storage media. Every authorised read decrypts transparently, so it does not protect against the realistic threats: a compromised app role or credentials, an over-broad IAM policy, an admin with console access, a leaked table export, a PITR restore into another account, or DynamoDB Streams consumers. With the AWS-owned key there is also no CloudTrail record of key use and no way to revoke it. That is exactly the gap PCI DSS 3.5.1.2 closes by requiring field-level protection on top of disk encryption, and the EDPB's "technical measures" on the additional information point the same way.

App-side (field-level) encryption of the vault keeps the value unreadable to everything outside the process that holds the key, including backups, exports, streams, and operators. It also lets the vault take part in crypto-shredding.

**Recommended vault design** (needs a vault format change, so it belongs to format v2):

1. **Encrypt the value app-side** with AES-256-GCM, AAD = `namespace || token` so a ciphertext can't be moved to another token.
2. **Key choice:** encrypt under the **subject's DEK**, with subject = the token. The README's own pattern uses the token as the subject ID, so `Forget(token)` then shreds the encrypted fields *and* the vault entry, including copies in backups and PITR (fixes PE-29). Tokens not used as subjects can fall back to a per-namespace vault key.
3. **Replace plaintext lookups with a blind index:** store `HMAC-SHA256(index key, normalise(value))` as the index attribute instead of `token#<value>`. The index key is per namespace, held via KMS, and separate from DEKs. `Tokenize` stays idempotent without the vault ever storing plaintext.
4. **Drop `_search` by default.** Substring search over raw PII contradicts minimisation; if a product really needs it, make it an explicit opt-in with its own documented risk.
5. **Separate the vault:** its own table (ideally its own account), a customer-managed KMS key for SSE (audit trail plus revocation), and **separate IAM roles** for tokenize, detokenize and list. That is the "pseudonymisation domain" made concrete: most services can tokenize and only a few can re-identify.
6. **Audit detokenization:** emit an event (who, namespace, how many tokens, why) for every `Detokenize` and `ListTokens`, without values.
7. **Fix mapping integrity:** conditional writes on *both* the token and the value index, with retry on collision (PE-27, PE-28).

Keep DynamoDB encryption at rest on as defence in depth, preferably with a customer-managed KMS key.

### 7.4 New findings from the vault review (privacy-engine.elastic)

- **PE-25 Vault stores PII in plaintext three times.** `dynamodb/token_engine.go` `createTokens` writes the value to `_tknv`, to the LSI key `_lsik` (`token#<value>`) and, normalised, to `_search`. Only DynamoDB encryption at rest (AWS-owned key) protects it.
- **PE-26 No separation.** Keys, tokens and namespaces share `EngineTable`, and one `ReadWritePolicy` grants Put/Get/Query/Delete on all of it. Whoever can read the vault can read the key table too.
- **PE-27 Collision returns a wrong token.** On a token collision, `createTokens` treats `ConditionalCheckFailed` as "already exists" and `continue`s, but `Tokenize` still returns the new token to the caller. That token resolves to *another person's* value. Rare with UUIDv4, likely with short or custom tokens. Must retry with a new token.
- **PE-28 Duplicate tokens under concurrency.** The write condition is on the token key only, so two concurrent `Tokenize` calls for the same new value both succeed with different tokens. The value then has two subject IDs, so `Forget` on one leaves the other's data readable. Use a transaction with a condition on the value index.
- **PE-29 Erasure gap.** `DeleteToken` / `PurgeNamespace` remove items, but the plaintext persists in PITR and on-demand backups for their retention period. App-side encryption under the subject's DEK (7.3, step 2) makes those copies unreadable.
- **PE-30 `TokenGenFunc` receives the value.** The signature invites `hash(value)` tokens, which ENISA warns can be reversed by brute force for emails and similar. Document that token generators must not derive tokens from the value, or drop the parameter.

---

## 8. Hotfix PR (step 1): scope and plan

PE-01 and PE-08 are fixed. The remaining rows are not started.

**Goal:** fix the confirmed bugs that need no wire-format or API break, each with a regression test, so the library is safe to keep using while format v2 is designed.

**Branch:** `fix/audit-hotfixes` from `main`, after the current uncommitted Purge work is committed on its own.

### Changes

| Finding | Change | Regression test |
|---|---|---|
| PE-22 | First commit: `GOWORK=off go mod tidy`; CI already runs without `go.work` | `GOWORK=off go test ./...` passes |
| PE-01 | Key engines return copies (`bytes.Clone`) from `GetKeys`/`GetOrCreateKeys`; cache and store never share slices; zero only owned memory | Hold a key, `ClearCache(force)`, assert key unchanged; assert origin key unchanged after wrapper eviction; race test of `Monitor` vs `Encrypt` under `-race` |
| PE-08 | AES-256 encryptor rejects keys that are not 32 bytes or are all zero, in `Encrypt`, `Decrypt` and both stream methods | 16-, 24-, 31-byte and zero keys return `ErrEncryptionFailure`/`ErrDecryptionFailure` |
| PE-03 | `Decrypt` checks `len(cipherTxt) >= nonce + tag` before slicing | `ENC..dTE=.AQID` returns an error, no panic; first fuzz target `FuzzDecrypt` |
| PE-04 | Cache wrapper `DisableKey`/`ReEnableKey`: once the origin call succeeds, update or drop the cache entry and return `nil`; never return `ErrKeyNotFound` for a cache miss | Forget and Recover after `Clear(force)` return `nil` and the origin state matches |
| PE-07 | Factory clear func captures the entry's protector at creation and runs under the lock; no map read | Clear func after forced eviction does not panic; `-race` clean |
| PE-09 | Add `GoString`, `LogValue` (slog) and `MarshalJSON`/`MarshalText` to `core.Key` and `core.TokenData`, all redacted | Table test over `%v %s %#v %+v %q`, `json.Marshal`, slog JSON and text handlers, nested in `TokenRecord` |
| PE-10 | `Decrypt` returns an error when a subject's key is *unknown* to the engine, and only applies `replace` when the engine reports it disabled or deleted | Wrong-namespace decrypt returns an error and leaves fields untouched; forgotten subject still gets `replace` |
| PE-15 | In-memory `TokenEngine.ClearCache` is a no-op when it is the store (`origin == nil`), matching the key engine | Non-forced `Clear` after TTL keeps tokens in the store |
| PE-16 | In-memory `Tokenize` applies `Prefix` like the DynamoDB engine | Token starts with `sub_` |
| PE-19 | Stream goroutines stop when the consumer stops: return a reader that also implements `io.Closer` (the `*io.PipeReader` already does; document `Close`) and close the pipe on context cancellation | 50 abandoned-then-closed streams leave no goroutines (`runtime.NumGoroutine` before/after) |

### Notes on compatibility
- PE-10 is a behaviour change: callers that relied on "unknown key means empty field" will now get an error. That is the intended safer default; it goes in the CHANGELOG under "Changed".
- PE-08 rejects non-256-bit keys. Any custom `KeyGen` producing other sizes was already contradicting the docs.
- PE-04 needs the same semantics in `privacytest` suites, so third-party backends get tested for it.
- No change to the wire format, the stream format, or exported interfaces. `io.Reader` return types stay; `Close` is documented on the concrete value.

### Out of scope for this PR
Format v2 items (PE-02, 05, 06, 11, 23), vault redesign (PE-25 to PE-30, in privacy-engine.elastic), API cleanup (section 2), and docs/hygiene (steps 4-6).

### Done when
- Every row above has a passing regression test, and `GOWORK=off go test -race ./...` passes.
- Coverage of `aes` is above 0% with the new tests (the full 90% bar is step 3).
- gosec, staticcheck and govulncheck are still clean.
- This file's summary table marks each fixed ID as "Fixed in #PR".

---

## 9. Limits of this review and next round

### What this review covered
- Every Go file in this module, read in full.
- Tooling: `go vet`, `go test -race`, coverage, govulncheck, gosec, staticcheck.
- Proof-of-concept tests for every finding marked "Confirmed" (run in a scratch copy, `GOWORK=off`; they will become the regression tests in section 8).
- Fuzzing of the decryption and wire-format parsers (9.1).
- privacy-engine.elastic: the DynamoDB token engine, the table template and how engines are wired into `NewProtector`. Not the rest of that repo.

### What it did not cover
- **struct-sensitive** was reviewed after this file was written. The hardening is on that repo's `main` (`e76df16`, `e490169`) and is not in the `v0.7.0` this module requires. What this repo still has to change is in [section 10](#10-struct-sensitive-contract-to-adopt).
- **The key hierarchy in privacy-engine.elastic**: how the KMS and DynamoDB key engines wrap, store, disable and delete DEKs. This is half of the OWASP key-management picture (section 4) and was only inferred from the README.
- **Primary-source checks**: two citations still rest on secondary sources (see 9.2) and must be checked by hand against the original PDFs before this file goes to an auditor.
- **Inferred, not measured**: the timing of a future `runtime/secret` graduation, and production impact estimates (e.g. how often a Monitor tick overlaps an `Encrypt`).

### 9.1 Fuzzing results (round 3, 2026-10-22)

Native Go fuzzing (`testing.F`), run in a scratch copy with `GOWORK=off`; no fuzz files were added to the repo yet (they belong in the hotfix PR, section 8).

| Target | Budget | Result |
|---|---|---|
| `aes.Decrypt` | until first failure | Crashed on its seed input (3 bytes): PE-03 reproduced |
| `aes.Decrypt`, with PE-03 patched in the scratch copy | 90 s, 7.5 M execs | No further crash |
| `aes.DecryptStream` | 90 s, 6.6 M execs | No crash; no forged stream accepted with a *different non-empty* plaintext. Truncation (PE-02) is not caught by this oracle by design |
| `parseWireFormat` | 60 s, 1.0 M execs | No crash |
| `Protector.Decrypt` (struct with a fuzzed field) | until first failure | Crashed on `ENC..dTE=.AQID`: PE-03 through the public API |
| `Protector.Decrypt`, with PE-03 patched | 90 s, 2.0 M execs | No further crash |

Conclusion: PE-03 is the only crash the parsers showed in this budget. Keep these four targets in CI (short budget per PR, longer nightly) once the hotfix lands.

### 9.2 Citation verification status

| Citation | Status |
|---|---|
| GDPR Art. 4(5), 25, 32 | Primary (EUR-Lex) |
| EDPB Guidelines 01/2025 | Primary PDF located; summary consistent with EDPB's own consultation page. Still the consultation version (adopted 16 Jan 2025); check whether a final version has been published |
| ENISA 2019 report | Policy *names* (deterministic, document-randomised, fully randomised) confirmed from the report's table of contents; their *definitions* and the hash brute-force remark come from secondary sources. The PDF could not be text-extracted on this machine. **Check by hand** |
| PCI DSS v4.0.1 Req. 3.5.1.2 | Consistent across several assessor and vendor sources; the PCI SSC site refuses automated download. **Check by hand** against the standard PDF |
| PCI Tokenization Guidelines (2011) | Downloaded but not text-extractable here; not relied on for any claim in this file |
| OWASP Key Management Cheat Sheet | Primary |
| Go `runtime/secret` status | Primary (pkg.go.dev, Go 1.27 release notes, golang/go#21865) |

### 9.3 Next round, before the external audit
1. **struct-sensitive**: the review landed (SS-01 through SS-13). Adopting it here is [section 10](#10-struct-sensitive-contract-to-adopt), not a new review.
2. **privacy-engine.elastic**: separate review of the KMS/DynamoDB key engines, IAM and lifecycle, completing the OWASP table; vault findings PE-25 to PE-30 move there (prefix `PX-`). Requested.
3. Hand-check the two citations marked above.
4. After the hotfix and format v2 land, re-review the diff only and update every ID's status.
5. Later, the same method for crypto-convoy and struct-avro.

## 10. struct-sensitive contract to adopt

**Adopted** on `fix/audit-hardening`: the module now requires struct-sensitive `v0.8.0` (tag of `bdea8a7`) and `GOWORK=off go test -race ./...` passes. The notes below are kept as the record of what changed.

This module required `github.com/ln80/struct-sensitive v0.7.0`. The hardening is on that repo's `main` (`e76df16`, `e490169`) and is not in that tag. Bumping the requirement changes encrypt and decrypt. Do it as part of this hardening work, not as a silent `go.mod` edit. The findings are SS-01 through SS-13 in struct-sensitive `docs/audit-readiness.md`. The items below are what this module still has to change.

### Blocks the bump

`replace` is no longer a legal tag option. struct-sensitive accepts `kind` on `data` and `prefix` on `subjectID` only. `Profile.Fullname` is tagged `pii:"data,replace=deleted pii"` (`main_test.go`). `Decrypt` reads `fr.Options["replace"]` when the subject's key is gone (`protector.go`, the second replace callback). After the bump, `Scan` returns `ErrInvalidTagConfiguration` before encrypt or decrypt runs. `MustFieldTag(...).Options.Get("replace")` in `protector_test.go` panics once parsing fails. Resolve this before bumping: allow `replace` on `data` again in struct-sensitive, or stop putting the forgotten-subject placeholder in the tag.

A missing subject is no longer reported as a bad tag. `Scan(..., true)` on a struct that has `data` and no subject returns `ErrSubjectIDNotFound` and does not wrap `ErrInvalidTagConfiguration`. The `StructSubjectNotFound` case in `protector_test.go` still expects `ErrInvalidTagConfiguration`. Two `subjectID` fields on one struct stay a tag error, under the renamed sentinel `ErrMultipleSubjectID`. The old name `ErrMultipleNestedSubjectID` is gone. That case is still joined with `ErrInvalidTagConfiguration`, so `StructMultipleSubjects` can keep its assertion.

### Encrypt and Decrypt

`Encrypt` prefetches keys from `piiStruct.SubjectID()` only (`protector.go`). `FieldReplace.SubjectID` is now the subject of the struct that owns the field. The parent subject is used only when the element has none. A nested element with its own subject is not in `keys`, so the callback returns `ErrSubjectForgotten`. `Replace` writes nothing unless every callback succeeds, so the record is left unchanged rather than half-encrypted, and it is not encrypted either. Before `Replace`, collect every `fr.SubjectID` (a `Plan` with a callback that records subjects, or a first pass) and prefetch those keys. `SubjectID()` is the value `Scan` observed. Changing the struct afterwards does not change it. `Decrypt` already takes the subject from the wire value, not from `SubjectID()`.

`FieldReplace.Path` is available for PE-11. `Name` is still the bare field name. `Path` looks like `Email`, `Members[0].Email`, or `Labels[0].Street`. A map element uses a stable index after sorting keys. The map key is not part of the path, because the key can be personal data. Format v2 decided not to bind the path (PE-11 accepted risk).

One struct is all-or-nothing. The `Encrypt` and `Decrypt` loops still commit struct 0 before struct 1 fails, so PE-12 is still open for a batch.

`isWireFormatted` in the encrypt callback is still this module's check (PE-05). struct-sensitive will not say whether a value is already encrypted. Authenticate the value under that field's subject key instead of trusting the shape.

An empty subject with `prefix=usr_` is still the string `usr_`, not `ErrSubjectIDNotFound`. Do not use a prefix as a stand-in for a missing ID. Integer subject fields are rejected. `[]byte` and one `*string` are accepted. A tagged field that cannot be handled, including an unexported field, is an error. An embedded struct with no tag is walked, so fields that were previously skipped will be encrypted after the bump.

`FieldReplace.Options` is a copy. Writing it does not change the next value. Reading `replace` still works once that option parses.

A pointer cycle returns `ErrCycle`. A chain deeper than 10,000 structs returns `ErrMaxDepth`. Neither is wrapped as a bad tag.

This module does not call `Mask`. If a later change does, default redaction is the fixed placeholder `***`. `mask.Register` returns an error and will not replace `email`, `ipv4_addr`, `credit_card`, or `fullname`. `mask.Override` does. Those masks still keep identifying structure (domain, initials, BIN and last 4, one IPv4 octet).

Plaintext and ciphertext inside `Replace` are Go strings and cannot be wiped. `[]byte` fields are zeroed when a replacement is committed.

## References

- [GDPR (Regulation (EU) 2016/679), Art. 4(5), 25, 32](https://eur-lex.europa.eu/eli/reg/2016/679/oj)
- [EDPB Guidelines 01/2025 on Pseudonymisation](https://www.edpb.europa.eu/system/files/2025-01/edpb_guidelines_202501_pseudonymisation_en.pdf)
- [ENISA, Pseudonymisation techniques and best practices (2019)](https://www.enisa.europa.eu/publications/pseudonymisation-techniques-and-best-practices)
- [PCI SSC document library (PCI DSS v4.0.1, Req. 3.5.1.2; Tokenization Guidelines)](https://www.pcisecuritystandards.org/document_library/)
- [OWASP Key Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Key_Management_Cheat_Sheet.html)
- [runtime/secret package docs](https://pkg.go.dev/runtime/secret)
- [golang/go#21865: runtime/secret proposal](https://github.com/golang/go/issues/21865)
- [Go 1.27 release notes](https://go.dev/doc/go1.27)
- [Go feature: Secret mode (Anton Zhiyanov)](https://antonz.org/accepted/runtime-secret/)
