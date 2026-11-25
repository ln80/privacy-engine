# Wire format: field values and streams

| | |
|---|---|
| Status | **Normative.** Field and stream formats unchanged since v0.7.0 |
| Code | `wire_format.go`, `aes/256_gcm.go`, `aes/util.go`, `aes/stream.go`, `protector.go` |

## 1. Key hierarchy

```
KEK ── held by the key engine's backend (KMS, HSM); the library never sees it
 └─ DEK ── one per (namespace, subject, key version), stored wrapped
     ├─ field values   AES-256-GCM under the DEK                               §2–3
     ├─ streams        HKDF-SHA256(DEK, salt, "privacy-engine/stream/v2" | ns)  §5
     └─ derived keys   DeriveSubjectKey(purpose): HKDF-SHA256, salt "privacy-engine-v1"
```

A value names its DEK, never how the DEK is wrapped: changing the KEK
rewrites key records, never data. Deleting the DEK shreds every use of it,
except a derived key the caller stored.

## 2. Field value encoding

```
value   = "ENC." base64url(subjectID) "." base64url(payload)      no padding
payload = alg (1) | keyVersion (4, BE) | ciphertext
```

For `alg = 0x01`: `ciphertext = nonce (12) | encrypted plaintext | tag (16)`.

| Field | Rule |
|---|---|
| `alg` | `0x01` = AES-256-GCM under the DEK, the only one defined; it is also the format version. `0xFF` is reserved for test doubles |
| `keyVersion` | `1` for a subject's DEK; `0` for caller-managed keys (streams only) |
| subject ID | 1 to 1024 bytes decoded; pseudonymous (§6) |
| payload | At least 33 bytes for `0x01` (header + nonce + tag + 1) |

A string is a field value only if it starts with `ENC.`, splits on its first
`.` into two non-empty parts of `A-Z a-z 0-9 - _`, both decode as strict
unpadded base64url, and the lengths hold. Anything else is not a field value.
Every accepted value re-encodes to the same string (fuzzed by
`FuzzParseWireValue`).

Example, subject `sub_445d4aa3-5e05-4071-a070-09a13911d3a1`:

```
ENC.c3ViXzQ0NWQ0YWEzLTVlMDUtNDA3MS1hMDcwLTA5YTEzOTExZDNhMQ.AQAAAAFmmmUlER1itz4sjKMfNvpwwaD3NA6iSXmqQnEzxqnvNT4TIw_N9Et0Ozs
                                                           └ 01 | 00000001 | nonce | ct | tag
```

## 3. Field cryptography (`alg = 0x01`)

```
ciphertext = nonce | AES-256-GCM-Seal(DEK, nonce, plaintext, aad)
aad        = "privacy-engine/field/v2" | alg (1) | keyVersion (4, BE) | len16(namespace) | namespace
```

- **Key**: the subject's 32-byte DEK. Other sizes and all-zero keys are refused.
- **Nonce**: 96 random bits per value; safe for about 2³² values per DEK, that is per subject.
- **AAD**: canonical and length-prefixed. The namespace rejects values moved
  across tenants; `alg` and `keyVersion` cannot be edited. The subject is not
  bound: another subject's key already fails.

## 4. Behaviour

The subject named **in the value** selects the key, even if the struct names
another. Each struct is all-or-nothing: on error, no field changes.

### Encrypt, per field

| Field holds | Subject key | Result |
|---|---|---|
| `""` | – | Left empty |
| Plaintext | active | Encrypted, `keyVersion` 1 |
| Plaintext | forgotten | `ErrSubjectForgotten` |
| Value with unknown `alg` or `keyVersion` | – | `ErrValueNotAuthentic` |
| Value | active, authenticates | Kept (idempotent) |
| Value | active, does not authenticate | `ErrValueNotAuthentic` (fail closed) |
| Value | disabled or deleted | Kept: it is shredded, and saving the record must still work |
| Value | unknown | `ErrKeyUnknown` |

The struct's subjects get keys through `GetOrCreateKeys`; subjects named only
by values are read with `GetKeys`, never created.

### Decrypt, per field

| Field holds | Subject key | Result |
|---|---|---|
| Not a value | – | Left as is |
| Value with unknown `alg` or `keyVersion` | – | `ErrInvalidWireFormat`, before any key lookup |
| Value | active, authenticates | Plaintext |
| Value | active, does not authenticate | `core.ErrDecryptionFailure` |
| Value | disabled or deleted | The tag's `replace=`, else `ForgottenValue` (default `""`) |
| Value | unknown | `ErrKeyUnknown`, field untouched |

`DecryptStream` and `DeriveSubjectKey` return `ErrSubjectForgotten` or
`ErrKeyUnknown` likewise. Key states are defined in
[key-lifecycle.md](key-lifecycle.md#2-dek-states).

Error messages name the field path (`Members[0].Email`), never a value or
subject; `privacy.Error.Subject()` and `Namespace()` give those.

## 5. Streams

STREAM construction (Hoang et al. 2015), as in Tink and age:

```
header    = version (1) = 2 | alg (1) = 1 | keyVersion (4, BE) | segmentSize (4, BE) | salt (32) | noncePrefix (7)
streamKey = HKDF-SHA256(DEK, salt, info = "privacy-engine/stream/v2" | len16(namespace) | namespace)
segment i = AES-256-GCM(streamKey, nonce = noncePrefix | i (4, BE) | final (1), aad = header)
```

- Segments hold `segmentSize` bytes (default 64 KiB); only the last, possibly
  empty, has `final = 1`. Ciphertext segments are `segmentSize + 16` bytes, so
  there is no length framing.
- Truncation, dropped, reordered, duplicated or appended segments, header
  edits and wrong key or namespace all fail.
- The decrypter accepts `segmentSize` from 16 B to 4 MiB and at most 2³²
  segments.
- Plaintext is released per authenticated segment: **treat output as valid
  only once `Read` returns `io.EOF`.**
- Readers are pull-based; an abandoned stream leaks no goroutine.

## 6. Subject IDs

Subject IDs must be pseudonymous: random IDs or tokens, never an email or a
name. Each value names its subject in clear, as the record's own `subjectID`
field already does. That lets a value decrypt into any type, keep following
its subject when copied, and be re-keyed without loading domain types.

## 7. Accepted risks

| Risk | Why accepted |
|---|---|
| Two values of one subject (email ↔ phone) can be swapped | Needs write access and only rearranges one person's data. Binding field paths would break data on refactors; a `bind=` option can come as a new `alg` |
| Subject visible in values | §6 |
| ~2³² values per DEK | Random-nonce bound (§3) |
| No key rotation | `keyVersion` is reserved and authenticated ([key-lifecycle.md](key-lifecycle.md#5-rotation-not-supported)) |
| Stream plaintext released per segment | Inherent to streaming; commit at `io.EOF` |
| Plaintext as Go strings | Cannot be wiped; the protector clears its `[]byte` copies |

## 8. Versioning and compatibility

| Format | Identifier | Current | Since |
|---|---|---|---|
| Field value | `ENC.` prefix, `alg` byte | `0x01` | v0.7.0 |
| Stream | header `version`, `alg` | `2`, `1` | v0.7.0 |
| Sealed vault value | first byte | `0x01` | v0.8.0 ([token-vault.md](token-vault.md)) |
| Key derivation | versioned HKDF labels | `…/v2`, `…/v1` | v0.7.0 |
| Subject key | `keyVersion` | `1` | v0.7.0 |

1. **An identifier never changes meaning.** A new construction gets a new one.
2. **Reading outlives writing.** A release may write a new identifier; it
   keeps reading the old ones.
3. **From v1.0**, every release reads all data written by its major version.
   Dropping read support takes a major release, announced one minor ahead
   with a migration path.
4. **Before v1.0**, the current identifiers are meant to become v1. A change
   that leaves data unreadable is flagged as breaking, with a migration path.

Formats from before v0.7.0 are not parsed. The Go API versions separately:
see [api-stability.md](api-stability.md).
