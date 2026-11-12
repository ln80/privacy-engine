# Wire format v2: field values and streams

| | |
|---|---|
| Status | **Specification.** Implemented on `fix/audit-hardening` (commits in section 9) |
| Code | `wire_format.go` (field encoding), `aes/256_gcm.go` and `aes/util.go` (field crypto), `aes/stream.go` (streams), `protector.go` (behaviour) |
| Findings | Fixes PE-02, PE-03, PE-05, PE-10, PE-23. PE-06 is handled by a rule (section 6). PE-11 is an accepted risk (section 7) |
| Compatibility | None. v1 field values, the legacy `<pii:` form and stream v1 are not parsed |

## 1. Key hierarchy

Each layer knows only about the layer just below it:

```
┌─ KEK ───────────── KMS CMK (privacy-engine.elastic, KMS wrapper)
│    wraps the DEK, under an encryption context from a pluggable function
├─ DEK ───────────── one per (namespace, subject, key version), stored wrapped in the key store
│    Forget disables it (graceful mode) or deletes it; PurgeNamespace removes all of a namespace's DEKs
├─ uses of the DEK
│    ├─ field values   AES-256-GCM directly under the DEK                       (section 2-3)
│    ├─ streams        HKDF-SHA256(DEK, salt, "privacy-engine/stream/v2" | ns)   (section 5)
│    └─ derived keys   DeriveSubjectKey(purpose): HKDF-SHA256, salt "privacy-engine-v1"
└─ data ──────────── field values, streams
```

- **A value says which DEK to use, never how the DEK is protected.** The KMS key and the encryption context live on the key item. A CMK migration, a new encryption-context function or a different KEK provider rewrites key items only, never data.
- **Crypto-shredding covers every use.** Field values, stream keys and derived keys all depend on the DEK. The one exception is a derived key that a caller stores itself (PE-14). Storing it is the caller's responsibility.

## 2. Field value encoding

```
value   = "ENC." base64url(subjectID) "." base64url(payload)        base64url without padding
payload = alg (1) | keyVersion (4, big-endian) | ciphertext
```

For `alg = 0x01`, `ciphertext = nonce (12) | encrypted plaintext | tag (16)`.

| Field | Rule |
|---|---|
| `alg` | `0x01` = AES-256-GCM directly under the DEK (section 3). The only value defined; it also serves as the format version. `0xFF` is reserved for test doubles |
| `keyVersion` | `1` for a subject's DEK. `0` is reserved for caller-managed keys (streams only). No other version exists until rotation is built |
| subject ID | 1 to 1024 bytes once decoded. Must be pseudonymous (section 6) |
| payload | Header plus a non-empty ciphertext. The encryptor enforces its own minimum: nonce + tag = 28 bytes for `0x01`, so a value's payload is at least 33 bytes |

A string is a field value only if all of these hold. Otherwise it is "not a field value":

1. It starts with `ENC.` (case-sensitive).
2. The rest splits on its first `.` into two non-empty parts, each using only `A-Z a-z 0-9 - _`. This also rules out a third part, padding, whitespace and newlines.
3. Both parts decode as strict base64url without padding, so non-canonical trailing bits are rejected.
4. The lengths above hold.

Every accepted value re-encodes to exactly the same string, so a value has a single text form. Equality checks and idempotency rely on that, and it is fuzzed (`FuzzParseWireValue`). The alphabet check is not redundant: Go's base64 decoder skips `\r` and `\n` even in strict mode.

Example: subject `sub_445d4aa3-5e05-4071-a070-09a13911d3a1`, plaintext `Samanta Murray`:

```
ENC.c3ViXzQ0NWQ0YWEzLTVlMDUtNDA3MS1hMDcwLTA5YTEzOTExZDNhMQ.AQAAAAFmmmUlER1itz4sjKMfNvpwwaD3NA6iSXmqQnEzxqnvNT4TIw_N9Et0Ozs
    └─ base64url(subject) ─────────────────────────────────┘ └ AQAAAAF… = 01 | 00000001 | nonce | ct | tag
```

## 3. Field cryptography (`alg = 0x01`)

```
ciphertext = nonce | AES-256-GCM-Seal(key = DEK, nonce, plaintext, aad)
aad        = "privacy-engine/field/v2" | alg (1) | keyVersion (4, BE) | len16(namespace) | namespace
```

- **The key** is the subject's 32-byte DEK. Non-256-bit and all-zero keys are rejected (PE-08).
- **The nonce** is 96 random bits per value. The usual bound for random GCM nonces is about 2³² encryptions per key. A DEK belongs to one subject in one namespace, so the bound applies per subject. Key versions are the remedy if a subject ever gets close.
- **The AAD** is canonical and length-prefixed, so no two different bindings encode to the same bytes. It comes from `core.Binding{Namespace, KeyVersion}` plus the encryptor's algorithm ID. Each part has a job:
  - The namespace rejects a value moved to another tenant, even if a key store bug hands back a key.
  - `alg` and `keyVersion` cannot be edited without failing authentication.
  - The subject is not bound: each subject has its own key, so a value moved to another subject already fails.
- **Plaintext** goes in and comes out as `[]byte`. The protector wipes its copy after converting it to the field's string.

## 4. Behaviour

The subject named **in the value** selects the key. If the struct declares a different subject (a copied value, or a struct with several subjects), the value's subject wins. Each struct is all-or-nothing: on error, none of its fields change.

### Encrypt, per field

| Field holds | Key state of the value's subject | Result |
|---|---|---|
| Empty string | – | Left empty |
| Not a field value | the field's subject is active | Encrypted under the field's subject, `keyVersion` 1 |
| Not a field value | the field's subject is forgotten | `ErrSubjectForgotten` |
| Field value with an unknown `alg` or `keyVersion` | – | `ErrValueNotAuthentic` (wrapping `ErrInvalidWireFormat`) |
| Field value | active, authenticates | Kept as is (idempotency, PE-05) |
| Field value | active, does not authenticate | `ErrValueNotAuthentic` (fail closed) |
| Field value | disabled or deleted | Kept as is: the value is shredded, and saving its record again must keep working |
| Field value | unknown | `ErrKeyUnknown` |

The struct's subjects get their keys through `GetOrCreateKeys`. Subjects that only values name are read with `GetKeys` and never created.

### Decrypt, per field

| Field holds | Key state of the value's subject | Result |
|---|---|---|
| Not a field value | – | Left as is (never encrypted) |
| Field value with an unknown `alg` or `keyVersion` | – | `ErrInvalidWireFormat`, checked before the key lookup |
| Field value | active, authenticates | Plaintext |
| Field value | active, does not authenticate | `core.ErrDecryptionFailure` (tampered, wrong namespace, or wrong key) |
| Field value | disabled or deleted (forgotten) | The tag's `replace=` value, otherwise `ProtectorConfig.ForgottenValue` (default `""`) |
| Field value | unknown (never created, purged, wrong namespace, misconfigured backend) | `ErrKeyUnknown`, field untouched (PE-10) |

`DecryptStream` and `DeriveSubjectKey` return `ErrSubjectForgotten` or `ErrKeyUnknown` on the same distinction. `EncryptStream` creates missing keys, so it can only report a forgotten subject.

### Key states

The key engine reports them (`core.KeyEngine.GetKeys`, conformance-tested in `privacytest`):

| State | Meaning |
|---|---|
| `ACTIVE` | The key is returned |
| `DISABLED` | `Forget` in graceful mode; `Recover` can re-enable it |
| `DELETED` | Deleted directly, or after the grace period |
| `UNKNOWN` | No record in the namespace: never created, or removed by `PurgeNamespace`. Never stored |

### Errors

Messages name the field path (`Address.Street`, `Members[0].Email`) and never a value or subject ID. The subject and namespace are available through `privacy.Error.Subject()` and `Namespace()`, which search the whole wrapped chain.

## 5. Stream format v2

Streams use the STREAM construction (Hoang, Reyhanitabar, Rogaway, Vizár 2015), as Tink and age do:

```
header    = version (1) = 2 | alg (1) = 1 | keyVersion (4, BE) | segmentSize (4, BE) | salt (32) | noncePrefix (7)
streamKey = HKDF-SHA256(ikm = DEK, salt, info = "privacy-engine/stream/v2" | len16(namespace) | namespace)
segment i = AES-256-GCM(streamKey, nonce = noncePrefix | i (4, BE) | final (1), aad = header)
```

- **Segments.** Every segment holds `segmentSize` bytes of plaintext (default 64 KiB) except the last, which holds 0 to `segmentSize` bytes and is the only one sealed with `final = 1`. Empty input still produces one final segment.
- **Framing.** Ciphertext segments are `segmentSize + 16` bytes except the last, so there is no length framing. The decrypter recognises the last segment by reaching EOF.
- **What fails authentication:** truncation at any point, dropped, reordered, duplicated or appended segments, any header edit, and a wrong key or namespace.
- **Key version.** `keyVersion` is the binding's: 1 for a subject's DEK, 0 for the `*WithKey` methods. A stream opened with another version fails before any segment is read.
- **Limits.** The decrypter accepts a `segmentSize` from 16 B to 4 MiB and at most 2³² segments.
- **Plaintext timing.** Each segment's plaintext is released once that segment authenticates. A damaged stream therefore yields its intact leading segments and then an error. **Treat output as valid only once `Read` returns `io.EOF`.**
- **No goroutines.** The readers are pull-based, so an abandoned stream leaks nothing.

## 6. Subject IDs

**Rule (PE-06):** subject IDs must be pseudonymous identifiers, such as random IDs or tokens from the tokenizer. Never use an email, a name, or any other direct identifier as a subject ID.

Every field value names its subject in clear. The record already stores the same subject in clear in its `subjectID` field, so following the rule means the value exposes nothing new.

The subject stays in the value because a value then describes itself:

1. **It decrypts into any type.** A DTO, a read model or a generated event type does not need a subject field, and a refactor that moves or renames one breaks nothing.
2. **A copied value keeps following its owner.** Subject A's value copied into subject B's record still decrypts with A's key, and `Forget(A)` shreds the copy.
3. **Mixed-subject structs work.**
4. **One key fetch per call.** Subjects are read from the values first.
5. **Rotation, re-key and audit jobs can find each value's DEK without loading domain types.**

Revision 1 of this design took the subject from the struct instead. It would have lost points 1, 2 and 5 while hiding nothing the record does not already show.

## 7. Accepted risks and limits

| Item | Why it is accepted |
|---|---|
| **Field swap within one subject (PE-11).** Two values of the same subject and namespace (email ↔ phone of the same person) can be swapped undetected | Requires write access to the data store and only rearranges one person's own data. Binding Go field paths would make old data unreadable after a refactor, which is a real risk for event-sourced callers. If needed later, a stable `bind=<name>` tag option can arrive as a new `alg` with no format change |
| **Subject visible in values** | See section 6. The rule must be followed by callers |
| **Random-nonce bound** | About 2³² values per subject key (section 3) |
| **Key rotation not built** | `keyVersion` is reserved and authenticated. Rotation needs the key store to keep several versions per subject, so it is designed after privacy-engine.elastic is fixed |
| **Stream plaintext released per segment** | Inherent to streaming. Callers commit output only at `io.EOF` (section 5) |
| **Plaintext as Go strings** | struct-sensitive passes field values as `string`, which cannot be wiped. Only the protector's `[]byte` copies are cleared |

## 8. Design history and decisions

- **Revision 1** removed the subject from values, derived a field subkey, and bound the subject and field path in the AAD.
- **Revision 2** kept the subject (section 6), dropped the field subkey (streams and `DeriveSubjectKey` already have their own HKDF domains), and bound only the namespace and header.
- **Revision 3** kept the `ENC.` prefix and parses only v2. There is no text version field: `alg` serves as the format version.

| ID | Decision |
|---|---|
| D1 | The encryption context for wrapped DEKs is a pluggable function (privacy-engine.elastic) |
| D2 | One CMK at this stage. The resolver keeps per-tenant CMKs possible later |
| D3 | `Forget` is graceful by default; immediate deletion when forced |
| D-C | A value that looks encrypted but does not authenticate under an active key fails `Encrypt` |
| D-D | Prefix `ENC.`; only v2 is parsed |
| – | A purged namespace's data decrypts to `ErrKeyUnknown`, not a placeholder |

## 9. Implementation

| Commit | Change | Findings |
|---|---|---|
| `7924951` | Stream format v2 | PE-02, PE-19 |
| `74dac69` | Reject a too-short ciphertext | PE-03 |
| `182d867` | `GetKeys` reports missing-key states | PE-10 (contract) |
| `f1ff4f7` | `core.Binding`, algorithm ID, `[]byte` plaintext, key version in the stream header | PE-23 |
| `2ebc08d` | Field encoding v2, strict parser, v1 removed | PE-23 |
| `50797ec` | Idempotency by authentication; Decrypt state table; `ForgottenValue` | PE-05, PE-10 |
