# Field wire format v2: proposal

| | |
|---|---|
| Status | Agreed design (revision 3). Implementation in progress on this branch |
| Branch | `fix/audit-hardening` |
| Findings addressed | PE-03, PE-05, PE-10, PE-23 in the format; PE-06 by a documented rule; PE-11 out of scope (section 7) |
| Compatibility | None kept. v1 values and the legacy `<pii:` form are not parsed at all. There is no deployed data to keep |
| Related | Stream format v2 is done (`aes/stream.go`, PE-02). This document covers field values |

**Revision 2 changes.** Revision 1 removed the subject ID from the value and added a field subkey and subject binding in the AAD. After review:
- the subject ID **stays** in the value (section 3 explains why v1 had it);
- **no field subkey**: field values use the DEK directly;
- the AAD binds the **namespace and the header** only.

**Revision 3 changes.** D-C agreed (fail closed). D-D: the prefix stays `ENC.`. With no legacy to support there is no version field in the text: the first payload byte identifies the format and algorithm together, and only v2 is parsed.

## 1. Why change the format

A field value today (`wire_format.go`):

```
ENC.<version>.<base64(subjectID)>.<base64(nonce | ciphertext | tag)>
ENC..dTE=.q2b0…     ← subject "u1", version empty (= 1)
```

| ID | Problem in v1 | Fixed by |
|---|---|---|
| PE-23 | No algorithm or key version: DEKs can never rotate and the `Encryptor` cannot change | Header with algorithm ID and key version |
| PE-03 | A too-short ciphertext panics `Decrypt` | Strict parser with a minimum length |
| PE-05 | Any input matching the regex is stored as "already encrypted", including attacker input naming another subject | Idempotency decided by authentication |
| PE-10 | A value in the wrong namespace, or a misconfigured backend, silently becomes the "forgotten" placeholder | Key engine reports *why* a key is missing; unknown is an error |
| PE-06 | The value names its subject in clear | Kept on purpose; subject IDs must be pseudonymous (section 3) |
| – | Regex parsing, two prefixes, a text version field, standard base64 with padding | One prefix, base64url without padding, length-checked binary payload whose first byte is the format/algorithm ID |

## 2. The mental model

Four layers. Each one knows only about the layer just below it:

```
┌─ KEK ───────────── KMS CMK (privacy-engine.elastic, KMS wrapper)
│    wraps the DEK, with an encryption context from a pluggable function (D1)
├─ DEK ───────────── one per (namespace, subject, key version), stored wrapped
│    in the key store; Forget disables it, the janitor or immediate mode deletes it
├─ uses of the DEK
│    ├─ field values   AES-256-GCM directly under the DEK      ← this document
│    ├─ streams        HKDF(DEK, salt, "privacy-engine/stream/v2") per stream (done)
│    └─ derived keys   DeriveSubjectKey(purpose), HKDF with its own salt (doconvoy attachments)
└─ data ──────────── field values, streams
```

**A field value says which DEK, never how the DEK is protected.** Which KMS key wraps the DEK, and under which encryption context, is recorded once on the key item. A CMK migration (`ReEncrypt` of key items), a new encryption-context function, or a different KEK provider then touches key items only, never data records. So "with or without envelope" is a key store choice, and the field format is the same either way.

**Crypto-shredding covers every use.** Field values, stream keys and derived keys all depend on the DEK, so destroying the DEK destroys them all. The one exception is a derived key a caller saves itself (PE-14), which stays a documented caller responsibility.

## 3. Why the subject ID stays in the value

The subject has been in the wire format since the first commit (2024). At that time `Decrypt` scanned with `Scan(ptr, false)`, so a struct did not need a subject field at all, and struct-sensitive still documents `FieldReplace.SubjectID` as possibly empty. A v1 value **describes itself**: it carries what is needed to find its key. That gives five properties a v2 value must keep:

1. **Decrypting does not depend on the struct's shape.** A value can be decrypted into a DTO, a read model or a generated event type that has no subject field, or after the subject field was renamed or moved.
2. **Copied values keep the right key.** Subject A's ciphertext copied into subject B's record still decrypts with A's key, and `Forget(A)` still shreds the copy: the copy follows its owner's lifecycle.
3. **Mixed-subject structs work.** Each value names its own key, whatever the struct nesting says.
4. **One key fetch.** `Decrypt` reads all subjects from the values, then makes a single `GetKeys` call.
5. **Tools need no domain types.** A rotation, re-key or audit job can scan a table and know which DEK each value needs without loading every Go struct. DEK rotation, which the key version is reserved for, depends on this.

Taking the subject from the struct instead (revision 1) would lose 1, 2 and 5, and would turn any read model or refactor that drops the subject field into a decrypt error.

**What keeping it costs (PE-06).** The value names a subject in clear. But the record already stores the same subject in clear in its `subjectID` field, so in the common case the value adds no new exposure. The real risk is a subject ID that is itself personal data, such as an email. The rule, written in the README and the godoc:

> Subject IDs must be pseudonymous identifiers: random IDs or tokens from the tokenizer. Never use an email, a name, or any other direct identifier as a subject ID.

doconvoy already follows it: subjects are `sub_`/`rcp_` tokens, user, secret, request and workspace IDs.

## 4. Layout

```
value   = "ENC." base64url(subjectID) "." base64url(payload)         (no padding)
payload = alg (1) | keyVersion (4, BE) | nonce (12) | ciphertext | tag (16)
```

- `alg = 0x01`: field format v2, AES-256-GCM under the DEK. It is the only format ID, so it doubles as the format version; no other value is accepted.
- `keyVersion` starts at `1`. Until rotation is designed, the protector writes 1 and rejects anything else with a clear error, not "forgotten".
- Subject ID: 1 to 1024 bytes after decoding.
- Payload: the 5-byte header plus a non-empty ciphertext, checked by the parser. The encryptor then checks its own minimum (nonce + tag = 28 bytes for `0x01`), so an AES-256-GCM value is at least 33 bytes and nothing is sliced before its length is known (PE-03).
- Parsing is a prefix check, one split on `.`, an alphabet check (`A-Z a-z 0-9 - _` only) and strict base64url decoding, with no regex. Exactly three parts; anything else is "not a v2 value". The alphabet check matters: Go's base64 decoder skips `\r` and `\n` even in strict mode, which would give one value two textual forms. Every accepted value re-encodes to the exact same string (fuzzed).
- base64url without padding makes values safe in URLs, JSON, DynamoDB keys and file names.

Example: plaintext `alice@example.org` (17 bytes), subject a 36-character UUID:

```
ENC.<48 chars of subject>.<67 chars of payload>      120 characters (v1: 114)
```

The 6 extra characters are the algorithm and key-version header.

### Associated data

Canonical and length-prefixed, so no two different inputs encode to the same bytes (this also removes the PE-24 `|chunk:` style ambiguity for fields):

```
aad = "privacy-engine/field/v2" | alg (1) | keyVersion (4) | len16(namespace) | namespace
```

- **The namespace** rejects a value moved to another tenant, even if a key store bug or a misconfiguration hands back a key.
- **The header** (`alg`, `keyVersion`) cannot be edited without failing authentication.
- **The subject is not bound.** Each subject has its own key, so a value moved to another subject, or with its subject field rewritten, already fails authentication: it is opened with a different key.

### Nonce

A random 96-bit nonce per value. The usual bound for random GCM nonces is about 2³² encryptions per key. A key belongs to one subject in one namespace, so the bound is per subject. It will be documented; key versions are the way out if a subject ever gets close.

## 5. Behaviour

The subject in the **value** decides which key is used. When the struct also declares a subject that differs (a copied value, or a mixed-subject struct), the value's subject wins, as in v1.

### Encrypt, per field

| Value | Result |
|---|---|
| Empty string | Left empty (as today) |
| Not a v2 value | Encrypted under the field's subject, current key version |
| v2 value, its subject's key is **Active** and it **authenticates** | Kept as is: already encrypted (idempotency, PE-05) |
| v2 value, its subject's key is **Active** and it does **not** authenticate | **Error** (D-C) |
| v2 value, its subject's key is **Disabled or Deleted** | Kept as is: it is a shredded value, and re-saving a record that holds one must keep working |
| v2 value, its subject is **Unknown** to the engine | **Error** |

Keys for subjects named by values but not by the struct are fetched with `GetKeys` (never created), in the same prefetch as the struct's subjects.

### Decrypt, per field

This needs the key engine to say *why* a key is missing (section 6).

| Value | Key state of the value's subject | Result |
|---|---|---|
| Not a v2 value | – | Left as is (never encrypted) |
| v2, unknown algorithm or key version | – | Error |
| v2 | Active, authenticates | Plaintext |
| v2 | Active, fails authentication | Error: tampered, wrong namespace, or wrong key. Field untouched |
| v2 | Disabled or Deleted | Forgotten value (below) |
| v2 | **Unknown** | **Error** `ErrKeyUnknown`. Field untouched (PE-10) |

Errors name the field path, never the value or the subject. One struct stays all-or-nothing, as struct-sensitive guarantees.

**Forgotten value.** struct-sensitive accepts `replace=` on `data` tags again (`bdea8a7`), so the tag stays the per-field placeholder. `ProtectorConfig.ForgottenValue` (default `""`) covers fields without the option.

## 6. Contract changes this needs

| Where | Change | Why |
|---|---|---|
| `core.KeyEngine.GetKeys` | Also report the state of each requested ID that has no active key: `Disabled`, `Deleted` or `Unknown` | PE-10. Engines already store the state; the DynamoDB engine reads it and drops it |
| `core.Encryptor` | `Encrypt`/`Decrypt` take `{namespace, keyVersion}` and `[]byte` plaintext | The header and namespace go into the AAD; `[]byte` lets plaintext be wiped where callers allow |
| `privacytest` | Cases for state reporting, including unknown subjects (PX-05) | So privacy-engine.elastic is tested against the same rules |
| Stream header | Add the 4-byte key version next to `alg`, while stream v2 still has no data | Same rotation story for streams and fields. `*WithKey` streams write `0` = caller-managed key |

Key versions are **reserved, not implemented**. Rotation needs the key store to keep several versions per subject and an API to ask for one. That is its own design, after privacy-engine.elastic is fixed.

## 7. Not in this format: field binding (PE-11)

Swapping two values of the **same subject and namespace** (email ↔ phone of the same person) still goes undetected. Only someone with write access to the database can do it, and they can only rearrange one person's own data. Binding the Go field path would block it, but renaming or moving a field would then make old data unreadable, which is a real hazard for event-sourced code like doconvoy. PE-11 stays open, documented as an accepted risk. If it is ever needed, a stable `bind=<name>` tag option can come in a new algorithm ID, with no format change.

## 8. Decisions

- **D1** Encryption context for wrapped DEKs: pluggable function (privacy-engine.elastic).
- **D2** One CMK at this stage; the resolver keeps per-tenant CMKs possible later.
- **D3** `Forget` is graceful by default; immediate deletion when forced.
- **D-C** A v2 value that does not authenticate under an active key fails `Encrypt` (fail closed).
- **D-D** Prefix `ENC.`; only this format is parsed.

## 9. Implementation plan (one commit each, on this branch)

1. `fix(aes)`: reject ciphertext shorter than nonce + tag (PE-03), with the first `FuzzDecrypt`.
2. `feat(core)`: `GetKeys` reports the state of missing keys; memory engine and `privacytest` updated.
3. `feat(core,aes)`: `Encryptor` takes `{namespace, keyVersion}` and `[]byte`; header-bound AAD; stream header gains the key version.
4. `feat`: field wire format v2 (PE-23): new parser and encoder, no regex; v1 and `<pii:` parsing removed.
5. `fix`: idempotency by authentication (PE-05) and the Decrypt state table (PE-10), with `ForgottenValue`.
6. `docs`: this file becomes the format spec; README rule on pseudonymous subject IDs (PE-06); audit statuses updated.

Each step leaves `GOWORK=off go test -race ./...` green, with a regression test per finding ID.
