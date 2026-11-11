# Field wire format v2: proposal

| | |
|---|---|
| Status | Proposal, for discussion. Nothing here is implemented yet |
| Branch | `fix/audit-hardening` |
| Findings addressed | PE-03, PE-05, PE-06, PE-10, PE-11, PE-23 (see `audit-readiness.md`) |
| Compatibility | None kept. v1 values (`ENC.` and `<pii:`) stop being readable. There is no deployed data to keep |
| Related | Stream format v2 is already done (`aes/stream.go`, PE-02). This document covers field values |

## 1. Why change the format

A field value today looks like this (`wire_format.go`):

```
ENC.<version>.<base64(subjectID)>.<base64(nonce | ciphertext | tag)>
ENC..dTE=.q2b0…     ← subject "u1", version empty (= 1)
```

Six findings come from this shape:

| ID | Problem in v1 | Root cause |
|---|---|---|
| PE-06 | Every ciphertext names its subject in clear, after `Forget` too, and the same subject links records across datasets | Subject ID is in the value |
| PE-11 | A ciphertext can be moved to another field or record of the same namespace and still decrypts | AAD is `ns:<namespace>` only |
| PE-10 | A value moved to another namespace, or a misconfigured backend, silently becomes the "forgotten" placeholder and the PII is lost on the next save | Missing key is read as "forgotten"; nothing distinguishes "unknown" |
| PE-23 | No algorithm or key version, so DEKs can never rotate and the `Encryptor` cannot change | Version is the only header field |
| PE-05 | Any input matching the regex is treated as already encrypted and stored as is, including attacker input naming another subject | Idempotency is decided by shape, not by authentication |
| PE-03 | A value with a too-short ciphertext panics `Decrypt` | No length check before slicing the nonce |

## 2. The mental model

There are four layers. Each one knows only about the layer just below it:

```
┌─ KEK ───────────── KMS CMK (privacy-engine.elastic, KMS wrapper)
│    wraps, with an encryption context from a pluggable function (D1)
├─ DEK ───────────── one per (namespace, subject, key version), stored wrapped
│    in the key store; Forget disables it, the janitor or immediate mode deletes it
├─ subkeys ──────── HKDF(DEK, label): never stored, derived when used
│    ├─ field key      "privacy-engine/field/v2"         ← this document
│    ├─ stream key     "privacy-engine/stream/v2" + salt ← done (PE-02)
│    └─ derived keys   DeriveSubjectKey(purpose)         ← doconvoy attachments
└─ data ──────────── field values (this format), streams (stream format v2)
```

Two consequences shape the design.

**The field value says nothing about the envelope.** A value only has to tell the decrypter *which DEK* to use. Which KMS key wraps that DEK, under which encryption context, is recorded once on the key item in the key store. Moving to another CMK (a `ReEncrypt` of every key item), changing the encryption-context function, or switching KMS for another KEK provider then touches only key items, never a data record. If KMS details were in every value, each of those changes would mean rewriting every encrypted field of every record. So "with or without envelope" is a key store question, and the field format is the same in both cases.

**Crypto-shredding still works through every subkey.** Field, stream and derived keys all come from the DEK, so destroying the DEK destroys all of them. The one exception is a derived key that a caller saves itself (PE-14), and that stays a documented caller responsibility.

## 3. What a v2 value contains, and what it leaves out

| Information | v1 | v2 | Why |
|---|---|---|---|
| Format marker and version | `ENC.<v>` | `ENC2.` | Cheap check for "is this one of ours" |
| Algorithm ID | – | 1 byte | Crypto agility (PE-23) |
| Key version | – | 4 bytes | DEK rotation later, with no format change (PE-23) |
| Subject ID | in clear | **not stored** | Data minimisation (PE-06). Taken from the struct at decrypt time |
| Key reference, fingerprint or hash of the subject | – | **not stored** | Any per-subject tag that does not change would let records be linked (PE-06) |
| Namespace | – | not stored, **bound in AAD** | Known to the protector; binding it rejects moves between namespaces |
| Field binding | – | not stored, **bound in AAD** (D-B) | Rejects moves between fields (PE-11) |
| Nonce, ciphertext, tag | yes | yes | |
| KMS key, encryption context | – | **not stored** | Lives on the key item (section 2) |

### Why the subject can come from the struct

With struct-sensitive v0.7+, every `FieldReplace` carries `SubjectID`: the subject of the struct that owns the field, or of the nearest parent that declares one. Subject fields themselves are never encrypted. So at decrypt time the protector already knows whose value it is reading, and the value does not need to say so. Binding the subject in the AAD then makes the struct and the value check each other: a value under the wrong subject fails authentication instead of being decrypted with the wrong key or being read as forgotten.

doconvoy check: no production code parses `ENC.` or calls `CheckFormat`, and every struct with `data` fields declares a subject (one test asserts the `ENC.` prefix and will need updating). One behaviour change to keep in mind for the doconvoy step: a ciphertext can no longer be copied as is from one struct to a struct with a different subject. It has to be decrypted and encrypted again. In v1 that copy worked because the value named its own subject.

## 4. Layout

```
value   = "ENC2." base64url-nopad(payload)
payload = alg (1) | keyVersion (4, BE) | nonce (12) | ciphertext | tag (16)
```

- `alg = 0x01`: AES-256-GCM with the field subkey below. No other value is accepted.
- `keyVersion`: starts at `1`. Until rotation is designed, the protector writes 1 and rejects anything else with a clear error (not "forgotten").
- base64url without padding, so the value is safe in URLs, JSON, DynamoDB keys and file names. It differs from the standard alphabet so v1 tooling cannot mistake one for the other.
- Minimum payload length is `1 + 4 + 12 + 16 = 33` bytes. Anything shorter is rejected before any slicing (PE-03).

Example (plaintext `alice@example.org`, 17 bytes):

```
ENC2.AQAAAAE…   5 + ceil((33 + 17) * 4 / 3) = 72 characters
```

A v1 value for the same plaintext with a 36-character UUID subject is 114 characters. v2 is shorter because the subject is gone.

### Field subkey

```
fieldKey = HKDF-SHA256(ikm = DEK, salt = none, info = "privacy-engine/field/v2")
```

It is derived once per subject per `Encrypt`/`Decrypt` call, not once per field, and wiped after use. It separates field encryption from streams and from `DeriveSubjectKey` (whose salt is `privacy-engine-v1`), so no two uses ever encrypt under the same AES key.

### Associated data

The AAD is canonical and length-prefixed, so no two different tuples encode to the same bytes (this also fixes the PE-24 `|chunk:` ambiguity for fields):

```
aad = "privacy-engine/field/v2"
    | alg (1) | keyVersion (4)
    | len16(namespace) | namespace
    | len16(subjectID) | subjectID
    | len16(binding)   | binding        (D-B)
```

The header bytes are in the AAD, so changing the algorithm or key version byte fails authentication. They also select the key, so an attacker gains nothing by editing them.

### Nonce

A random 96-bit nonce per value. The usual bound for random GCM nonces is about 2³² encryptions per key. Here a key belongs to one subject in one namespace, so the bound is per subject. It will be documented, and key versions are the way out if a subject ever gets close.

## 5. Behaviour

### Encrypt, per field

1. Empty string: left empty (same as today).
2. The value parses as `ENC2.` **and** authenticates under this field's namespace, subject and binding: left as is. This is the idempotency rule, and the value is checked by authenticating it, not by looking at its shape (PE-05).
3. The value parses as `ENC2.` but does **not** authenticate: **error** (D-C).
4. Anything else: encrypted under the subject's current key version.

### Decrypt, per field

This depends on the key engine reporting *why* a key is missing, which is a contract change (section 6).

| Value | Key state for (namespace, subject) | Result |
|---|---|---|
| Not `ENC2.` | any | Left as is (a field that was never encrypted) |
| `ENC2.`, unknown alg or key version, or too short | any | Error |
| `ENC2.` | Active, authenticates | Plaintext |
| `ENC2.` | Active, fails authentication | Error: tampered, moved, or wrong subject or namespace. Field untouched |
| `ENC2.` | Disabled or Deleted | Forgotten value (see below) |
| `ENC2.` | **Unknown** to the engine | **Error** `ErrKeyUnknown`. Field untouched (PE-10) |

Errors name the field path, never the value. One struct stays all-or-nothing, as struct-sensitive already guarantees.

**The forgotten value.** struct-sensitive no longer accepts the `replace=` tag option (audit section 10), so the placeholder moves to configuration: `ProtectorConfig.ForgottenValue` (default `""`). This is a small, separate change made in the same series.

## 6. Contract changes this needs

| Where | Change | Why |
|---|---|---|
| `core.KeyEngine.GetKeys` | Also report the state of each requested ID with no active key: `Disabled`, `Deleted` or `Unknown` | PE-10: tell "forgotten" from "never existed". Engines already store the state; the DynamoDB engine reads it today and drops it |
| `core.Encryptor` | Encrypt and Decrypt take a context `{namespace, subjectID, binding, keyVersion}` instead of `namespace` alone, and `[]byte` plaintext | AAD and subkey need them; `[]byte` lets plaintext be wiped where callers allow (audit section 2) |
| `privacytest` | Cases for the state reporting, including the PX-05 "unknown subject" behaviour | So privacy-engine.elastic is tested against the same rules |
| Stream header | Add the 4-byte key version next to `alg`, while stream v2 still has no data | Same rotation story for streams and fields. `*WithKey` streams write `0` = caller-managed key |

Key versions are **reserved, not implemented**. Rotation needs the key store to keep several versions per subject and an engine API to ask for a version. That is its own design, after privacy-engine.elastic is fixed. Reserving the field now means rotation will not need another format change.

## 7. Decisions needed

**D-B. What is the field binding in the AAD?**
- (1) Nothing. Bind namespace and subject only. A value can still be swapped between two fields of the same subject (email ↔ phone, same person), which an attacker with write access to the database can do, with limited impact.
- (2) The field path without indices, e.g. `Members[].Email`. Blocks swaps between different fields. Elements of one slice stay interchangeable, so adding, removing or reordering slice elements stays safe. **Renaming or moving a Go field breaks decryption of old data.** For event-sourced code like doconvoy, where old events are read for years, that is a real hazard.
- (3) The full path with indices, `Members[0].Email`. Strongest, but removing element 0 makes every later element undecryptable. Not recommended.
- (4) An explicit, stable name: `bind=<name>` on the tag, falling back to (1) when absent. It survives refactoring, but needs a struct-sensitive tag option and discipline from callers.

Recommendation: **(1) now**, with the binding slot kept in the AAD so (4) can be added later without a format change. (2) looks tempting, but it turns a harmless refactor into data loss.

**D-C. A value that looks like `ENC2.` but does not authenticate, on Encrypt:**
- Error (fail closed). Loud when doconvoy copies a ciphertext between subjects by mistake (section 3). User input that happens to start with `ENC2.` and is valid base64url of at least 33 bytes is rejected. In practice that is only someone deliberately imitating the format.
- Encrypt it as plaintext. Always correct for attacker input (it decrypts back to their literal string), but a copied ciphertext silently becomes a ciphertext-shaped string after decryption.

Recommendation: **error**.

**D-D. Prefix: `ENC2.`** or something more specific to this library, such as `pe2.`. The prefix is the only part visible to people reading the database. Recommendation: `ENC2.`, which stays close to what operators know.

## 8. Implementation plan (one commit each, on this branch)

1. `fix(aes)`: reject ciphertext shorter than nonce + tag (PE-03), with the first `FuzzDecrypt`. Independent of the rest; can land first.
2. `feat(core)`: `GetKeys` reports the state of missing keys; memory engine and `privacytest` updated.
3. `feat(core,aes)`: `Encryptor` takes the encryption context and `[]byte`; field subkey via HKDF; stream header gains the key version.
4. `feat`: field wire format v2 (PE-06, PE-11, PE-23): new `wire_format.go`, AAD binding, protector uses the struct's subject.
5. `fix`: idempotency by authentication (PE-05) and Decrypt state table (PE-10), with `ForgottenValue`.
6. `docs`: this file becomes the format spec; audit statuses updated.

Each step leaves `GOWORK=off go test -race ./...` green, with a regression test per finding ID.
