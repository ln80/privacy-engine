---
name: privacy-engine-integrate
description: Add the Go library github.com/ln80/privacy-engine to a Go service to protect personal data. Covers field-level encryption of struct fields with one key per data subject, crypto-shredding for erasure requests (GDPR Art. 17, right to be forgotten), tokenization of identifiers such as emails, and audit events. Use when asked to encrypt PII or personal data in Go structs, events or records, make data erasable or forgettable in immutable stores (event logs, audit trails, backups), add crypto-shredding, pseudonymize or tokenize identifiers, or wire erasure and re-identification auditing in a Go codebase.
license: Apache-2.0
compatibility: Requires Go 1.25 or later. Uses github.com/ln80/privacy-engine v0.12.0 or later.
metadata:
  author: ln80
  version: "0.12"
---

# Integrate privacy-engine into a Go service

privacy-engine encrypts tagged struct fields under one key per data subject.
Deleting a subject's key makes all of that subject's data unreadable
wherever it was copied. Integrate it at the boundaries where personal data
enters and leaves storage.

## 1. Read the specification for the version in use

```sh
go get github.com/ln80/privacy-engine@latest   # if not yet a dependency
sh scripts/locate-docs.sh /path/to/user/module
```

The script prints the `docs/` directory of the version in use. Read
`architecture.md` §2 (the guarantees) and `production.md`. Consult
`wire-format.md` §4 for exact `Encrypt`/`Decrypt` behaviour per key state,
and `token-vault.md` when tokenizing.

## 2. Map the personal data, then agree the design with the user

List before writing code:

- the structs, events and records holding personal data, and which fields;
- the **subject** of each record: the person whose erasure must remove it;
- where records are written (repositories, event appends, publishers) and
  read back, and which read paths are keyed by a direct identifier (email);
- personal data **already stored in clear** (see
  [references/patterns.md](references/patterns.md#existing-data)).

**Subject IDs must be pseudonymous**: a random ID or a token, never an email,
name or phone number. Every encrypted value names its subject in clear.
Records keyed by an email today get a token as their ID (step 6), which
changes caller-facing APIs (`Get(email)` becomes `Get(id)`, events carry the
ID): say so to the user before changing them.

## 3. Tag the structs

```go
type Customer struct {
    ID      string  `pii:"subjectID"`
    Email   string  `pii:"data"`
    Name    string  `pii:"data,replace=[erased]"` // shown once the subject is forgotten
    Address Address `pii:"dive"`                  // recurse into nested structs
    Plan    string                                // not personal data: left in clear
}
```

- `sensitive` and `sens` work as tag names too.
- Data fields must be string types, `*string`, `[]string` or `[]*string`;
  nested structs work directly or through slices and maps (`dive`). Other
  types fail at `Encrypt` with an unsupported-field error.
- A nested struct without its own `subjectID` belongs to its parent's
  subject, so one `Address` type can serve several records. A nested struct
  declaring its own `subjectID` needs `privacy.WithMultipleSubjects()`.

## 4. Build the Protector

Production needs real backends with wrapped keys. If the user has none yet,
build them with the **privacy-engine-backend** skill. Until then, the
`memory` engines may stand in **for local development and tests only**:
take `core.KeyEngine` and `core.TokenEngine` as constructor parameters, and
name the in-memory variant so nobody ships it (`NewDevProtector`). The
in-memory engines lose every key on restart.

```go
func NewProtector(tenant string, keys core.KeyEngine, tokens core.TokenEngine, a privacy.Auditor) *privacy.Protector {
    return privacy.NewProtector(tenant, keys,
        privacy.WithTokenEngine(tokens), // only if tokenizing
        privacy.WithAuditor(a),          // regulated data: always
    )
}
// production: keys := envelope.NewKeyEngine(kmsWrapper, keyStore)
```

- Single tenant: one `NewProtector` call. Several tenants: one Protector per
  tenant through `privacy.NewFactory`; call `factory.Monitor(ctx)` once.
- Depend on the narrowest interface: `privacy.Encrypter`, `Shredder`,
  `Tokenizer`, `Reidentifier`, or a small interface of your own with exactly
  the methods a component calls.

Options and trade-offs: [references/patterns.md](references/patterns.md#options).

## 5. Encrypt on write, decrypt on read

Call `p.Encrypt(ctx, &rec)` on a copy right before persisting or publishing,
and `p.Decrypt(ctx, &rec)` right after loading. Patterns and error handling:
[references/patterns.md](references/patterns.md).

- Never log, trace or cache a decrypted struct. Log IDs only.
- `Encrypt` is idempotent and safe on already-encrypted records.
- Each struct is all-or-nothing: on error, no field changes.

## 6. Tokenize identifiers at ingestion

```go
email = strings.ToLower(strings.TrimSpace(email)) // normalise: the vault indexes exact bytes
res, err := p.Tokenize(ctx, privacy.TokenDataSlice(email), privacy.WithPrefix("cus_"))
id := res.Get(email).Token // same token for the same value in this tenant
```

- Use the token downstream and as the subject ID.
- **There is no read-only lookup by value**: `Tokenize` of an unknown value
  creates a token and stores the value sealed. Look up by email only where
  that is acceptable (sign-up, login of a known user); elsewhere read by ID.
- Reveal values with `Detokenize` only where needed, through the
  `Reidentifier` role; every reveal is audited.

## 7. Wire erasure

```go
err := p.Forget(ctx, id)                       // graceful: Recover works until the grace period ends
err := p.Forget(ctx, id, privacy.Immediately()) // confirmed request: no recovery, no erasure job needed
```

- When `id` is a token, one `Forget` shreds the subject's key **and** its
  vault entry; tokenizing the same value again yields a new, unlinkable
  token.
- An ID with neither a key nor a vault entry (unknown, or already erased)
  returns an error wrapping `core.ErrKeyNotFound`: treat it as "nothing to
  erase". A graceful `Forget` of an already forgotten subject returns nil.
- Answer the data subject with `FinalAt` from the Forget audit event;
  [references/patterns.md](references/patterns.md#returning-finalat) shows
  how to return it to the caller.
- Graceful erasure completes when a job calls `DeleteUnusedKeys` and
  `EraseForgotten` on the engines, or the store erases by TTL:
  [references/patterns.md](references/patterns.md#erasure-job).
- Delete the mutable record too, and every plaintext copy the library cannot
  reach: logs, caches, search indexes, analytics.

## 8. Test

Use the `memory` engines in tests. Cover at least:

- round trip: encrypt, persist, load, decrypt;
- encrypted at rest: every stored personal field passes
  `privacy.CheckFormat(v) == nil`, and no plaintext appears in stored data
  or captured logs;
- `Forget` then decrypt: placeholders in every record and event of that
  subject, including copies taken before `Forget`; other subjects unaffected;
- writing for a forgotten subject fails with `privacy.ErrSubjectForgotten`;
- `Forget` of an unknown ID matches the behaviour you chose for it.

## Checklist

- [ ] Every personal-data field is tagged; subject IDs are pseudonymous.
- [ ] Encrypt before every write path; decrypt after every read path.
- [ ] Production uses real backends with wrapped keys; `memory` is dev/test only.
- [ ] An auditor is set; erasure answers with `FinalAt`.
- [ ] An erasure job or TTL completes graceful erasure.
- [ ] No decrypted data in logs; existing plaintext data has a migration plan.
