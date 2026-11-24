---
name: privacy-engine-integrate
description: Add the Go library github.com/ln80/privacy-engine to a Go service to protect personal data. Covers field-level encryption of struct fields with one key per data subject, crypto-shredding for erasure requests (GDPR Art. 17, right to be forgotten), tokenization of identifiers such as emails, and audit events. Use when asked to encrypt PII or personal data in Go structs, events or records, make data erasable or forgettable in immutable stores (event logs, audit trails, backups), add crypto-shredding, pseudonymize or tokenize identifiers, or wire erasure and re-identification auditing in a Go codebase.
license: Apache-2.0
compatibility: Requires Go 1.25 or later. Uses github.com/ln80/privacy-engine v0.11.0 or later.
metadata:
  author: ln80
  version: "0.11"
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
`wire-format.md` §4 for exact `Encrypt`/`Decrypt` behaviour per key state.

## 2. Map the personal data

Before writing code, list for the user:

- the structs, events and records that hold personal data, and which fields;
- the **subject** each record belongs to (the person whose erasure must
  remove it);
- where records are written (repositories, event store appends, queue
  publishers) and read back.

**Subject IDs must be pseudonymous**: a random ID or a token, never an email,
name or phone number. Every encrypted value names its subject in clear. If
records are keyed by an email today, tokenize the email at ingestion and use
the token as the subject ID (step 6).

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

`sensitive` and `sens` work as tag names too. A struct uses one subject;
embedding another subject's data needs `privacy.WithMultipleSubjects()`.
Data fields must be string types, `*string`, `[]string` or `[]*string`;
nested structs work directly or through slices and maps (`dive`). Other types
fail at `Encrypt` with an unsupported-field error.

## 4. Build the Protector

Production needs real backends; never use the `memory` package outside
tests. If the user has no key store, key wrapper or token store yet, build
them with the **privacy-engine-backend** skill first.

```go
keys := envelope.NewKeyEngine(kmsWrapper, keyStore) // wrapped keys only in the store
newProtector := func(tenant string) *privacy.Protector {
    return privacy.NewProtector(tenant, keys,
        privacy.WithTokenEngine(tokenStore), // only if tokenizing
        privacy.WithAuditor(auditor),        // regulated data: always
    )
}
factory := privacy.NewFactory(newProtector) // one Protector per tenant (namespace)
factory.Monitor(ctx)                        // clears caches, evicts idle Protectors
p, done := factory.Instance(tenantID)
defer done()
```

Options and trade-offs are in [references/patterns.md](references/patterns.md#options).
Give each service the narrowest role interface it needs (`privacy.Encrypter`,
`Shredder`, `Tokenizer`, `Reidentifier`), backed by its own credentials.

## 5. Encrypt on write, decrypt on read

Call `p.Encrypt(ctx, &rec)` right before persisting or publishing, and
`p.Decrypt(ctx, &rec)` right after loading. Patterns for repositories and
event stores, and error handling, are in
[references/patterns.md](references/patterns.md).

- Never log, trace or cache a decrypted struct.
- `Encrypt` is idempotent and safe to call on already-encrypted records.
- Each struct is all-or-nothing: on error, no field changes.

## 6. Tokenize identifiers at ingestion

```go
res, err := p.Tokenize(ctx, privacy.TokenDataSlice(email), privacy.WithPrefix("sub_"))
subjectID := res.Get(email).Token // same token for the same email in this tenant
```

Use the token downstream and as the subject ID. Reveal values with
`Detokenize` only in the few places that must, through the `Reidentifier`
role; every reveal is audited.

## 7. Wire erasure

```go
err := p.Forget(ctx, subjectID)                       // graceful: Recover works until the grace period ends
err := p.Forget(ctx, subjectID, privacy.Immediately()) // confirmed request: no recovery
```

- Answer the data subject with `FinalAt` from the Forget audit event.
- Run the erasure job (`DeleteUnusedKeys`, `EraseForgotten`) or rely on a
  store that erases by TTL.
- Delete plaintext copies the library cannot reach: logs, caches, search
  indexes, analytics.

## 8. Test

Use `memory.NewKeyEngine()` and `memory.NewTokenEngine()` in tests only. Add
at least: encrypt, persist and decrypt round trip; `Forget` then decrypt
gives the placeholder; writing for a forgotten subject fails with
`privacy.ErrSubjectForgotten`.

## Checklist

- [ ] Every personal-data field is tagged; subject IDs are pseudonymous.
- [ ] Encrypt before every write path; decrypt after every read path.
- [ ] Production uses real backends with wrapped keys, never `memory`.
- [ ] An auditor is set; erasure answers with `FinalAt`.
- [ ] An erasure job or TTL completes erasure.
- [ ] No decrypted data in logs; plaintext copies have their own deletion.
