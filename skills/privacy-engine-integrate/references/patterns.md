# Integration patterns

## Options

| Option | Default | When to change |
|---|---|---|
| `WithCacheTTL(d)` / `WithoutCache()` | cache on, 20 s | Lower the TTL for faster cross-instance erasure, at the cost of more key store and KMS calls |
| `WithImmediateErasure()` | graceful | Every `Forget` erases at once, with no `Recover`. Prefer `Forget(id, Immediately())` per call |
| `WithTokenEngine(e)` | none | Required for `Tokenize`, `Detokenize`, `ListTokens` |
| `WithAuditor(a)` | none | Always for regulated data |
| `WithMultipleSubjects()` | off | A struct embeds another subject's data, each field under its nearest subject |
| `WithForgottenValue(v)` | `""` | Placeholder for forgotten fields without `replace=` |

Per call: `Forget(ctx, id, privacy.Immediately())`; `Tokenize(ctx, values,
privacy.WithPrefix("cus_"), privacy.WithTokenGenerator(gen))`. Options are
the only way to configure: the config structs are not exported.

## Repository decorator

Encrypt and decrypt at the storage boundary, so domain code handles
plaintext and storage only ciphertext:

```go
type CustomerRepo struct {
    db   *sql.DB
    priv privacy.Encrypter
}

func (r *CustomerRepo) Save(ctx context.Context, c Customer) error {
    if err := r.priv.Encrypt(ctx, &c); err != nil { // c is a copy: the caller keeps plaintext
        return err
    }
    return r.insert(ctx, c)
}

func (r *CustomerRepo) Get(ctx context.Context, id string) (Customer, error) {
    c, err := r.load(ctx, id)
    if err != nil {
        return Customer{}, err
    }
    return c, r.priv.Decrypt(ctx, &c)
}
```

## Event stores and message queues

Encrypt each event before append or publish; decrypt after load or consume.
Events stay immutable: forgetting the subject shreds every past event at
once. Several structs in one call: `p.Encrypt(ctx, &e1, &e2)`.

## Error handling

| Error (use `errors.Is`) | Meaning | Typical handling |
|---|---|---|
| `privacy.ErrSubjectForgotten` | Writing personal data for a forgotten subject | Reject the write; the person asked to be erased |
| `privacy.ErrKeyUnknown` | A value names a subject unknown in this namespace | Wrong tenant or store, or a purge: investigate, do not ignore |
| `privacy.ErrValueNotAuthentic`, `core.ErrDecryptionFailure` | A value was altered or copied across tenants | Treat as tampering: alert |
| `privacy.ErrAuditFailure` | The audit sink failed | Erasure: applied, retry the call. Reveal: nothing was returned |
| `privacy.ErrMultipleSubjects` | `Encrypt` found several subjects in one struct | A bug in the tags; or use `WithMultipleSubjects()` if intended |
| `core.ErrKeyNotFound` (from `Forget`, `Recover`) | The ID has no key and no vault entry: unknown, or already erased | `Forget`: nothing to erase; report not found or treat as done |

Errors name field paths, never values. `privacy.Error.Subject()` and
`Namespace()` give the context.

## Auditor

```go
auditor := privacy.AuditorFunc(func(ctx context.Context, e privacy.AuditEvent) error {
    slog.InfoContext(ctx, "privacy audit", "op", e.Op, "namespace", e.Namespace,
        "subject", e.Subject, "final_at", e.FinalAt, "revealed", len(e.Revealed), "err", e.Err)
    return nil // or persist to an append-only store and return its error
})
```

Events never carry values or keys. Take the actor and reason from `ctx`.

## Returning FinalAt

`Forget` returns only an error; the erasure deadline arrives in the audit
event, delivered synchronously with the caller's context. Collect it through
the context:

```go
type finalAtKey struct{}

// The auditor records FinalAt into a slot the caller placed in ctx.
auditor := privacy.AuditorFunc(func(ctx context.Context, e privacy.AuditEvent) error {
    if slot, ok := ctx.Value(finalAtKey{}).(*time.Time); ok && e.Op == privacy.OpForget {
        *slot = e.FinalAt
    }
    return persist(ctx, e) // your audit trail
})

func (s *Store) Forget(ctx context.Context, id string) (finalAt time.Time, err error) {
    ctx = context.WithValue(ctx, finalAtKey{}, &finalAt)
    err = s.priv.Forget(ctx, id)
    return finalAt, err
}
```

A zero `FinalAt` means unknown: an engine does not report its grace period.

## Erasure job

Graceful `Forget` disables a key and hides a vault entry; a job completes
erasure after the grace period, unless the stores erase by TTL. Run it at
least daily, for every tenant namespace:

```go
func eraseExpired(ctx context.Context, keys core.KeyEngine, tokens core.TokenEngine, ns string, grace time.Duration) error {
    if err := keys.DeleteUnusedKeys(ctx, ns); err != nil {
        return err
    }
    _, err := tokens.EraseForgotten(ctx, ns, time.Now().Add(-grace))
    return err
}
```

Pass the same engines the Protector uses (`envelope.KeyEngine` forwards to
the store). Reads already treat expired keys as deleted; the job removes
the material. `Immediately()` needs no job.

## Existing data

Crypto-shredding only reaches values encrypted under the subject's key.
Personal data already stored in clear cannot be shredded:

- **Mutable records:** migrate by loading, re-keying to a token ID if
  needed, encrypting, and rewriting. `Encrypt` is idempotent, so the
  migration can be re-run.
- **Immutable logs and backups:** rewrite them into a new encrypted stream
  and delete the old one, or document the plaintext with its retention
  and delete it when that expires. Tell the user; do not hide it.

## Streams and derived keys

- Files and large payloads: `p.EncryptStream(ctx, subjectID, r)` and
  `p.DecryptStream(ctx, subjectID, r)`. Trust the output only once `Read`
  returns `io.EOF`.
- A per-purpose key for another system: `p.DeriveSubjectKey(ctx, subjectID, "purpose")`.
  It dies with the subject's key; do not store it.

## Anti-patterns

- An email, name or phone number as subject ID.
- Logging or tracing decrypted structs; error messages built from values.
- `memory` engines in production.
- Decrypting in a shared cache and keeping plaintext after `Forget`.
- Forgetting the plaintext copies: search indexes, analytics exports, logs.
