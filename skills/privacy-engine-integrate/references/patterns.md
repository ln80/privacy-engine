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
