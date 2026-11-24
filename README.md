privacy-engine
==============
[![Go Module](https://github.com/ln80/privacy-engine/actions/workflows/module.yml/badge.svg)](https://github.com/ln80/privacy-engine/actions/workflows/module.yml)
[![GoDoc](https://godoc.org/github.com/ln80/privacy-engine?status.svg)](https://godoc.org/github.com/ln80/privacy-engine)

Field-level encryption, crypto-shredding and tokenization for Go structs.

Each data subject gets its own key. Delete the key and the subject's data is
unreadable everywhere it was copied: event logs, audit trails, backups. Made
for stores you cannot edit, where erasure (GDPR Art. 17) must still work.

```bash
go get github.com/ln80/privacy-engine
```

## Quick start

```go
type User struct {
    ID    string `pii:"subjectID"`
    Email string `pii:"data,replace=redacted"`
}

p := privacy.NewProtector("tenant-1", memory.NewKeyEngine()) // memory: tests only

u := User{ID: "user-123", Email: "alice@example.com"}
_ = p.Encrypt(ctx, &u) // u.Email = "ENC.dXNlci0xMjM.AQAAAAF..."
stored := u            // what your database holds

_ = p.Decrypt(ctx, &u) // u.Email = "alice@example.com"

_ = p.Forget(ctx, "user-123") // graceful: Recover works until the grace period ends
_ = p.Decrypt(ctx, &stored)   // stored.Email = "redacted"
```

| Tag | Meaning |
|---|---|
| `pii:"subjectID"` | The field holding the subject ID |
| `pii:"data"` | Encrypt this field |
| `pii:"data,replace=X"` | Show `X` once the subject is forgotten |
| `pii:"dive"` | Recurse into a nested struct |

`sensitive` and `sens` work as tag names too.

> **Subject IDs must be pseudonymous**: a random ID or a token, never an
> email or a name. Encrypted values name their subject in clear.

## Tokenization

Replace an identifier with a random token, and use the token as the subject:

```go
p := privacy.NewProtector("tenant-1", keys, privacy.WithTokenEngine(tokens))

res, _ := p.Tokenize(ctx, privacy.TokenDataSlice("alice@example.com"), privacy.WithPrefix("sub_"))
id := res.Get("alice@example.com").Token // "sub_…", same token for the same value

vals, _ := p.Detokenize(ctx, []string{id})
_ = p.Forget(ctx, id) // hides the value and shreds data encrypted under id
```

## Streams

```go
enc, _ := p.EncryptStream(ctx, "user-123", file)
dec, _ := p.DecryptStream(ctx, "user-123", enc)
```

Plaintext is released per authenticated segment: trust the output only once
`Read` returns `io.EOF`.

## Options

| Option | Default | |
|---|---|---|
| `WithTokenEngine(e)` | none | Enables tokenization |
| `WithCacheTTL(d)`, `WithoutCache()` | 20 s | Key cache; bounds cross-instance erasure delay |
| `WithImmediateErasure()` | graceful | `Forget` erases at once; `Immediately()` does it per call |
| `WithAuditor(a)` | none | Events for erasure and re-identification |
| `WithMultipleSubjects()` | off | Several subjects in one struct |
| `WithForgottenValue(v)` | `""` | Placeholder when the tag has no `replace=` |
| `WithEncryptor(e)` | AES-256-GCM | Encryption algorithm |

For many tenants, `privacy.NewFactory` keeps one `Protector` per namespace
and evicts idle ones. Code that needs only part of the API can take a role
interface: `Encrypter`, `Shredder`, `Tokenizer` or `Reidentifier`.

## Production

The `memory` engines are for tests. In production you implement the storage
contracts in `core` (a key store, a `KeyWrapper` for your KMS or HSM, a token
store), combine keys with `envelope.NewKeyEngine(wrapper, store)`, and prove
them with the `privacytest` conformance suites. Start with:

- [docs/implementing-backends.md](docs/implementing-backends.md): what a backend must do
- [docs/production.md](docs/production.md): deployment, erasure, backups, monitoring
- [docs/README.md](docs/README.md): all documentation, including the threat model and formats

Coding agents: see [AGENTS.md](AGENTS.md).

## Limitations

- **Not independently reviewed.** Report issues as described in [SECURITY.md](SECURITY.md).
- **No key rotation** yet ([details](docs/key-lifecycle.md#5-rotation-not-supported)).
- **Erasure stops at the library**: plaintext you copy elsewhere, and key
  store backups until they expire, are yours to handle.
- **Pre-v1 API**: minor releases may break it. Stored data follows the
  [versioning rules](docs/wire-format.md#8-versioning-and-compatibility).

## License

Apache License 2.0. See [LICENSE](LICENSE).
