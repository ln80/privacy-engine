privacy-engine
============
[![Go Module](https://github.com/ln80/privacy-engine/actions/workflows/module.yml/badge.svg)](https://github.com/ln80/privacy-engine/actions/workflows/module.yml)
[![GoDoc](https://godoc.org/github.com/ln80/privacy-engine?status.svg)](https://godoc.org/github.com/ln80/privacy-engine)

A Go library for field-level encryption, crypto-shredding, and tokenization of sensitive data in structs. Built on top of [struct-sensitive](https://github.com/ln80/struct-sensitive), it uses struct tags to identify PII fields and applies AES-256-GCM encryption per data subject.

Designed for immutable stores (event logs, audit trails) where you can't delete records but need to comply with data erasure requirements (GDPR Article 17) via cryptographic erasure.

## Installation

```bash
go get github.com/ln80/privacy-engine
```

## Features

- **Field-level encryption** using AES-256-GCM with per-subject data encryption keys (DEK)
- **Crypto-shredding** with graceful mode: disable keys first, recover within a grace period, then hard-delete
- **Streaming encryption** for large payloads with chunk-based authenticated encryption
- **Tokenization** to replace sensitive identifiers with opaque surrogate tokens
- **Key derivation** via HKDF-SHA256 for purpose-scoped keys from a subject's DEK
- **Multi-tenancy** with namespace isolation and a Factory for managing Protector instances
- **Pluggable backends** via `KeyEngine`, `Encryptor`, and `TokenEngine` interfaces

## Quick Start

```go
import (
    "context"

    "github.com/ln80/privacy-engine"
    "github.com/ln80/privacy-engine/memory"
)

type User struct {
    ID      string `pii:"subjectID"`
    Email   string `pii:"data,replace=redacted"`
    Country string
}

func main() {
    ctx := context.Background()
    protector := privacy.NewProtector("my-namespace", memory.NewKeyEngine())

    user := User{ID: "user-123", Email: "alice@example.com", Country: "BE"}

    // Encrypt PII fields in-place
    _ = protector.Encrypt(ctx, &user)
    // user.Email is now: "ENC..dXNlci0xMjM=.Base64CipherText..."
    // user.Country is unchanged

    // Decrypt back
    _ = protector.Decrypt(ctx, &user)
    // user.Email is "alice@example.com" again

    // Crypto-shred: forget the subject's key
    _ = protector.Encrypt(ctx, &user)
    _ = protector.Forget(ctx, "user-123")
    _ = protector.Decrypt(ctx, &user)
    // user.Email is now "redacted" (from the replace tag option)
}
```

## Struct Tags

Fields are tagged using `pii`, `sensitive`, or `sens` (interchangeable):

| Tag | Purpose | Example |
|-----|---------|---------|
| `subjectID` | Identifies the data subject (one per struct; see below for nested subjects) | `pii:"subjectID"` |
| `data` | Marks a field as sensitive | `pii:"data"` |
| `data,replace=X` | Replacement value when the subject is forgotten | `pii:"data,replace=deleted"` |
| `dive` | Recurse into nested structs | `pii:"dive"` |

> **Subject IDs must be pseudonymous.** Use a random ID or a token from the
> tokenizer, never an email, a name or another direct identifier. Every
> encrypted value names its subject in clear (see [Wire Format](#wire-format)),
> just as the record's own `subjectID` field does. To key data on an email,
> tokenize the email first and use the token as the subject, as in the example
> below.

### One subject or several per record

By default `Encrypt` requires each record to use one subject, so forgetting that subject erases all of the record's personal data. A record whose data belongs to several subjects (for example an embedded author with its own `subjectID`) fails with struct-sensitive's `ErrMultipleSubjectID`. To allow it, encrypting each field under the nearest declared subject:

```go
p := privacy.NewProtector("tenant", engine, func(pc *privacy.ProtectorConfig) {
    pc.MultipleSubjects = true
})
```

`Decrypt` reads the subject from each value and accepts either.

## Architecture

```
┌──────────────┐
│  Protector   │  ← Main API: Encrypt, Decrypt, Forget, Recover, Tokenize
└──────┬───────┘
       │
  ┌────┴─────┐    ┌────────────┐    ┌──────────────┐
  │KeyEngine │    │ Encryptor  │    │ TokenEngine  │
  │(keys CRUD)│   │(AES-256-GCM)│  │(value↔token) │
  └──────────┘    └────────────┘    └──────────────┘
```

- **KeyEngine** manages encryption key lifecycle (create, get, disable, re-enable, delete). Implementations: in-memory (for tests), DynamoDB + KMS (production, see [privacy-engine.elastic](https://github.com/ln80/privacy-engine.elastic)).
- **Encryptor** handles the actual encryption. Default: AES-256-GCM with random nonces; the AAD binds the namespace, the key version and the algorithm ID (`core.Binding`).
- **TokenEngine** manages value-to-token mappings for pseudonymization. Optional.

## Tokenization

Replace sensitive identifiers with opaque tokens early in the pipeline:

```go
tokens, _ := protector.Tokenize(ctx, privacy.TokenDataSlice("alice@example.com"), privacy.WithPrefix("sub_"))
surrogateID := tokens.Get("alice@example.com").Token
// Use surrogateID downstream instead of the real email
```

## Streaming Encryption

For large payloads (files, attachments):

```go
encReader, _ := protector.EncryptStream(ctx, "user-123", plaintextReader)
// encReader emits authenticated ciphertext in 64 KiB segments

decReader, _ := protector.DecryptStream(ctx, "user-123", encReader)
// decReader emits the original plaintext
```

Streams use the STREAM construction (as in Tink and age): each stream gets its own
key derived from the subject's key, and every segment is bound to its position, to
the header and to whether it is the last one. Truncation, reordering, dropped or
appended segments, and header edits all fail with `ErrDecryptionFailure`.

Plaintext is released one authenticated segment at a time, so a damaged stream
yields its first intact segments and then an error. Treat the output as valid only
once `Read` returns `io.EOF`, for example by writing to a temporary location and
committing on success. The readers hold no goroutine, so an abandoned stream leaks
nothing.

## Factory & Monitoring

For multi-tenant applications, use the Factory to manage one Protector per namespace:

```go
factory := privacy.NewFactory(func(namespace string) privacy.Protector {
    return privacy.NewProtector(namespace, keyEngine, opts...)
})

// Periodically clears key caches and evicts idle protectors
factory.Monitor(ctx)

protector, clearFn := factory.Instance("tenant-abc")
defer clearFn()
```

## Configuration

`NewProtector` accepts functional options:

| Option | Default | Description |
|--------|---------|-------------|
| `CacheEnabled` | `true` | Wrap engines with in-memory TTL cache |
| `CacheTTL` | `20s` | Cache time-to-live |
| `GracefulMode` | `true` | Disable keys before deleting (allows recovery) |
| `Encryptor` | AES-256-GCM | Encryption algorithm |
| `TokenEngine` | `nil` | Token engine for pseudonymization |

## Production Backend

See [privacy-engine.elastic](https://github.com/ln80/privacy-engine.elastic) for a serverless implementation using AWS DynamoDB (key/token storage) and KMS (master key management), deployable via SAM.

## Wire Format

Encrypted field values are stored as:

```
ENC.<base64url(subjectID)>.<base64url(alg | keyVersion | nonce | ciphertext | tag)>
```

The value names the subject whose key encrypted it, so it can be decrypted
into any struct and keeps following that subject when copied. The algorithm
ID and key version are authenticated with the namespace. Only this format is
parsed. The full specification is in [docs/wire-format-v2.md](docs/wire-format-v2.md).

| On `Encrypt`, a field that… | Result |
|---|---|
| is plaintext | encrypted under the field's subject |
| is already encrypted and authenticates under its subject's key | kept as is (idempotent) |
| is encrypted for a forgotten subject | kept as is (it is shredded) |
| looks encrypted but does not authenticate | `ErrValueNotAuthentic` |
| names a subject unknown in the namespace | `ErrKeyUnknown` |

| On `Decrypt`, the value's subject key is… | Result |
|---|---|
| active | plaintext; a value that does not authenticate is an error |
| disabled or deleted (forgotten) | the tag's `replace=` value, or `ProtectorConfig.ForgottenValue` |
| unknown (never created, purged, wrong namespace) | `ErrKeyUnknown`, field untouched |

Every struct is all-or-nothing: on error, none of its fields change.

## License

MIT
