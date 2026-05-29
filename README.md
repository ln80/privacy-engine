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
| `subjectID` | Identifies the data subject (one per struct) | `pii:"subjectID"` |
| `data` | Marks a field as sensitive | `pii:"data"` |
| `data,replace=X` | Replacement value when the subject is forgotten | `pii:"data,replace=deleted"` |
| `dive` | Recurse into nested structs | `pii:"dive"` |

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
- **Encryptor** handles the actual encryption. Default: AES-256-GCM with random nonces and namespace-bound AAD.
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
// encReader emits authenticated ciphertext in 4MB chunks

decReader, _ := protector.DecryptStream(ctx, "user-123", encReader)
// decReader emits the original plaintext
```

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
ENC.<version>.<base64(subjectID)>.<base64(ciphertext)>
```

The `ENC.` prefix is used for idempotency detection (fields already encrypted are not re-encrypted). Legacy `<pii:...` format is accepted during decryption for backward compatibility.

## License

MIT
