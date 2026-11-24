# Key lifecycle

| | |
|---|---|
| Status | **Normative.** Backend requirements R-KE, R-TE in [implementing-backends.md](implementing-backends.md) |

## 1. Keys

| Key | ID | Created | Destroyed |
|---|---|---|---|
| KEK | Your KMS key, per deployment or tenant | By you | By you; shreds every DEK it wraps |
| Subject DEK | Subject ID | First `Encrypt` or `EncryptStream` | `Forget` (after grace), `Purge` |
| Vault key | `@vault`, per namespace | First `Tokenize` | `Purge` only |
| Derived key | – | `DeriveSubjectKey`, never stored | With its DEK, unless you stored it |

IDs starting with `@` are reserved, so `Forget` can never reach `@vault`.

## 2. DEK states

```
(no record) ── GetOrCreateKeys ──► ACTIVE ── graceful Forget ──► DISABLED
     ▲                              │   ▲                         │    │
     │                    immediate │   └──────── Recover ────────┘    │ grace
     │                       Forget ▼                                  ▼ over
     └──── PurgeNamespace ──────  DELETED ◄────────────────────────────┘
           (from any state)
```

| State | `GetKeys` | Decrypt | Next |
|---|---|---|---|
| `ACTIVE` | key | plaintext | `DISABLED`, `DELETED` |
| `DISABLED` | missing | placeholder | `ACTIVE`, `DELETED` |
| `DELETED` | missing | placeholder | none: never recreated |
| `UNKNOWN` | missing | `ErrKeyUnknown` | `ACTIVE` |

`UNKNOWN` is never stored: it means no record (never created, or purged).
A key disabled longer than the grace period reads `DELETED` at once, even
before its material is removed (R-KE-6).

## 3. Erasure timeline

`Forget` at `t0`, grace period `G`, cache TTL `C`:

| When | Effect |
|---|---|
| `t0` | This instance stops decrypting; audit event has `FinalAt = t0 + G` |
| `≤ t0 + C` | Every instance has stopped |
| `t0` – `t0 + G` | `Recover` restores key and vault entry |
| `t0 + G` | Key reads `DELETED`; material removed by job or TTL |
| Backup expiry | Last wrapped copy gone ([production.md](production.md#backups)) |

Immediate mode deletes at `t0`: `FinalAt = t0`, no `Recover`.

## 4. Vault entries

| State | Reached by | Value |
|---|---|---|
| `ACTIVE` | `Tokenize` | Sealed, indexed |
| `FORGOTTEN` | Graceful `Forget(token)` | Sealed, not indexed or revealed |
| `ERASED` | Grace over, or immediate `Forget` | Gone for good |

`Recover` re-indexes a forgotten entry unless the value got a new token
meanwhile. `DeleteToken` removes an entry. See [token-vault.md](token-vault.md).

## 5. Rotation: not supported

Neither DEKs nor `@vault` rotate. Values carry an authenticated
`keyVersion = 1`, so rotation can come without a format change.

| Need | Do |
|---|---|
| Rotate the KEK | Use KMS rotation or re-wrap the DEKs. Data is untouched |
| A DEK is exposed | `Forget` immediately, re-encrypt under a new subject ID |
| `@vault` is exposed | Tokenize into a new namespace, `Purge` the old one |
