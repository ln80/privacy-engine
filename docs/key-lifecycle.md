# Key lifecycle

| | |
|---|---|
| Status | **Normative** |
| Contracts | `core.KeyEngine`, `core.TokenEngine`; requirements R-KE and R-TE in [implementing-backends.md](implementing-backends.md) |

## 1. Keys

| Key | ID | Scope | Created | Destroyed |
|---|---|---|---|---|
| KEK | Your KMS key | One per deployment, or per tenant | By you, in the KMS | By you; destroys every DEK it wraps |
| Subject DEK | The subject ID | One subject in one namespace | First `Encrypt` or `EncryptStream` for the subject | `Forget` (after the grace period), `Purge` |
| Vault key | `@vault` | One namespace's token vault | First `Tokenize` in the namespace | `Purge` only |
| Derived keys | – | A subject and a purpose | `DeriveSubjectKey`, never stored by the library | With their DEK, unless you stored them |

IDs starting with `@` are reserved: the protector refuses them as subject IDs
and tokens, so `Forget` can never reach `@vault`.

## 2. DEK states

```
                 GetOrCreateKeys
   (no record) ─────────────────► ACTIVE ◄──────────┐
        ▲                           │               │ Recover, within the grace period
        │                  Forget   │ Forget        │
        │              (immediate)  │ (graceful)    │
        │                     ┌─────┘     └──► DISABLED
        │                     ▼                     │ grace period over
        │                  DELETED ◄────────────────┘
        │                     │
        └─────────────────────┘  PurgeNamespace (from any state)
```

| State | `GetKeys` reports | Decrypt gives | Can become |
|---|---|---|---|
| `ACTIVE` | the key | plaintext | `DISABLED`, `DELETED` |
| `DISABLED` | missing, `DISABLED` | placeholder | `ACTIVE` (`Recover`), `DELETED` |
| `DELETED` | missing, `DELETED` | placeholder | nothing; no key is created again for the ID |
| `UNKNOWN` | missing, `UNKNOWN` | `ErrKeyUnknown` | `ACTIVE`, through `GetOrCreateKeys` |

`UNKNOWN` is never stored: it is the answer for an ID without a record, never
created or purged.

**The deadline is enforced on read.** A key disabled longer than the grace
period is reported `DELETED` and cannot be re-enabled from that moment,
whether the material was removed by a job (`DeleteUnusedKeys`) or a storage
TTL, or not yet removed at all (R-KE-6).

## 3. Erasure timeline

For `Forget(s)` at time `t0` in graceful mode, with grace period `G` and key
cache TTL `C`:

| When | Effect |
|---|---|
| `t0` | This instance stops decrypting `s`. The audit event carries `FinalAt = t0 + G` |
| `t0 + C` at most | Every instance has stopped decrypting `s` (R-CS-4) |
| `t0` to `t0 + G` | `Recover(s)` restores the key and the vault entry |
| `t0 + G` | The key is `DELETED` on every read; its material is removed by the job or the TTL |
| backup retention | The last backup holding the wrapped DEK expires ([production.md](production.md#backups)) |

Immediate mode (`Immediately()` or `WithImmediateErasure()`) deletes at
`t0`, so `FinalAt = t0` and `Recover` fails.

## 4. Token vault entries

A token follows its subject:

| Vault entry | Reached by | Value |
|---|---|---|
| `ACTIVE` | `Tokenize` | sealed, found by its index |
| `FORGOTTEN` | graceful `Forget(token)` | sealed, no longer indexed or revealed |
| `ERASED` | grace period over, or immediate `Forget` | removed; the token never resolves again |

`Recover` makes a forgotten entry active and re-indexes it unless the value
got a new token meanwhile. `DeleteToken` removes an entry outright.
[token-vault.md](token-vault.md) has the full flows.

## 5. Rotation: not supported

There is no DEK rotation and no `@vault` rotation. Every value carries
`keyVersion = 1`, authenticated, so rotation can be added without a format
change, but nothing reads another version today.

What you can do now:

| Need | How |
|---|---|
| Rotate the KEK | Use your KMS's rotation, which keeps old versions for unwrapping, or re-wrap every stored DEK under the new KEK. Data is untouched: values name their DEK, never how it is wrapped |
| A DEK is exposed | `Forget` the subject immediately, then re-encrypt its data under a new subject ID |
| `@vault` is exposed | Tokenize into a new namespace and `Purge` the old one |
| Approaching 2³² values per DEK (the random-nonce bound) | Not reachable for one person's data in practice; key versions will be the remedy |
