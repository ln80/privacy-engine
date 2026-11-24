# Token vault: design and storage contract

| | |
|---|---|
| Code | `vault.go` (flows), `vault_crypto.go` (keys, blind index, sealing), `core/token_engine.go` (storage contract), `memory/token_engine.go` (in-memory store) |
| Conformance | `privacytest.RunTokenEngineTest`: every `core.TokenEngine` must pass it |
| Format | Sealed values start with the format and algorithm byte `0x01` |

## 1. What the vault is

The token vault maps a personal value (an email, say) to a random pseudonym
such as `sub_3f2c…`. Downstream code stores and passes the token; only a
caller that can detokenize sees the value again.

In GDPR terms the vault is the *additional information* of Art. 4(5): it must
be kept separately and protected by its own measures. Pseudonymised data is
still personal data (EDPB Guidelines 01/2025).

A token is usually also a **subject ID**: data about the person is encrypted
under the token's own key, so `Forget(token)` shreds both the data and the
vault entry (section 5).

## 2. Principles

1. **Storage never sees a value in clear.** The `Protector` seals each value
   and computes its lookup key; a `TokenEngine` stores opaque bytes.
2. **Lookups by key, never by range or search.** A value is found through its
   blind index, a token by its ID. There is no search on values.
3. **One value, one live token.** The store enforces it: creating a token is
   conditioned on both the token and the value's index being free.
4. **Tokens are random.** `TokenGenFunc` never receives the value, so a token
   cannot be a hash of it (hashed emails can be reversed by brute force).
5. **Erasure follows the key lifecycle.** A forgotten token is hidden at once
   and its value removed when the grace period ends, or at once in immediate
   mode.

## 3. Cryptography

### 3.1 One key per namespace, two derived keys

```
vaultKey = the namespace's DEK under the reserved ID "@vault"   (KeyEngine.GetOrCreateKeys)
indexKey = HKDF-SHA256(vaultKey, info = "privacy-engine/vault/index/v1")
sealKey  = HKDF-SHA256(vaultKey, info = "privacy-engine/vault/value/v1")
```

- `@vault` is created the first time a namespace tokenizes and is deleted only
  by `PurgeNamespace`. IDs starting with `@` are reserved: the `Protector`
  refuses them as subject IDs and tokens, so `Forget` never reaches it.
- Separate HKDF labels keep the two uses apart: the index key never encrypts,
  the seal key never hashes.
- Each `Tokenize`, `Detokenize` or `ListTokens` call reads the vault key once,
  however many tokens it handles; none when the protector's cache holds it.

### 3.2 Blind index and sealed value

```
index  = HMAC-SHA256(indexKey, value)                                         32 bytes
sealed = 0x01 | nonce (12) | AES-256-GCM(sealKey, nonce, value, aad)
aad    = "privacy-engine/vault/v1" | 0x01 | len16(namespace) | namespace | len16(token) | token
```

- **A keyed index, not a plain hash.** Emails are guessable: with a plain
  SHA-256, anyone holding the store could hash candidate emails and match them.
- **The exact bytes are hashed.** Normalising values (case, whitespace) is the
  caller's job, before `Tokenize`. The vault never stores a normalised copy.
- **The token is bound in the AAD.** All tokens of a namespace share one seal
  key, so without this binding someone with write access could move one
  person's sealed value onto another's token. A moved value fails to open.
- **The namespace is bound in the AAD and in the key.** A value copied into
  another namespace fails to open.
- **What the index reveals:** that two records of one namespace hold the same
  value, which is the deterministic behaviour `Tokenize` promises. Nothing
  links namespaces.

### 3.3 What sealing protects, by key engine

The vault is as strong as the key engine that holds `@vault`:

| Key engine | What sealing achieves |
|---|---|
| Keys wrapped by a KMS or HSM (a key encryption key the store cannot read) | A reader of the vault storage without decrypt rights on the wrapping key sees tokens and ciphertext only: console users, exports, stream consumers, a backup restored elsewhere. Restricting those rights to the runtime that detokenizes is the pseudonymisation boundary |
| Keys stored unwrapped next to the vault | **Not a security boundary.** Whoever reads the vault can read the key. Values are only kept out of keys, indexes and cursors |
| `memory` | Tests |

## 4. Records and states

A `core.VaultRecord` holds the token, its `Index`, its `Sealed` value, a
`State` and two timestamps. A store also keeps an index entry mapping
`Index` to the token while the record is active.

| State | Index entry | Sealed value | `Detokenize` | `ListTokens` |
|---|---|---|---|---|
| `ACTIVE` | present | present | value | value |
| `FORGOTTEN` | removed | kept for `Recover` | omitted | listed, no value |
| `ERASED` | removed | deleted | omitted | listed, no value |

## 5. Operations

**Tokenize(values).** Compute each value's index and look them up in one
call. A hit returns its token. For a miss, generate a token, seal the value
for it and `Insert` record and index entry atomically:

- the token already exists (a generator collision): retry with a new token,
  up to 5 times;
- the index already points to another token (a concurrent `Tokenize` of the
  same value won): return that token.

No subject key is created: a token gets one only when data is encrypted under it.

**Detokenize(tokens).** Get the records, open each active one. A sealed value
that does not authenticate is an error. Unknown, forgotten and erased tokens
are omitted.

**ListTokens(query).** A page of records in token order, by prefix. The
cursor is the last token, which is pseudonymous. Active records carry their
value; others carry only their state, so an operator can see that a subject
was forgotten without seeing who.

**Forget(id).** When a token engine is configured, `Protector.Forget` also
acts on the vault entry of `id`, if there is one:

| Mode | Vault entry |
|---|---|
| Graceful (default) | `FORGOTTEN`: the index entry is removed (if it still points to this token) and the sealed value kept until the grace period ends |
| Immediate (`GracefulMode = false` or `Immediately()`) | `ERASED`: sealed value and index entry deleted |

Removing the index entry means the value no longer finds the token, so a
person tokenized again gets a **new** token that cannot be linked to the old
one, and their new data encrypts normally. `Forget` returns `ErrKeyNotFound`
only when the ID has neither a key nor a vault entry.

**Recover(id).** Re-enables the key and makes a forgotten entry active again.
Its index entry is recreated unless a newer token took the value meanwhile:
the old data is then recovered, and the value stays with the newer token. An
erased entry cannot be recovered.

**Erasure after the grace period.** `TokenEngine.EraseForgotten(ns, before)`
erases every record forgotten before the cutoff; run it with
`now − grace period` next to `KeyEngine.DeleteUnusedKeys`. A store may also
erase by itself (a storage TTL, for example); it must then report a record
forgotten longer than the grace period as `ERASED`, and refuse to restore it,
even before the physical deletion.

**DeleteToken(token).** Deletes the record and its index entry (if it still
points to this token). It does not touch keys: erasing a person is
`Forget`'s job; call `Forget` first if both are wanted.

**PurgeNamespace.** Deletes every record and index entry. The key engine's
purge deletes `@vault` with the other keys.

## 6. Contract for a `TokenEngine`

A backend implements `core.TokenEngine`, meets requirements R-TE-1 to R-TE-7
in [implementing-backends.md](implementing-backends.md#4-token-store-coretokenengine)
and passes `privacytest.RunTokenEngineTest`.

## 7. Limits and accepted risks

| Item | Why it is accepted |
|---|---|
| Whoever can read the vault **and** obtain `@vault` reads every value of the namespace | The same boundary as for all encrypted data: storage access plus the key. With a wrapped key engine, the wrapping key's policy is the control |
| Without a key wrapper, sealing is not a boundary | Section 3.3 |
| Backups keep sealed values, and a copy of `@vault` if keys are backed up with them, until their retention expires | Erasure from backups is bounded by backup retention; document it in your deployment |
| The index shows equal values within a namespace | Inherent to deterministic tokenization |
| One token domain per namespace | The same value gets the same token everywhere in a namespace. Use separate namespaces where two contexts must not be linkable |
| No rotation of `@vault` | Rotation re-seals and re-indexes the namespace; it is designed with key versions later |
