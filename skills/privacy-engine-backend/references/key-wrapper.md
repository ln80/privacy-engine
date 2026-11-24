# Key wrapper: implementing core.KeyWrapper

A key wrapper protects data keys (DEKs) with a key encryption key (KEK) that
never leaves a KMS or HSM. Implement two methods; `envelope.NewKeyEngine`
does everything else.

```go
type KeyWrapper interface {
    GenerateKey(ctx context.Context, namespace, keyID string) (plain core.Key, wrapped []byte, err error)
    UnwrapKey(ctx context.Context, namespace, keyID string, wrapped []byte) (core.Key, error)
}
```

## Rules for every KMS

- **Symmetric KEK only (R-KW-7).** Use an AES key (or ChaCha20-Poly1305 in
  Vault). Refuse RSA or EC KEKs: anyone holding the public key and write
  access to the key store could plant a DEK of their choosing.
- **Bind every DEK to its namespace and key ID (R-KW-1).** Pass the binding
  as the KMS's authenticated context. If the wrap operation has none, wrap
  `core.BindDataKey(dek, namespace, keyID)` instead of the DEK, and open the
  unwrapped payload with `core.UnbindDataKey`; zero the payload after use.
- **Version the binding (R-KW-5)**, e.g. a `"v": "1"` context entry or the
  `BindDataKey` format. Changing it makes stored keys unreadable.
- **Generate 32-byte DEKs (R-KW-3)** with the KMS's data-key API or
  `crypto/rand`. Never derive them from IDs. Zero and refuse any other length.
- **Fail closed (R-KW-2, R-KW-4):** return an error and no bytes when the KMS
  rejects a blob; never log, persist or return the plaintext in errors.
- **Own the blob format.** `wrapped` is opaque to the library: prefix it
  with a format byte and any metadata the KMS needs to unwrap (a key
  version), and keep that format stable.
- **Map namespaces to KEKs** if tenants need separate keys: the wrapper
  receives the namespace on every call.

## AWS KMS

- KEK: symmetric KMS key (`SYMMETRIC_DEFAULT`).
- Generate: `GenerateDataKey` with `KeySpec: AES_256` and
  `EncryptionContext: {"v": "1", "ns": namespace, "sid": keyID}`; return
  `Plaintext` and `CiphertextBlob`.
- Unwrap: `Decrypt` with the same `EncryptionContext` and the `KeyId`.
- Permissions can be conditioned on the encryption context
  (`kms:EncryptionContext:ns`), so one KEK can serve several tenants with
  per-tenant rights.

## HashiCorp Vault Transit

- KEK: a transit key of type `aes256-gcm96` (or `chacha20-poly1305`); not an
  RSA key type (R-KW-7).
- Generate: 32 bytes from `crypto/rand`, then `POST transit/encrypt/<key>`
  with base64 `plaintext` and base64 `associated_data` = the binding (for
  example `"v1|" + len-prefixed namespace and keyID`). The `datakey`
  endpoint takes no associated data, so do not use it for bound DEKs.
- Unwrap: `POST transit/decrypt/<key>` with the `ciphertext` and the same
  `associated_data`. The ciphertext (`vault:vN:...`) carries the key version.
- Permissions: ACL policies per key path (`transit/encrypt/<key>`,
  `transit/decrypt/<key>`); restricting by associated data is not
  documented, so use one key per tenant where tenants need separate rights.
- Rotation: `transit/keys/<key>/rotate`; old versions keep decrypting.
  Deleting a key requires `deletion_allowed` on its config.

## Google Cloud KMS

- KEK: a symmetric `ENCRYPT_DECRYPT` crypto key.
- Generate: 32 bytes from `crypto/rand` (Google's envelope-encryption
  guidance), then `Encrypt` on the crypto key with `plaintext` and
  `additionalAuthenticatedData` = the binding.
- Unwrap: `Decrypt` on the crypto key (not a version: Cloud KMS picks it)
  with the same `additionalAuthenticatedData`.
- Permissions: `roles/cloudkms.cryptoKeyEncrypterDecrypter` on the key or key
  ring; conditions on the associated data are not documented, so use one key
  per tenant where tenants need separate rights.
- Destroying a key version is scheduled (30 days by default) and can be
  cancelled until then.

## Azure Key Vault and Managed HSM

- KEK: an AES key (`oct-HSM`). It requires **Key Vault Premium or Managed
  HSM**: Key Vault Standard only offers RSA keys, which R-KW-7 refuses.
- Associated data is not documented for the key-wrap algorithms, so bind
  with the helper: `wrapKey` with algorithm `A256KW` on the 64-byte
  `core.BindDataKey` payload (a multiple of 8 bytes, as AES key wrap needs).
- Generate: 32 bytes from `crypto/rand`; Key Vault has no data-key API.
- Unwrap: `unwrapKey` must name the key **version**. `wrapKey` returns it in
  `kid`: store it in your blob format, then `core.UnbindDataKey` the result.
- Permissions: Managed HSM roles can be assigned per key; Key Vault roles
  apply to a whole vault, so use a vault per tenant where tenants need
  separate rights.

## Concurrent creation is the engine's job (R-KW-6)

Do not wrap the store yourself. `envelope.NewKeyEngine(wrapper, store)` makes
the loser of a concurrent creation unwrap the stored blob instead of keeping
its own key. Run `privacytest.TestKeyEngine` on that composition.

## Testing

```go
w := mykms.NewKeyWrapper(client, kekID)
privacytest.TestKeyWrapper(t, w) // R-KW-1 to 4
privacytest.TestKeyEngine(t, envelope.NewKeyEngine(w, mystore.NewKeyEngine(db)),
    func(c *privacytest.KeyEngineTestConfig) { /* same options as the store */ })
```

Run against the real KMS in a test account or an emulator (LocalStack or
local-kms for AWS, a Vault dev server). A KMS may ignore changes to
non-secret metadata in its blob (a key reference): `TestKeyWrapper` accepts
the original key in that case, never other bytes. R-KW-7 is not tested:
check the KEK's key type yourself. `memory.NewKeyWrapper()` is a reference
for tests, not for production.

## Deployment rules (tell the user)

- Scope the application's KMS rights to the binding where the KMS allows it
  (AWS), otherwise to per-tenant keys.
- Database administrators get no unwrap rights.
- KMS audit logs may show the binding; subject IDs must be pseudonymous.
- One KEK per tenant makes tenant offboarding one key deletion, backups
  included. Guard deletion with the KMS's waiting period and alerts.
- Rotating the KEK keeps old versions decrypting; the library has no job to
  re-wrap stored DEKs.
