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

## Bind every wrapped key to its namespace and key ID (R-KW-1, R-KW-5)

A wrapped DEK must unwrap only for the namespace and key ID it was generated
for. Use the KMS's authenticated context, never a plain parameter:

- **AWS KMS:** `GenerateDataKey` with `KeySpec: AES_256` and an
  `EncryptionContext`; `Decrypt` with the same `EncryptionContext` and the
  `KeyId`. Example context: `{"v": "1", "ns": namespace, "sid": keyID}`.
- **Other KMSs and HSMs:** use their associated-data parameter for
  encrypt/wrap and decrypt/unwrap. Check the provider's documentation for
  it. If the KMS offers no authenticated context, stop and tell the user:
  the binding cannot be enforced, and R-KW-1 cannot pass.

Version the binding (the `"v"` entry). Changing its layout makes every stored
key unreadable; a new layout needs a new version and a re-wrap migration.

## Generate keys in the KMS or with crypto/rand (R-KW-3)

- Prefer the KMS's data-key generation (AWS `GenerateDataKey`).
- Otherwise generate 32 bytes with `crypto/rand` and wrap them.
- Never derive a DEK from the key ID or namespace.
- Refuse a plaintext of any length other than 32 bytes, and zero it
  (`core.ZeroKey`) before returning the error.

## Unwrap fails closed (R-KW-2, R-KW-4)

- Return an error, and no bytes, when the KMS rejects the blob.
- Never log, return in errors or persist the plaintext.
- `privacytest.TestKeyWrapper` flips, cuts and swaps blobs. A KMS may ignore
  changes to non-secret metadata in its blob (a key reference): returning
  the original key is then acceptable, returning any other bytes is not.

## Concurrent creation is the engine's job (R-KW-6)

Do not wrap the store yourself. `envelope.NewKeyEngine(wrapper, store)` makes
the loser of a concurrent creation unwrap the stored blob instead of keeping
its own key. Run `privacytest.TestKeyEngine` on that composition.

## Testing

```go
w := mykms.NewKeyWrapper(client, kekID)
privacytest.TestKeyWrapper(t, w)                                         // R-KW-1 to 4
privacytest.TestKeyEngine(t, envelope.NewKeyEngine(w, mystore.NewKeyEngine(db)))
```

Run against the real KMS in a test account or a local emulator
(LocalStack, local-kms). `memory.NewKeyWrapper()` is a reference for tests,
not for production.

## Deployment rules (tell the user)

- Grant the application generate and decrypt rights **scoped to the
  binding** (for example an IAM condition on the namespace context key).
- Database administrators get no unwrap rights.
- KMS audit logs show the binding in clear; subject IDs must be pseudonymous.
- One KEK per tenant makes tenant offboarding one key deletion, backups
  included. Guard KEK deletion with the KMS waiting period and alerts.
