# API stability

The Go API follows [semantic versioning](https://semver.org). Before v1.0,
minor releases may break it; from v1.0, only a major release does. Stored
formats version separately ([wire-format.md §8](wire-format.md#8-versioning-and-compatibility)).

## What the promise covers

Every exported identifier of `privacy`, `core`, `aes`, `envelope`, `memory`
and `privacytest`. Not covered: `internal/`, error message text, and the
order of map iterations and unsorted slices.

## Rules

1. **Interfaces you implement never gain methods.** `core.KeyEngine`,
   `core.TokenEngine`, `core.KeyWrapper`, `core.Encryptor` and
   `privacy.Auditor` are frozen. A new capability comes as a new, optional
   interface that the library detects at run time, as `core.GracePeriodReporter`
   does. An implementation that does not have it keeps working.
2. **Interfaces you consume may gain methods.** The role interfaces
   (`privacy.Encrypter`, `Shredder`, `Tokenizer`, `Reidentifier`) describe the
   `Protector`; do not implement them outside tests.
3. **Options are opaque.** `ProtectorOption`, `FactoryOption`,
   `ForgetOption` and `TokenizeOption` are built by their `With*` functions;
   the config they set is not exported. New options may be added.
4. **Structs may gain fields.** `privacy.AuditEvent`, `core.VaultRecord`, the
   `privacytest` configs and the list results may grow. Use field names in
   composite literals.
5. **Errors are matched with `errors.Is` or `errors.As`**, never by message.
   The sentinels and `core.IndexTakenError` keep their meaning.
6. **Conformance suites are pinned to requirements.** A release may add a
   subtest for a new requirement only behind a new optional interface or a
   new config field that defaults to skipping it. A backend that passed keeps
   passing.

## Later additions

Rules 1 and 6 leave room for what v1 does not do. Key rotation, if it comes,
would be an optional key engine interface for versioned keys; `keyVersion`
is already in every value ([key-lifecycle.md §5](key-lifecycle.md#5-rotation-not-supported)).
