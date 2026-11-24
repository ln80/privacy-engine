# Documentation

These files ship with the module, at
`$(go env GOMODCACHE)/github.com/ln80/privacy-engine@<version>/docs/`.

| Document | For |
|---|---|
| [architecture.md](architecture.md) | Scope and guaranteed requirements |
| [threat-model.md](threat-model.md) | What is protected, against whom |
| [key-lifecycle.md](key-lifecycle.md) | Key states, erasure timeline, rotation |
| [implementing-backends.md](implementing-backends.md) | Building key stores, key wrappers, token stores |
| [production.md](production.md) | Deploying and operating |
| [wire-format.md](wire-format.md) | Encrypted value and stream formats, versioning |
| [token-vault.md](token-vault.md) | Tokenization design |
| [audit-events.md](audit-events.md) | Audit events |

Requirement IDs (`R-KE-3`) are stable and cited by the conformance tests.
Normative documents state what code must do: a mismatch is a bug.
