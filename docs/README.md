# Documentation

These files ship with the module. In a project that depends on it they are at
`$(go env GOMODCACHE)/github.com/ln80/privacy-engine@<version>/docs/`, so a
coding agent can read the version actually in use.

| Document | Read it to |
|---|---|
| [architecture.md](architecture.md) | Learn the scope, non-goals and guaranteed requirements (R-CS, R-TK, R-AU) |
| [threat-model.md](threat-model.md) | See what is protected against whom, and what is not |
| [key-lifecycle.md](key-lifecycle.md) | Follow keys and tokens through their states, the erasure timeline, and the rotation limitation |
| [implementing-backends.md](implementing-backends.md) | Build a key store, key wrapper or token store (R-KE, R-KW, R-TE, R-EN) |
| [production.md](production.md) | Deploy, configure, back up and monitor |
| [wire-format-v2.md](wire-format-v2.md) | Parse or produce encrypted values and streams; versioning guarantees |
| [token-vault.md](token-vault.md) | Understand tokenization's cryptography and flows |
| [audit-events.md](audit-events.md) | Record erasure and re-identification |

## By task

| Task | Read, in order |
|---|---|
| Encrypt and shred data in an application | Root README, architecture §2, production |
| Build a production backend | architecture §3, implementing-backends, key-lifecycle, then the `privacytest` suite |
| Review security | threat-model, architecture §2, wire-format-v2, token-vault, [SECURITY.md](../SECURITY.md) |

## Conventions

- **Requirement IDs** (`R-KE-3`) are stable. Conformance tests and issues cite
  them; a requirement that is dropped keeps its ID retired.
- **Normative** documents state what code must do. When code and a normative
  document disagree, one of them has a bug: report it.
