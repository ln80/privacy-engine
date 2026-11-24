# Threat model

| | |
|---|---|
| Status | **Normative.** Not independently reviewed ([SECURITY.md](../SECURITY.md#security-status)) |
| Assumes | Wrapped keys and separate stores ([architecture.md](architecture.md#3-components)) |

## 1. Assets

| Asset | Where |
|---|---|
| Personal data | Data store, as `ENC.` values and streams |
| DEKs | Key store (wrapped); process memory (plaintext, cached) |
| KEK | KMS or HSM only |
| Token vault | Token store: sealed values, blind index |
| Subject IDs, tokens | In clear in records, key IDs, KMS logs; pseudonymous by rule |
| Audit trail | Your sink |

## 2. Threats

| ID | Threat | Mitigation | Residual |
|---|---|---|---|
| T1 | Copy of the data store (backup, injection, snapshot) | Application-level encryption (§3) | Which records share a subject |
| T2 | DBA with the key store | Wrapped DEKs; no unwrap rights (R-KW-2, §4); blobs unforgeable without KMS rights (R-KW-7) | **Everything, if DEKs are stored unwrapped** |
| T3 | Admin with KMS **and** store rights | Separation of duties, KMS policy and logs | A deployment flaw |
| T4 | Compromised application | Narrow roles with separate credentials, short cache TTL, per-tenant KEKs | Out of scope (§5) |
| T5 | Write access to data | Authenticated encryption, namespace in AAD (R-CS-7, 8) | Swapping two values of one subject ([wire-format.md](wire-format.md#7-accepted-risks)) |
| T6 | Backend returns the wrong key | Namespace in AAD; wrapper binds namespace and key ID (R-KW-1) | None: detected |
| T7 | Erasure not taking effect | Deadline checked on read (R-KE-6), cache TTL (R-CS-4), material removed (R-KE-7) | Key store backups until expiry ([production.md](production.md#backups)) |
| T8 | Insider re-identifying | Audit, fail closed (R-AU), `Reidentifier` for few services | Detected, not prevented |
| T9 | Linking records | Random tokens, keyed index (R-TK-1, 3) | Equal values share a token in a namespace: split namespaces that must not link |
| T10 | Brute-forcing tokens or index | Random tokens; HMAC keyed by `@vault` | Needs `@vault` (T2, T3) |
| T11 | Malformed input | Strict parsers, bounded segments, fuzzing | Report via [SECURITY.md](../SECURITY.md) |
| T12 | Secrets in logs | Self-redacting types, value-free errors (R-CS-9) | Your own logging of decrypted data |

## 3. Encryption at rest is not enough

Disk or database encryption protects against stolen disks. The database
decrypts for every authorized query, so it does **not** protect against
DBAs, injection, exports, replicas or restored backups, and it cannot erase
one subject. Application-level encryption covers all of these. Keep both on.

## 4. Separation of duties

Only the application runtime holds all three rights. Nobody else holds two.

| Principal | Data store | Key store | KMS unwrap |
|---|---|---|---|
| Application | read, write | read, write | scoped to its keys |
| DBA, operator | yes | yes | **no** |
| KMS administrator | no | no | policy only; unwrap by break-glass |
| Erasure job | no | delete | no |

Key store access must never imply unwrap rights: then a key store backup is
useless without the KEK.

## 5. Out of scope

- **A compromised process**: it holds cached DEKs and can call the KMS. Limit
  the blast radius (§2 T4) and alert on unusual KMS volume.
- **Memory disclosure**: Go strings and the GC can keep plaintext copies.
- **Side channels** beyond Go's `crypto` packages.
- **Plaintext copies** the application makes.
- **Availability**: losing the KEK or key store loses the data, by design.
