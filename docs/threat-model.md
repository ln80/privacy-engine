# Threat model

| | |
|---|---|
| Status | **Normative** for v0.x. Not independently reviewed ([SECURITY.md](../SECURITY.md#security-status)) |
| Assumes | The deployment in [architecture.md](architecture.md#3-components): envelope-wrapped keys, separate stores |

## 1. Assets

| ID | Asset | Where it lives |
|---|---|---|
| A1 | Personal data in records | Data store, as `ENC.` field values and streams |
| A2 | DEKs | Key store (wrapped), process memory (plaintext, cached) |
| A3 | KEK | KMS or HSM only |
| A4 | Token vault: sealed values, blind index | Token store |
| A5 | Subject IDs and tokens | In clear in records, values, key IDs, KMS logs. Pseudonymous by rule |
| A6 | Audit trail | Your audit sink |

## 2. Threats

| ID | Adversary or failure | Gets | Mitigation | Residual |
|---|---|---|---|---|
| T1 | Copy of the data store (leaked backup, injection, snapshot) | Ciphertext and subject IDs | Application-level encryption (§3) | Which records belong to the same subject |
| T2 | DBA or operator with the key store | Wrapped DEKs | Envelope encryption: unwrapping needs KMS rights the DBA lacks (R-KW-2) | None, if duties are separated (§4). **With unwrapped keys in the store, T2 reads everything** |
| T3 | Cloud admin with KMS **and** store rights | Everything | Separation of duties, KMS key policy, KMS audit logs | Accepted: one principal holding both is a deployment flaw |
| T4 | Compromised application process or credentials | What the application can decrypt | Least privilege per service (role interfaces plus separate credentials), short cache TTL, per-tenant KEKs | Out of scope (§5) |
| T5 | Write access to the data store | Can alter values | Authenticated encryption, namespace in AAD (R-CS-7, 8) | Swapping two values of the same subject goes undetected ([wire-format.md](wire-format.md#7-accepted-risks-and-limits)) |
| T6 | Buggy or hostile backend returning the wrong key | Wrong-key decryption attempts | AAD binds the namespace; the wrapper binds namespace and key ID (R-KW-1) | Detected, never silent |
| T7 | Erasure that does not take effect | Data still readable after `Forget` | Reads enforce the grace deadline (R-KE-6), cache TTL bounds other instances (R-CS-4), material is removed, not flagged (R-KE-7) | Key store backups until their retention ends ([production.md](production.md#backups)) |
| T8 | Insider abusing re-identification | Values behind tokens | Audit events, fail closed on audit failure (R-AU-1, 2), `Reidentifier` given to few services | Detection, not prevention |
| T9 | Linking records | Equality of values within a namespace | Random tokens (R-TK-1), keyed index (R-TK-3), one token domain per namespace | Inherent to deterministic tokenization: use separate namespaces for contexts that must not link |
| T10 | Guessing values from tokens or index | Offline brute force | Tokens are random; the index is an HMAC keyed by `@vault` | Needs `@vault`, which is T2/T3 |
| T11 | Malformed or hostile input | Crash, hang, memory blow-up | Strict parsers, bounded stream segments, fuzzing | Under test, see [SECURITY.md](../SECURITY.md) to report |
| T12 | Secrets leaking into logs | Keys or values in logs | Self-redacting types, value-free errors (R-CS-9) | Your own logging of decrypted structs |

## 3. Database encryption at rest is not enough

Storage encryption (disk, TDE, managed-database encryption) protects against
stolen disks. The database decrypts transparently for every query it
authorizes, so it does **not** protect against:

- an operator, DBA or support engineer with query access;
- an application bug or injection that reads more than it should;
- exports, replicas, snapshots and backups restored elsewhere;
- erasure: you cannot shred one subject out of an encrypted volume.

Application-level encryption keeps data encrypted in every one of those
places, and the DEK per subject is what makes crypto-shredding possible. Keep
storage encryption on as well: the two are complementary.

## 4. Separation of duties

No single principal should hold two of these three:

| Principal | Data store | Key store | KMS unwrap |
|---|---|---|---|
| Application runtime | read, write | read, write | yes, scoped to its keys |
| DBA, operator | yes | yes | **no** |
| KMS administrator | **no** | **no** | manages policy; unwrap only through break-glass |
| Erasure job | no | write (delete) | no |
| Re-identification service | no | read | yes, `@vault` keys only, where the KMS can scope it |

Database administrators should not automatically get access to encryption
material: key store access must not imply unwrap rights, and backups of the
key store are only useful together with the KEK.

## 5. Out of scope

- **A compromised running process.** It holds plaintext DEKs in its cache and
  can call the KMS. Limit the blast radius: one service per role, short cache
  TTL, per-tenant KEKs, alerting on unusual KMS volume.
- **Memory disclosure.** The library wipes its own key and plaintext buffers,
  but Go strings and the garbage collector can leave copies.
- **Side channels** beyond what Go's `crypto` packages already address.
- **Plaintext copies** the application makes: logs, caches, search indexes,
  analytics, message queues.
- **Availability.** Losing the KEK or the key store loses the data, by design.
