# Key store: implementing core.KeyEngine

The key store keeps, per (namespace, key ID), the key bytes it is given, a
state, and the time the key was disabled. With a key wrapper in front, the
bytes are wrapped keys: the store never needs to know.

## Data model

One record per (namespace, key ID):

| Field | Meaning |
|---|---|
| `namespace`, `key_id` | Primary key. Always filter on both |
| `state` | `ACTIVE`, `DISABLED` or `DELETED`. `UNKNOWN` is never stored |
| `key` | The bytes given by `GetOrCreateKeys`' KeyGen. Empty once deleted |
| `disabled_at` | Set by the first `DisableKey`; cleared by `ReEnableKey` |

SQL sketch:

```sql
CREATE TABLE privacy_keys (
  namespace   TEXT NOT NULL,
  key_id      TEXT NOT NULL,
  state       TEXT NOT NULL CHECK (state IN ('ACTIVE','DISABLED','DELETED')),
  key         BLOB,
  disabled_at INTEGER,          -- Unix milliseconds, NULL unless DISABLED
  PRIMARY KEY (namespace, key_id)
);
```

## Effective state: enforce the deadline on read (R-KE-6)

Compute the state every method sees, on every read, before acting:

```go
func effective(r record, now time.Time, grace time.Duration) core.KeyState {
    if r.State == core.StateDisabled && now.Sub(r.DisabledAt) >= grace {
        return core.StateDeleted // past the deadline, whether or not a job ran
    }
    return r.State
}
```

Use it in `GetKeys`, `GetOrCreateKeys`, `DisableKey` and `ReEnableKey`. A key
whose deadline passed must read `DELETED` and refuse `ReEnableKey`, even if
its material is still stored. Store times with at least millisecond
precision: whole seconds shorten a 2-second test grace period by up to half.

An `ACTIVE` record without key bytes cannot happen in a correct store. Treat
it as corruption and return an error wrapping `core.ErrGetKeyFailure`; do not
guess a state.

## GetKeys (R-KE-1, R-KE-2)

- Every requested ID lands in exactly one map: `keys` for `ACTIVE`, else
  `missing` with `DISABLED`, `DELETED`, or `UNKNOWN` when no record exists.
- `nil` or empty `keyIDs`: return two empty maps, no error.
- Return **copies** of key bytes (`bytes.Clone`): the caller zeroes them.

## GetOrCreateKeys: atomic creation (R-KE-3, R-KE-4)

Concurrent callers, in any process, must all get the one stored key. Never
read-then-write. Insert conditionally, then read what is stored:

```sql
INSERT INTO privacy_keys (namespace, key_id, state, key)
VALUES (?, ?, 'ACTIVE', ?)
ON CONFLICT (namespace, key_id) DO NOTHING;      -- Postgres, SQLite
-- MySQL: INSERT IGNORE; DynamoDB: PutItem with ConditionExpression attribute_not_exists(pk)
SELECT state, key, disabled_at FROM privacy_keys WHERE namespace = ? AND key_id = ?;
```

- Call `keyGen(ctx, namespace, keyID)` only for IDs without a record, and
  store exactly the bytes it returns.
- Return the **stored** key, never the generated one when the insert lost a
  race: a key that was not stored encrypts data nobody can read again.
- IDs whose effective state is `DISABLED` or `DELETED` are left out of the
  result, never recreated (R-KE-4).
- `keyGen` may be nil: fall back to `aes.Key256GenFn`.

## DisableKey, ReEnableKey (R-KE-5)

- Unknown or (effectively) deleted ID: return `core.ErrKeyNotFound`
  (wrapping is fine) and write nothing.
- `DisableKey` on a disabled key: no-op. **Keep the first `disabled_at`**: a
  second call must not restart the grace period. Use a conditional update
  (`WHERE state = 'ACTIVE'`).
- `ReEnableKey` on an active key: no-op; on a disabled key within the grace
  period: `ACTIVE`, clear `disabled_at`.

## Deleting material (R-KE-7, R-KE-8, R-KE-9)

- `DeleteKey`: state `DELETED`, **erase the key bytes** (set the column to
  NULL, remove the attribute). Keep the record: a deleted ID must read
  `DELETED` and never be recreated. Unknown ID: return nil, write nothing.
- `DeleteUnusedKeys`: delete the material of every key disabled for the
  grace period or longer; idempotent.
- `PurgeNamespace`: remove **every record** of the namespace, deleted ones
  included; idempotent; purged IDs then read `UNKNOWN` and may be created
  again.
- With a storage TTL instead of a job: keep the material in its own
  record or attribute that expires, so the `DELETED` marker survives, and
  still enforce the deadline on read (TTLs fire late). Declare
  `ErasesWithoutJanitor` in the suite.

`KeyMaterialProbe` for the suite reads storage directly:

```go
func ProbeKeyMaterial(db *sql.DB) func(ctx context.Context, ns, id string) (bool, error) {
    return func(ctx context.Context, ns, id string) (bool, error) {
        var n int
        err := db.QueryRowContext(ctx,
            `SELECT COUNT(*) FROM privacy_keys WHERE namespace=? AND key_id=? AND key IS NOT NULL`, ns, id).Scan(&n)
        return n > 0, err
    }
}
```

## Isolation and reporting (R-KE-10, R-KE-11)

- Every query filters on `namespace`. One key ID in two namespaces is two
  unrelated keys.
- Implement `core.GracePeriodReporter`: `func (e *Engine) GracePeriod() time.Duration`.
  Audit events use it to state when erasure is final.

## SQLite

SQLite allows one writer at a time; without settings, concurrent conditional
writes fail with `SQLITE_BUSY` instead of waiting, and R-KE-3 or R-TE-2
fails under `-race`. With the pure-Go driver `modernc.org/sqlite`, open with
`?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_txlock=immediate`,
so writers wait and transactions take the write lock up front. Postgres and
MySQL need no such setting.

## Errors and secrets

- Wrap storage failures with the core sentinels, e.g.
  `fmt.Errorf("%w: %w", core.ErrGetKeyFailure, err)`.
- Never put key bytes in errors or logs. `core.Key` redacts itself in fmt
  and slog; a raw `[]byte` does not.
