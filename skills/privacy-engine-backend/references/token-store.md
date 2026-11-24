# Token store: implementing core.TokenEngine

The token store keeps the vault: one record per token, and one index entry
per active value, mapping the value's blind index to its token. It never sees
a value in clear: the Protector seals values and computes indexes.

## Data model

| Store | Key | Fields |
|---|---|---|
| Records | (namespace, token) | `index`, `sealed`, `state` (`ACTIVE`, `FORGOTTEN`, `ERASED`), `created_at`, `forgotten_at` (Unix seconds) |
| Index entries | (namespace, index) | `token` |

```sql
CREATE TABLE privacy_tokens (
  namespace TEXT NOT NULL, token TEXT NOT NULL,
  idx BLOB NOT NULL, sealed BLOB, state TEXT NOT NULL,
  created_at INTEGER NOT NULL, forgotten_at INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (namespace, token));
CREATE TABLE privacy_token_index (
  namespace TEXT NOT NULL, idx BLOB NOT NULL, token TEXT NOT NULL,
  PRIMARY KEY (namespace, idx));
```

Store `Index` and `Sealed` as opaque bytes. Look values up by `Index` only;
never derive, log or index anything from `Sealed` (R-TE-1). Return copies.

## Insert: atomic and doubly conditioned (R-TE-2)

Write the record and its index entry together or not at all, on two
conditions:

- the token is new, else return `core.ErrTokenExists`;
- the index is free, else return `&core.IndexTakenError{Token: winner}`,
  reading the winner's token from the index entry.

SQL: one transaction inserting both rows; map a primary-key conflict on
`privacy_tokens` to `ErrTokenExists` and on `privacy_token_index` to
`IndexTakenError` (then select the winner). DynamoDB: `TransactWriteItems`
with two `attribute_not_exists` conditions; inspect the cancellation reasons
to tell which one failed. Many concurrent inserts of one index must produce
exactly one winner.

## Removing index entries conditionally (R-TE-3)

`Forget`, `Erase` and `DeleteToken` delete the index entry **only if it still
points to this token**:

```sql
DELETE FROM privacy_token_index WHERE namespace = ? AND idx = ? AND token = ?;
```

After a forget, the value may have been tokenized again under a newer token;
an unconditional delete would lose the newer mapping.

## State transitions (R-TE-4)

- `Forget(token, at)`: `ACTIVE` → `FORGOTTEN` with `forgotten_at = at`,
  remove the index entry (conditionally). Already forgotten or erased:
  no-op, **keep the first time**. Unknown token: `core.ErrTokenNotFound`.
- `Restore(token)`: `FORGOTTEN` → `ACTIVE`; recreate the index entry only if
  the index is free, and report `reindexed`. Active: `(false, nil)`. Erased:
  `core.ErrTokenErased`. Unknown: `core.ErrTokenNotFound`.
- `Erase(token)`: delete `sealed`, state `ERASED`, remove the index entry
  (conditionally). Idempotent. Unknown: `core.ErrTokenNotFound`.
- `EraseForgotten(before)`: erase records forgotten **strictly before**
  `before`; return how many.
- `DeleteToken(token)`: delete the record and (conditionally) its index
  entry. Unknown: no-op.

## Grace period on read (R-TE-5)

If the store erases forgotten records by itself (a TTL), a record forgotten
for the grace period or longer must read `ERASED` with no sealed value and
refuse `Restore`, even before the TTL fires. Without a TTL, `EraseForgotten`
does the erasure and nothing more is needed. Declare `GracePeriod` in the
suite only for a store that erases by itself; it must exceed three hours,
because the suite forgets records up to two hours in the past.

## Listing and purging (R-TE-6, R-TE-7, R-TE-8)

- `ListTokens`: records whose token starts with `Prefix`, in token order,
  at most `Limit` (all when 0), strictly after `Cursor`. The returned
  `Cursor` is the page's last token when more records remain, `nil`
  otherwise. Cursors hold tokens, never values or indexes.
- `PurgeNamespace`: delete every record and index entry; idempotent.
- Every query filters on `namespace`.

## SealedProbe for the suite

```go
func ProbeSealed(db *sql.DB) func(ctx context.Context, ns, token string) (bool, error) {
    return func(ctx context.Context, ns, token string) (bool, error) {
        var n int
        err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM privacy_tokens
            WHERE namespace=? AND token=? AND sealed IS NOT NULL AND length(sealed) > 0`, ns, token).Scan(&n)
        return n > 0, err
    }
}
```
