# Second-order SQL injection test case (pyodbc / T-SQL)

Deliberately vulnerable sample for exercising SAST scanners and demonstrating
a **second-order SQL injection via `schema_name` inside a dynamically built
T-SQL `EXEC()` string**. For testing only.

## Files

| File | Purpose |
| --- | --- |
| `tenant_store.py` | **Vulnerable.** Stage 1 stores `schema_name` safely; stage 2 reads it back and concatenates it into an `EXEC()` string. |
| `tenant_store_fixed.py` | Remediated: allow-list validation + `QUOTENAME` via `sp_executesql`. |
| `test_second_order_injection.py` | Demonstrates the trigger and verifies the fix, using a fake cursor (no live DB needed). |

## The two stages

1. **Store** — `register_tenant()` inserts the attacker's `schema_name` with a
   parameterized query. Looks harmless; nothing executes.
2. **Trigger** — `get_tenant_rows()` reads the stored value and glues it into
   `EXEC('SELECT * FROM [' + '<schema>' + '].Orders')`. Identifiers can't be
   parameterized, so the stored value is concatenated and runs.

## Payload

```
dbo].Orders; DROP TABLE Audit; --
```

Produces:

```sql
EXEC('SELECT * FROM [dbo].Orders; DROP TABLE Audit; --].Orders')
```

The `--` comments out the trailing fragment; the injected statement runs.

## Run

```bash
python -m pytest test_second_order_injection.py -v
```

## Fix

Identifiers cannot be bound as parameters, so:

- Allow-list validate (`^[A-Za-z_][A-Za-z0-9_]*$`) on the way in **and** out.
- Escape server-side with `QUOTENAME()` inside `sp_executesql`.
- Never re-trust a value just because it was read back from the database.
