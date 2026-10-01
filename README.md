# Second-order SQL Injection Test Case (C# / SQL Server)

Deliberately vulnerable sample for exercising SAST scanners and demonstrating
a **second-order SQL injection via nested dynamic SQL inside T-SQL `EXEC()`**.

## The Vulnerability

This is nested dynamic SQL: the outer statement is already built unsafely by
`string.Format()`, and it in turn constructs a second SQL string executed via SQL
Server's `EXEC()`. A `schemaName` containing a single quote can both break the outer
literal and inject arbitrary T-SQL that is executed inside the `EXEC()` call — one of
the most dangerous unescaped-input patterns, hence the elevated severity.

## Files

| File | Purpose |
| --- | --- |
| `TenantSchemaRepository.cs` | **Vulnerable.** Stage 1 stores `schemaName` safely; stage 2 reads it back and concatenates it into nested T-SQL `EXEC()` strings via `string.Format()`. |
| `TenantSchemaRepository_Fixed.cs` | Remediated: allow-list validation + server-side `QUOTENAME()` via `sp_executesql`. |
| `TenantSchemaRepositoryTests.cs` | xUnit tests demonstrating the trigger and verifying the fix. |

## The Two Stages

### Stage 1: Store (Safe)
```csharp
repo.RegisterTenant("tenant1", schemaName);
```
Uses a fully parameterized query. The `schemaName` is inserted safely. Nothing executes.

### Stage 2: Trigger (Vulnerable)
```csharp
repo.GetTenantRows("tenant1");
```
Reads the stored `schemaName` back (still safe) but then concatenates it into an
unsafe nested dynamic SQL string:

```csharp
string outerSql = string.Format(
    "IF NOT EXISTS (SELECT 1 FROM sys.schemas WHERE name = '{0}') " +
    "EXEC('SELECT * FROM [{0}].Orders')",
    schemaName);
```

Because object identifiers (schema names, table names) cannot be parameterized in SQL
Server, developers concatenate them — which is exactly what makes `schemaName` a viable
injection vector.

## Payload

```
dbo].Orders; DROP TABLE Audit; --
```

### What Happens

The single quote in the payload breaks out of the inner `EXEC` string literal:

```sql
IF NOT EXISTS (SELECT 1 FROM sys.schemas WHERE name = 'dbo'].Orders; DROP TABLE Audit; --') 
EXEC('SELECT * FROM [dbo'].Orders; DROP TABLE Audit; --].Orders')
```

Inside the `EXEC()` call, the quote has already broken the outer layer. The attacker's
`DROP TABLE` runs, and the trailing `--` comment removes the malformed remainder.

## The Fix

Object identifiers cannot be parameterized, so the fix uses three layers:

1. **Allow-list validate** — Reject anything that is not a plain identifier: `^[A-Za-z_][A-Za-z0-9_]{0,127}$`
2. **Re-validate on the way OUT** — Do not trust a value just because it was read from the database
3. **Server-side escaping** — Use `QUOTENAME()` inside `sp_executesql()` so the identifier is escaped by SQL Server:

```csharp
string safeSql = @"
    DECLARE @query NVARCHAR(MAX) = 
        N'SELECT * FROM ' + QUOTENAME(@schema) + N'.Orders';
    EXEC sp_executesql @query;
";
cmd.Parameters.AddWithValue("@schema", schemaName);
```

The `@schema` parameter is only ever used inside `QUOTENAME()`, never concatenated.
`QUOTENAME()` wraps the identifier in square brackets and doubles any internal brackets,
preventing escape.

## Run Tests

```bash
dotnet test
```

The tests demonstrate:
- The vulnerable path building nested injected `EXEC()` statements
- The fixed path rejecting payloads at validation
- Valid schema names working correctly with `QUOTENAME()` and `sp_executesql`

## References

- **CWE-89**: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')
- **CWE-94**: Improper Control of Generation of Code ('Code Injection')
- **OWASP**: Second Order SQL Injection
- **SQL Server Docs**: [QUOTENAME](https://learn.microsoft.com/en-us/sql/t-sql/functions/quotename-transact-sql)
- **SQL Server Docs**: [sp_executesql](https://learn.microsoft.com/en-us/sql/relational-databases/system-stored-procedures/sp-executesql-transact-sql)
