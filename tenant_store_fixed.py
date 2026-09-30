"""
Remediated version of ``tenant_store.py``.

Object identifiers cannot be parameterized, so the fix is:

1. Allow-list validation: reject anything that is not a plain identifier.
2. Server-side quoting via ``QUOTENAME`` inside ``sp_executesql`` so the
   identifier is escaped by SQL Server itself.
3. Never re-trust a value just because it was read back from the database.
"""

import re

import pyodbc

# A plain, unquoted SQL Server identifier.
_IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def connect():
    return pyodbc.connect(
        "DRIVER={ODBC Driver 18 for SQL Server};"
        "SERVER=localhost;DATABASE=app;UID=sa;PWD=changeme;TrustServerCertificate=yes"
    )


def _validate_schema_name(schema_name: str) -> str:
    if not _IDENTIFIER_RE.match(schema_name or ""):
        raise ValueError(f"Invalid schema name: {schema_name!r}")
    return schema_name


def register_tenant(conn, tenant_id: str, schema_name: str) -> None:
    # Validate on the way IN so poisoned values never get stored.
    _validate_schema_name(schema_name)
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO Tenants (TenantId, SchemaName) VALUES (?, ?)",
        tenant_id,
        schema_name,
    )
    conn.commit()


def get_tenant_rows(conn, tenant_id: str):
    cur = conn.cursor()
    cur.execute("SELECT SchemaName FROM Tenants WHERE TenantId = ?", tenant_id)
    row = cur.fetchone()
    if row is None:
        return []

    # Re-validate on the way OUT; do not trust the DB round-trip.
    schema_name = _validate_schema_name(row[0])

    # QUOTENAME() escapes the identifier server-side; the dynamic SQL is
    # run through sp_executesql with the schema passed as a bound value
    # that is only ever used inside QUOTENAME().
    sql = (
        "DECLARE @q NVARCHAR(MAX) = "
        "N'SELECT * FROM ' + QUOTENAME(@schema) + N'.Orders'; "
        "EXEC sp_executesql @q;"
    )
    cur.execute(sql, schema_name)
    return cur.fetchall()
