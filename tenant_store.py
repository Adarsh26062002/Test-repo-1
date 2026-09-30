"""
Demonstration of a second-order SQL injection (CVE-style test case).

Stage 1: an attacker-controlled ``schema_name`` is STORED via a safe,
parameterized INSERT. Nothing malicious happens here.

Stage 2: a *different* code path reads that stored value back and
concatenates it into a dynamically built T-SQL ``EXEC()`` string.
Because the value "came from our own database" it is trusted and never
re-sanitized -- that is the second-order trigger.

Object identifiers (schema/table/column names) cannot be bound with
pyodbc parameters (``?``), so developers concatenate them, which is
exactly what makes ``schema_name`` a viable injection carrier.

This file is intentionally vulnerable. See ``tenant_store_fixed.py`` for
the remediated version.
"""

import pyodbc


def connect():
    return pyodbc.connect(
        "DRIVER={ODBC Driver 18 for SQL Server};"
        "SERVER=localhost;DATABASE=app;UID=sa;PWD=changeme;TrustServerCertificate=yes"
    )


def register_tenant(conn, tenant_id: str, schema_name: str) -> None:
    """Stage 1 -- STORE the value. Looks safe: fully parameterized."""
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO Tenants (TenantId, SchemaName) VALUES (?, ?)",
        tenant_id,
        schema_name,  # stored verbatim, no validation
    )
    conn.commit()


def get_tenant_rows(conn, tenant_id: str):
    """Stage 2 -- READ the stored value and glue it into an EXEC() string."""
    cur = conn.cursor()

    # Reading the value back is parameterized and looks innocent.
    cur.execute("SELECT SchemaName FROM Tenants WHERE TenantId = ?", tenant_id)
    row = cur.fetchone()
    if row is None:
        return []
    schema_name = row[0]

    # VULNERABLE SINK: schema_name came from the DB, so it is trusted and
    # concatenated straight into a nested T-SQL EXEC() string.
    sql = "EXEC('SELECT * FROM [' + '" + schema_name + "' + '].Orders')"
    cur.execute(sql)
    return cur.fetchall()
