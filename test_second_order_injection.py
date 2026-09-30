"""
Demonstrates the second-order SQL injection trigger without needing a
live SQL Server. A tiny fake cursor records the final SQL string that
would be sent to the server, so the test can assert on what gets built.

Run: python -m pytest test_second_order_injection.py -v
"""

import tenant_store
import tenant_store_fixed


class FakeCursor:
    """Records executed SQL; serves a stored schema_name back on read."""

    def __init__(self, store):
        self._store = store
        self.executed = []
        self._last_select_tenant = None

    def execute(self, sql, *params):
        self.executed.append((sql, params))
        # Emulate the stage-1 INSERT and the stage-2 SELECT round-trip.
        if sql.startswith("INSERT INTO Tenants"):
            tenant_id, schema_name = params
            self._store[tenant_id] = schema_name
        elif sql.startswith("SELECT SchemaName"):
            self._last_select_tenant = params[0]
        return self

    def fetchone(self):
        tenant = self._last_select_tenant
        if tenant in self._store:
            return [self._store[tenant]]
        return None

    def fetchall(self):
        return []


class FakeConn:
    def __init__(self):
        self.store = {}
        self._cursor = FakeCursor(self.store)

    def cursor(self):
        return self._cursor

    def commit(self):
        pass


# The poisoned schema name. `--` comments out the trailing `].Orders')`
# fragment so the injected DROP statement runs.
PAYLOAD = "dbo].Orders; DROP TABLE Audit; --"


def test_vulnerable_path_builds_injected_exec():
    conn = FakeConn()
    tenant_store.register_tenant(conn, "acme", PAYLOAD)  # stored safely
    tenant_store.get_tenant_rows(conn, "acme")           # fires on read

    final_sql = conn.cursor().executed[-1][0]
    # The injected statement ends up inside the dynamic EXEC() string.
    assert "DROP TABLE Audit" in final_sql
    assert final_sql.startswith("EXEC(")
    print("\nVulnerable SQL built:\n  " + final_sql)


def test_fixed_path_rejects_payload_on_store():
    conn = FakeConn()
    try:
        tenant_store_fixed.register_tenant(conn, "acme", PAYLOAD)
        assert False, "expected ValueError for poisoned schema name"
    except ValueError:
        pass


def test_fixed_path_uses_quotename_for_valid_schema():
    conn = FakeConn()
    tenant_store_fixed.register_tenant(conn, "acme", "reporting")
    tenant_store_fixed.get_tenant_rows(conn, "acme")

    final_sql = conn.cursor().executed[-1][0]
    assert "QUOTENAME(@schema)" in final_sql
    assert "sp_executesql" in final_sql


if __name__ == "__main__":
    test_vulnerable_path_builds_injected_exec()
    test_fixed_path_rejects_payload_on_store()
    test_fixed_path_uses_quotename_for_valid_schema()
    print("\nAll checks passed.")
