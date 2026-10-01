/// <summary>
/// Deliberately vulnerable sample for exercising SAST scanners and demonstrating
/// a second-order SQL injection via nested dynamic SQL inside T-SQL EXEC().
///
/// This is nested dynamic SQL: the outer statement is already built unsafely by
/// string.Format, and it in turn constructs a second SQL string executed via SQL
/// Server's EXEC(). A schemaName containing a single quote can both break the outer
/// literal and inject arbitrary T-SQL that is executed inside the EXEC() call --
/// one of the most dangerous unescaped-input patterns.
///
/// THIS FILE IS INTENTIONALLY VULNERABLE. See TenantSchemaRepository_Fixed.cs for
/// the remediated version.
/// </summary>

using System.Data;
using System.Data.SqlClient;

public class TenantSchemaRepository
{
    private readonly string _connectionString;

    public TenantSchemaRepository(string connectionString)
    {
        _connectionString = connectionString;
    }

    /// <summary>
    /// Stage 1 -- STORE the schema name. Looks safe: fully parameterized.
    /// </summary>
    public void RegisterTenant(string tenantId, string schemaName)
    {
        using var conn = new SqlConnection(_connectionString);
        conn.Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "INSERT INTO Tenants (TenantId, SchemaName) VALUES (@tenantId, @schemaName)";
        cmd.Parameters.AddWithValue("@tenantId", tenantId);
        cmd.Parameters.AddWithValue("@schemaName", schemaName);
        cmd.ExecuteNonQuery();
    }

    /// <summary>
    /// Stage 2 -- READ the stored value and glue it into an EXEC() string.
    ///
    /// VULNERABLE SINK: schemaName came from the database, so it is trusted and
    /// concatenated straight into nested T-SQL EXEC() strings. The outer statement
    /// uses string.Format unsafely, building a second dynamic SQL string that is
    /// executed via EXEC(). A schemaName containing a single quote breaks both layers.
    /// </summary>
    public DataTable GetTenantRows(string tenantId)
    {
        using var conn = new SqlConnection(_connectionString);
        conn.Open();

        // Stage 2a: Read the stored schemaName (parameterized, looks innocent)
        string schemaName;
        using (var cmd = conn.CreateCommand())
        {
            cmd.CommandText = "SELECT SchemaName FROM Tenants WHERE TenantId = @tenantId";
            cmd.Parameters.AddWithValue("@tenantId", tenantId);
            var result = cmd.ExecuteScalar();
            if (result == null)
                return new DataTable();
            schemaName = (string)result;
        }

        // Stage 2b: VULNERABLE -- build the outer SQL string unsafely with string.Format
        // This outer SQL string itself constructs a second dynamic SQL string that will
        // be executed via EXEC(). The schemaName is NOT parameterized or escaped.
        string outerSql = string.Format(
            "IF NOT EXISTS (SELECT 1 FROM sys.schemas WHERE name = '{0}') " +
            "EXEC('SELECT * FROM [{0}].Orders')",
            schemaName);

        using var cmdOuter = conn.CreateCommand();
        cmdOuter.CommandText = outerSql;
        using var adapter = new SqlDataAdapter(cmdOuter);
        var table = new DataTable();
        adapter.Fill(table);
        return table;
    }
}
