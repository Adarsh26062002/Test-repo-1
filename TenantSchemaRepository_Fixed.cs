/// <summary>
/// Remediated version of TenantSchemaRepository.cs.
///
/// Object identifiers (schema names, table names, etc.) cannot be parameterized
/// in SQL Server, so the fix uses three layers of defense:
///
/// 1. Allow-list validation: reject anything that is not a plain SQL identifier
/// 2. Re-validate on the way OUT: do not trust a value just because it was read from the database
/// 3. Server-side escaping via QUOTENAME() inside a parameterized sp_executesql call
/// </summary>

using System;
using System.Data;
using System.Data.SqlClient;
using System.Text.RegularExpressions;

public class TenantSchemaRepository_Fixed
{
    private readonly string _connectionString;

    // A plain, unquoted SQL Server identifier: starts with letter or underscore,
    // followed by letters, digits, or underscores. Max 128 chars per SQL Server.
    private static readonly Regex IdentifierRegex = new(@"^[A-Za-z_][A-Za-z0-9_]{0,127}$");

    public TenantSchemaRepository_Fixed(string connectionString)
    {
        _connectionString = connectionString;
    }

    private static string ValidateSchemaName(string schemaName)
    {
        if (string.IsNullOrEmpty(schemaName) || !IdentifierRegex.IsMatch(schemaName))
            throw new ArgumentException($"Invalid schema name: {schemaName!r}");
        return schemaName;
    }

    /// <summary>
    /// Stage 1 -- STORE the schema name with validation on the way IN.
    /// Reject poisoned values before they ever reach the database.
    /// </summary>
    public void RegisterTenant(string tenantId, string schemaName)
    {
        // Validate on the way IN so poisoned values never get stored.
        ValidateSchemaName(schemaName);

        using var conn = new SqlConnection(_connectionString);
        conn.Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "INSERT INTO Tenants (TenantId, SchemaName) VALUES (@tenantId, @schemaName)";
        cmd.Parameters.AddWithValue("@tenantId", tenantId);
        cmd.Parameters.AddWithValue("@schemaName", schemaName);
        cmd.ExecuteNonQuery();
    }

    /// <summary>
    /// Stage 2 -- READ the stored value with re-validation and server-side escaping.
    ///
    /// SAFE:
    /// - Re-validate the schema name on the way OUT (do not trust the DB round-trip)
    /// - Use sp_executesql with QUOTENAME() to escape the identifier server-side
    /// - The identifier is passed as a bound @parameter to sp_executesql, never concatenated
    /// </summary>
    public DataTable GetTenantRows(string tenantId)
    {
        using var conn = new SqlConnection(_connectionString);
        conn.Open();

        // Read the stored schemaName (parameterized)
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

        // Re-validate on the way OUT; do not trust the database round-trip
        schemaName = ValidateSchemaName(schemaName);

        // SAFE: Use sp_executesql with QUOTENAME() to escape the identifier server-side.
        // The schema name is passed as a bound parameter (@schema), never concatenated.
        // QUOTENAME() wraps it in square brackets and doubles any internal brackets.
        string safeSql = @"
            DECLARE @query NVARCHAR(MAX) =
                N'SELECT * FROM ' + QUOTENAME(@schema) + N'.Orders';
            EXEC sp_executesql @query;
        ";

        using var cmd2 = conn.CreateCommand();
        cmd2.CommandText = safeSql;
        cmd2.Parameters.AddWithValue("@schema", schemaName);
        using var adapter = new SqlDataAdapter(cmd2);
        var table = new DataTable();
        adapter.Fill(table);
        return table;
    }
}
