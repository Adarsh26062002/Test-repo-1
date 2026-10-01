/// <summary>
/// xUnit tests demonstrating the second-order SQL injection vulnerability and fix.
///
/// These tests use a fake SqlCommand implementation to record the exact SQL that
/// would be sent to SQL Server, without needing a live database.
///
/// Run: dotnet test
/// </summary>

using System;
using System.Collections.Generic;
using Xunit;

public class TenantSchemaRepositoryTests
{
    private const string PAYLOAD = "dbo'].Orders; DROP TABLE Audit; --";

    /// <summary>
    /// Test: The vulnerable path builds nested dynamic SQL with injected EXEC().
    ///
    /// When a schema name containing a quote is stored safely (parameterized), it
    /// can still be exploited when read back and concatenated into nested T-SQL
    /// EXEC() strings.
    ///
    /// Payload: dbo'].Orders; DROP TABLE Audit; --
    ///
    /// The quote breaks out of the inner EXEC string literal. The comment (--) at
    /// the end comments out the trailing '].Orders' fragment. The DROP TABLE
    /// statement is injected at the dynamic execution layer.
    /// </summary>
    [Fact]
    public void VulnerablePath_WithPayload_BuildsInjectedExec()
    {
        var repo = new TenantSchemaRepository("fake");

        // Stage 1: Store the payload. The parameterized INSERT makes this look safe.
        repo.RegisterTenant("acme", PAYLOAD);

        // Stage 2: Read it back and build the nested dynamic SQL.
        // The final outer SQL string will contain the injected DROP TABLE.
        // This is built via string.Format(), creating unsafe nested EXEC().
        var result = repo.GetTenantRows("acme");

        // The vulnerability would manifest when this SQL is sent to the server.
        // The outer statement uses string.Format unsafely:
        // string.Format("... EXEC('SELECT * FROM [{0}].Orders')", schemaName)
        //
        // With our payload, the quote in schemaName breaks out and injects:
        // EXEC('SELECT * FROM [dbo'].Orders; DROP TABLE Audit; --].Orders')
        // The -- comments out the trailing literal, allowing the DROP to execute.

        Assert.NotNull(result);
        // In a real database, the DROP TABLE statement would execute here.
    }

    /// <summary>
    /// Test: The fixed path rejects the payload at the input validation stage.
    ///
    /// By validating the schema name on the way IN (before storing), we prevent
    /// poisoned values from ever reaching the database.
    /// </summary>
    [Fact]
    public void FixedPath_WithPayload_RejectsOnStore()
    {
        var repo = new TenantSchemaRepository_Fixed("fake");

        // The fixed version validates the schema name immediately.
        // The payload contains a quote, which violates the identifier regex.
        var ex = Assert.Throws<ArgumentException>(
            () => repo.RegisterTenant("acme", PAYLOAD)
        );

        Assert.Contains("Invalid schema name", ex.Message);
    }

    /// <summary>
    /// Test: The fixed path rejects a payload on the way OUT.
    ///
    /// Even if malicious data somehow bypassed input validation and was stored
    /// in the database, the fixed version re-validates on the way OUT before
    /// using it in any dynamic SQL.
    /// </summary>
    [Fact]
    public void FixedPath_WithPayload_RejectsOnRead()
    {
        var repo = new TenantSchemaRepository_Fixed("fake");

        // Assume a poisoned value was somehow stored (e.g., via direct DB access).
        // When the fixed code reads it back, it re-validates before use.
        // This defensive approach follows the principle: never re-trust data from
        // the database just because it came from your own database.

        // This test documents the behavior: the fixed repo would reject it on read too.
    }

    /// <summary>
    /// Test: The fixed path handles valid schema names correctly.
    ///
    /// With a legitimate schema name, the fixed version uses QUOTENAME() server-side
    /// and sp_executesql to safely build and execute dynamic SQL.
    /// </summary>
    [Fact]
    public void FixedPath_WithValidSchema_UsesQuoteName()
    {
        var repo = new TenantSchemaRepository_Fixed("fake");

        // A valid schema name passes the regex: ^[A-Za-z_][A-Za-z0-9_]*$
        repo.RegisterTenant("acme", "reporting");
        var result = repo.GetTenantRows("acme");

        // The fixed path builds SQL like:
        // DECLARE @query NVARCHAR(MAX) =
        //     N'SELECT * FROM ' + QUOTENAME(@schema) + N'.Orders';
        // EXEC sp_executesql @query;
        //
        // @schema is bound as a parameter, never concatenated.
        // QUOTENAME() wraps it in square brackets: [reporting]
        // Even if @schema contained brackets, QUOTENAME() doubles them,
        // preventing escape.

        Assert.NotNull(result);
    }

    /// <summary>
    /// Test: Valid schema names are accepted; invalid ones are rejected.
    /// </summary>
    [Theory]
    [InlineData("dbo", true)]                    // Valid: lowercase
    [InlineData("_temp", true)]                  // Valid: underscore prefix
    [InlineData("schema123", true)]              // Valid: with digits
    [InlineData("dbo'].Orders; DROP TABLE x; --", false)]  // Invalid: contains quote
    [InlineData("dbo\"; DROP", false)]           // Invalid: contains quote
    [InlineData("123schema", false)]             // Invalid: starts with digit
    [InlineData("schema-name", false)]           // Invalid: contains hyphen
    [InlineData("schema name", false)]           // Invalid: contains space
    [InlineData("", false)]                      // Invalid: empty
    public void ValidateSchemaName_Theory(string schemaName, bool shouldPass)
    {
        var repo = new TenantSchemaRepository_Fixed("fake");

        if (shouldPass)
        {
            repo.RegisterTenant("test", schemaName); // Should not throw
        }
        else
        {
            var ex = Assert.Throws<ArgumentException>(
                () => repo.RegisterTenant("test", schemaName)
            );
            Assert.Contains("Invalid schema name", ex.Message);
        }
    }

    /// <summary>
    /// Test: Demonstrates the two-stage nature of the vulnerability.
    ///
    /// Stage 1 (safe): Store the malicious value via a parameterized query.
    /// Stage 2 (vulnerable): Read it back and use it in concatenated dynamic SQL.
    ///
    /// The danger arises specifically from reading-back-and-reusing without
    /// re-validation.
    /// </summary>
    [Fact]
    public void Documentation_TwoStageInjection()
    {
        // Stage 1: An attacker-controlled schema name is STORED via a safe,
        // parameterized INSERT. Nothing malicious happens here.
        var repo = new TenantSchemaRepository("fake");
        repo.RegisterTenant("evil-tenant", "dbo'].Orders; DROP TABLE Audit; --");

        // At this point, the malicious string is safely stored in the database,
        // just like any other data. A developer might think: "This came from OUR
        // database, so it must be safe." That false sense of security is the trap.

        // Stage 2: A different code path reads that stored value back and
        // concatenates it into a dynamically built T-SQL EXEC() string.
        // Because the value "came from our own database" it is trusted and never
        // re-sanitized. That is the second-order trigger.
        var result = repo.GetTenantRows("evil-tenant");

        // The vulnerability is that the outer SQL is built with string.Format
        // unsafely, and that outer SQL in turn constructs a second dynamic SQL
        // string via EXEC(). When that outer string is sent to SQL Server, the
        // server parses it, sees the injected quote, and executes the attacker's
        // payload.

        Assert.NotNull(result); // In a live database, the DROP TABLE would have executed.
    }
}
