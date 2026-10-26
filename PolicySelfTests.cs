using System.Security.Claims;
using System.Text.Json;

public static class PolicySelfTests
{
    private static ClaimsPrincipal Principal(string subject, string tenant, string scope = "orders.read") =>
        new(new ClaimsIdentity([new("sub", subject), new("tenant_id", tenant), new("scope", scope)], "TestOnly"));

    public static async Task RunAsync(IServiceProvider services)
    {
        using var scope = services.CreateScope();
        var orders = scope.ServiceProvider.GetRequiredService<OrderService>();
        var memberships = services.GetRequiredService<Memberships>();
        var checks = new List<string>();
        void Check(bool ok, string name)
        {
            if (!ok) throw new InvalidOperationException("FAIL: " + name);
            checks.Add(name);
        }
        var alice = Principal("alice", "tenant-a");
        Check((await orders.ReadAsync(alice, "order-a-101"))?.Id == "order-a-101", "Owner reads allowed order");
        Check(await orders.ReadAsync(alice, "order-b-202") is null, "Cross-tenant request denied by shared service");
        Check(await orders.ReadAsync(Principal("charlie", "tenant-a"), "order-a-101") is null,
            "Same tenant does not override this lab's owner policy");
        Check(await orders.ReadAsync(Principal("alice", "tenant-b"), "order-b-202") is null,
            "Claimed tenant also needs server-side membership");
        Check(await orders.ReadAsync(Principal("alice", "tenant-a", "orders.write"), "order-a-101") is null,
            "Write scope is not implicitly accepted as read scope");
        Check(await orders.ReadAsync(new ClaimsPrincipal(new ClaimsIdentity()), "order-a-101") is null,
            "Unauthenticated principal denied by shared service");
        memberships.Revoke("alice", "tenant-a");
        Check(await orders.ReadAsync(alice, "order-a-101") is null,
            "Membership revocation applies to an already-created principal");
        var audit = services.GetRequiredService<DecisionAudit>().Snapshot();
        Check(audit.Any(x => x.Outcome == "allowed") && audit.Any(x => x.Outcome == "denied"),
            "Business audit records both outcomes without order payloads");
        Console.WriteLine("SELF_TEST_REPORT:" + JsonSerializer.Serialize(new { checks }));
    }
}
