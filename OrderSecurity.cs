using System.Collections.Concurrent;
using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;

public sealed record StoredOrder(string Id, string TenantId, string OwnerSubject,
    string Status, decimal Total, string InternalNote);
public sealed record OrderView(string Id, string Status, decimal Total);

public static class OrderPermissions
{
    public static bool HasReadScope(ClaimsPrincipal user) => user.FindAll("scope")
        .SelectMany(c => c.Value.Split(' ', StringSplitOptions.RemoveEmptyEntries))
        .Contains("orders.read", StringComparer.Ordinal);
}

public sealed class Memberships
{
    private readonly ConcurrentDictionary<(string Subject, string Tenant), bool> active = new();
    public Memberships()
    {
        active[("alice", "tenant-a")] = true;
        active[("bob", "tenant-b")] = true;
        active[("charlie", "tenant-a")] = true;
    }
    public bool IsActive(string subject, string tenant) =>
        active.TryGetValue((subject, tenant), out var value) && value;

    // Used by the in-process test to verify current policy after token issuance.
    // Not exposed as an HTTP or MCP tool.
    public void Revoke(string subject, string tenant) => active[(subject, tenant)] = false;
}

public sealed class OrderStore
{
    private static readonly StoredOrder[] Orders =
    [
        new("order-a-101", "tenant-a", "alice", "Ready", 49m, "A-INTERNAL-DO-NOT-RETURN"),
        new("order-b-202", "tenant-b", "bob", "Ready", 79m, "B-INTERNAL-DO-NOT-RETURN")
    ];

    // Tenant comes from validated identity and current membership, never arguments.
    // A real database implementation should include this predicate in its query.
    public StoredOrder? FindInTenant(string tenant, string orderId) =>
        Orders.SingleOrDefault(o => o.TenantId == tenant && o.Id == orderId);
}

public sealed class ReadOrderRequirement : IAuthorizationRequirement
{
    public static ReadOrderRequirement Instance { get; } = new();
}

public sealed class OrderReadHandler(Memberships memberships)
    : AuthorizationHandler<ReadOrderRequirement, StoredOrder>
{
    protected override Task HandleRequirementAsync(AuthorizationHandlerContext context,
        ReadOrderRequirement requirement, StoredOrder resource)
    {
        var subject = context.User.FindFirst("sub")?.Value;
        var tenant = context.User.FindFirst("tenant_id")?.Value;
        if (context.User.Identity?.IsAuthenticated == true &&
            subject is not null && tenant is not null &&
            OrderPermissions.HasReadScope(context.User) &&
            memberships.IsActive(subject, tenant) &&
            resource.TenantId == tenant && resource.OwnerSubject == subject)
            context.Succeed(requirement);
        return Task.CompletedTask;
    }
}

public sealed record AuditDecision(string Actor, string Tenant, string Operation,
    string Outcome, string CorrelationId);

public sealed class DecisionAudit(ILogger<DecisionAudit> logger)
{
    private readonly ConcurrentQueue<AuditDecision> entries = new();
    public void Record(ClaimsPrincipal user, bool allowed)
    {
        var entry = new AuditDecision(user.FindFirst("sub")?.Value ?? "unknown",
            user.FindFirst("tenant_id")?.Value ?? "unknown", "get_order",
            allowed ? "allowed" : "denied", System.Diagnostics.Activity.Current?.TraceId.ToString() ?? "local");
        entries.Enqueue(entry);
        logger.LogInformation("Decision actor={Actor} tenant={Tenant} operation={Operation} outcome={Outcome} trace={Trace}",
            entry.Actor, entry.Tenant, entry.Operation, entry.Outcome, entry.CorrelationId);
    }
    public AuditDecision[] Snapshot() => entries.ToArray();
}

public sealed class OrderService(OrderStore store, Memberships memberships,
    IAuthorizationService authorization, DecisionAudit audit)
{
    public async Task<OrderView?> ReadAsync(ClaimsPrincipal user, string orderId,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var subject = user.FindFirst("sub")?.Value;
        var tenant = user.FindFirst("tenant_id")?.Value;
        if (user.Identity?.IsAuthenticated != true || subject is null || tenant is null ||
            !OrderPermissions.HasReadScope(user) || !memberships.IsActive(subject, tenant) ||
            string.IsNullOrWhiteSpace(orderId) || orderId.Length > 64)
        {
            audit.Record(user, false);
            return null;
        }

        var order = store.FindInTenant(tenant, orderId);
        if (order is null)
        {
            audit.Record(user, false);
            return null;
        }
        var decision = await authorization.AuthorizeAsync(user, order, ReadOrderRequirement.Instance);
        audit.Record(user, decision.Succeeded);
        return decision.Succeeded ? new OrderView(order.Id, order.Status, order.Total) : null;
    }
}
