using System.ComponentModel;
using System.Text.Json;
using Microsoft.AspNetCore.Authorization;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;

[McpServerToolType]
public sealed class OrderTools(OrderService orders, IHttpContextAccessor http)
{
    [McpServerTool(Name = "get_order", ReadOnly = true, Idempotent = true, OpenWorld = false)]
    [Authorize(Policy = "orders.read")]
    [Description("Read an order allowed by the caller's current tenant and ownership policy.")]
    public async Task<CallToolResult> GetOrder(
        [Description("Order identifier; knowing it does not grant access.")] string orderId,
        CancellationToken cancellationToken)
    {
        var principal = http.HttpContext?.User
            ?? throw new InvalidOperationException("This tool requires an HTTP request context.");
        var order = await orders.ReadAsync(principal, orderId, cancellationToken);
        return order is null
            ? new CallToolResult
            {
                IsError = true,
                Content = [new TextContentBlock { Text = "Order unavailable." }]
            }
            : new CallToolResult
            {
                Content = [new TextContentBlock { Text = JsonSerializer.Serialize(order) }]
            };
    }
}
