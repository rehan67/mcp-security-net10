# MCP Security in .NET 10: A Valid Token Is Not Enough

[![.NET 10](https://img.shields.io/badge/.NET-10.0-512BD4?logo=dotnet)](https://dotnet.microsoft.com/)
[![MCP](https://img.shields.io/badge/Protocol-MCP%202.3.0-00D2FF)](https://modelcontextprotocol.io/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Companion repository for the deep-dive system architecture video and engineering article:  
**"MCP Security in .NET 10: A Valid Token Is Not Enough"** by [Rehan Akbar](https://www.rehanakbar.dev/).

---

## 🎯 The Problem: The Single Lock Trap

In modern AI agent architectures using the [Model Context Protocol (MCP)](https://modelcontextprotocol.io), many teams assume that verifying an incoming OAuth JWT bearer token is sufficient to protect backend tools and resources.

**A valid token only proves identity; it does not prove authorization.**

If an AI agent caller (e.g. Alice in Tenant A) presents a cryptographically valid token and requests a private resource identifier belonging to another customer (`order-b-202` in Tenant B), a naive MCP server will happily execute the read.

This repository demonstrates the **4 Gates of Production MCP Security** implemented in .NET 10, ASP.NET Core, Entity Framework Core, and official Model Context Protocol packages.

---

## 🏛️ Hardened Architecture Flow

```text
[ AI Agent / Host Client ]
         │
         │  1. HTTP POST /mcp (Bearer JWT + JSON-RPC)
         ▼
┌────────────────────────────────────────────────────────┐
│ Gate 1: Audience & Ingress Verification                │
│ • Validates JWT audience (RFC 9068 profile)            │
│ • Rejects cross-API token replay (aud == /mcp)         │
└────────────────────────┬───────────────────────────────┘
                         │
                         ▼
┌────────────────────────────────────────────────────────┐
│ Gate 2: Runtime Tool Invocation Policy                 │
│ • .AddAuthorizationFilters()                           │
│ • Tool contract enforced by [Authorize(Policy="...")]  │
│ • Client discovery hiding is NOT relied on for safety │
└────────────────────────┬───────────────────────────────┘
                         │
                         ▼
┌────────────────────────────────────────────────────────┐
│ Gate 3: Context Binding (Ambient Identity)             │
│ • ClaimsPrincipal extracted from HttpContext.User      │
│ • Tenant boundary bound to validated 'tenant_id' claim │
│ • Tool argument schema NEVER accepts a 'tenant' string │
└────────────────────────┬───────────────────────────────┘
                         │
                         ▼
┌────────────────────────────────────────────────────────┐
│ Gate 4: EF Core Global Query Filter & Uniform Denial   │
│ • OrdersDbContext applies tenant global query filter   │
│ • WHERE "o"."TenantId" = @tenant injected into SQL     │
│ • Database returns zero rows for cross-tenant IDs      │
│ • Returns generic "Order unavailable." (anti-leakage)  │
│ • Anti-enumeration protection + Redacted Audit Log     │
└────────────────────────────────────────────────────────┘
```

---

## 🛡️ The 4 Defense Gates Explained

### 1. Gate 1: Token Audience & Ingress (RFC 9068 profile)
A token issued for a general customer portal or administrative service must never be accepted by an internal MCP server. We strictly enforce that the JWT audience matches the dedicated MCP tool endpoint:
```csharp
options.TokenValidationParameters = new TokenValidationParameters
{
    ValidateAudience = true,
    ValidAudience = listen + "/mcp",
    ValidateIssuer = true,
    ValidIssuer = issuer,
    ClockSkew = TimeSpan.Zero
};
```

### 2. Gate 2: Tool Invocation Policy (`[Authorize]`)
Tool filtering during discovery (`tools/list`) is merely a UI convenience for the LLM. If an agent guesses or prompts for a sensitive tool name directly via `tools/call`, runtime authorization must execute:
```csharp
[McpServerToolType]
public sealed class OrderTools(OrderService orders, IHttpContextAccessor http)
{
    [McpServerTool(Name = "get_order", ReadOnly = true, Idempotent = true)]
    [Authorize(Policy = "orders.read")]
    public async Task<CallToolResult> GetOrder(string orderId, CancellationToken ct) { ... }
}
```

### 3. Gate 3: Ambient Identity vs. Untrusted Arguments
**Never let an LLM declare whose data it is querying.** If your tool parameter schema accepts `tenantId: string`, any prompt injection can manipulate it. Instead, tenant context is derived strictly from ambient validated JWT claims:
```csharp
var principal = http.HttpContext?.User 
    ?? throw new InvalidOperationException("HTTP context required.");

var order = await orders.ReadAsync(principal, orderId, cancellationToken);
```

### 4. Gate 4: Entity Framework Core Global Query Filter & Uniform Denial
To ensure multi-tenant isolation cannot be bypassed by arbitrary ID lookups, `OrdersDbContext` applies an Entity Framework Core Global Query Filter:
```csharp
modelBuilder.Entity<StoredOrder>(entity =>
{
    entity.HasKey(e => e.Id);
    // EF Core injects WHERE "TenantId" = @tenant directly into every generated SQL statement
    entity.HasQueryFilter(e => e.TenantId == tenantContext.CurrentTenant);
});
```
When Alice queries for `order-b-202`, EF Core automatically injects `WHERE "o"."TenantId" = @tenant` into the SQL statement, and the database returns zero rows.
For both inaccessible and missing orders, the MCP tool returns the same tool error result (`isError: true`, text `Order unavailable.`) with no order payload, and records a redacted decision event. The separate REST route returns a standard 404 Not Found.

```csharp
return order is null
    ? new CallToolResult { IsError = true, Content = [new TextContentBlock { Text = "Order unavailable." }] }
    : new CallToolResult { Content = [new TextContentBlock { Text = JsonSerializer.Serialize(order) }] };
```

---

## 🧪 Automated Negative Assertion Test Suite

[`PolicySelfTests.cs`](PolicySelfTests.cs) contains **28 automated checks** executed against the live HTTP MCP pipeline and the EF Core database:

| # | Verified Test Scenario | Assertion Description |
|---|---|---|
| 1 | Missing credential | Rejected at HTTP boundary (401 Unauthorized) |
| 2 | Wrong audience | RFC 9068 audience mismatch rejected (401 Unauthorized) |
| 3 | Wrong issuer | Untrusted issuer signature rejected (401 Unauthorized) |
| 4 | Expired token | Expired token rejected at ingress (401 Unauthorized) |
| 5 | Invalid signature | Forged/bad signature rejected (401 Unauthorized) |
| 6 | Tool discovery | Authorized caller with `orders.read` discovers `get_order` via `tools/list` |
| 7 | Scope filtering | Unauthorized caller without `orders.read` has `get_order` hidden from catalog |
| 8 | Direct tool invocation | Calling known tool without scope rejected by authorization filter |
| 9 | Authorized read | Alice successfully reads `order-a-101` over MCP protocol |
| 10 | Data minimization | Success response omits internal database notes |
| 11 | Cross-tenant denial | Cross-tenant request returns uniform tool error `"Order unavailable."` |
| 12 | Zero data leakage | Cross-tenant response contains zero Tenant B order payloads |
| 13 | Header injection defense | Forwarded `X-Tenant-Id` headers cannot override authenticated identity |
| 14 | Dynamic membership | Forged tenant claim rejected without server-side membership |
| 15 | Same-tenant owner policy | Callers in same tenant without record ownership are denied |
| 16 | REST route isolation | Cross-tenant lookup on REST endpoint returns 404 Not Found |
| 17 | REST route authorized | Owner lookup on REST endpoint returns 200 OK with projected view |
| 18 | Concurrency isolation | 24 concurrent A/B MCP requests with identical RPC IDs stay isolated |
| 19 | EF Core SQL filter | Assert generated SQL contains `WHERE "o"."TenantId" = @tenant` |
| 20 | Database zero rows | Assert EF Core database returns zero rows for other tenant's order |
| 21 | Policy: Owner read | In-process: Allowed owner reads record |
| 22 | Policy: Cross-tenant | In-process: Cross-tenant read denied |
| 23 | Policy: Same-tenant | In-process: Non-owner in same tenant denied |
| 24 | Policy: Membership | In-process: Claimed tenant without active membership denied |
| 25 | Policy: Scope check | In-process: `orders.write` not accepted for read requirement |
| 26 | Policy: Unauthenticated | In-process: Unauthenticated principal denied |
| 27 | Policy: Revocation | In-process: Real-time membership revocation takes effect immediately |
| 28 | Policy: Audit trail | In-process: Audit logger records decisions without sensitive payloads |

---

## 🚀 Getting Started

### Prerequisites
- [.NET 10 SDK](https://dotnet.microsoft.com/download/dotnet/10.0) (pinned in [`global.json`](global.json))

The lab binds to `127.0.0.1` and runs in `Development` mode.

### Run the 28-Test Automated Suite (PowerShell)
```powershell
$env:ASPNETCORE_ENVIRONMENT = "Development"
$env:MCP_LAB_SIGNING_KEY = "test-secret-key-with-at-least-32-bytes!!"

dotnet run -- --self-test true
```
Expected output:
```text
SELF_TEST_REPORT:{"status":"passed","targetFramework":"net10.0","totalChecks":28,...}
```

### Run the MCP HTTP Server
```powershell
$env:ASPNETCORE_ENVIRONMENT = "Development"
$env:MCP_LAB_SIGNING_KEY = "your-secure-32-byte-signing-key-here!!"

dotnet run
```
The stateless HTTP MCP server will listen at `http://127.0.0.1:7047/mcp`.

---

## 📺 Video & Engineering Walkthrough

- **YouTube Video**: [MCP Security in .NET 10: A Valid Token Is Not Enough](https://www.youtube.com/channel/UC0Nv-J9AdeEGCPmdxw7Uo2A)
- **Technical Blog**: [https://www.rehanakbar.dev/](https://www.rehanakbar.dev/)

---

## 👤 Author & Connect

**Rehan Akbar**  
*Production software problems, system design, and backend engineering explained through practical examples.*

- 🌐 **Technical Blog**: [rehanakbar.dev](https://www.rehanakbar.dev/)
- 💼 **LinkedIn**: [linkedin.com/in/rehan-akbar95](https://linkedin.com/in/rehan-akbar95)
- 📸 **Instagram**: [@iiamrehanakbar](https://www.instagram.com/iiamrehanakbar)
- 📘 **Facebook**: [Rehan Akbar - Software Engineer](https://www.facebook.com/people/Rehan-Akbar-Software-Engineer/61594815128701/)
- 💻 **GitHub**: [@rehan67](https://github.com/rehan67)

---

## 📄 License
This project is licensed under the [MIT License](LICENSE).
