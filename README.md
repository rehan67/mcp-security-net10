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

This repository demonstrates the **4 Gates of Production MCP Security** implemented in .NET 10, ASP.NET Core, and official Model Context Protocol packages.

---

## 🏛️ Hardened Architecture Flow

```text
[ AI Agent / Host Client ]
         │
         │  1. HTTP POST /mcp (Bearer JWT + JSON-RPC)
         ▼
┌────────────────────────────────────────────────────────┐
│ Gate 1: Audience & Ingress Verification                │
│ • Validates RFC 9068 §2.2 Token Audience               │
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
│ Gate 4: Data Boundary & Generic 404 Denial             │
│ • Domain Store queries filtered by TenantId            │
│ • Cross-tenant and missing IDs both return 404         │
│ • Anti-enumeration protection + Redacted Audit Log     │
└────────────────────────────────────────────────────────┘
```

---

## 🛡️ The 4 Defense Gates Explained

### 1. Gate 1: Token Audience & Ingress (RFC 9068 §2.2)
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

### 4. Gate 4: Generic 404 Denial & Anti-Enumeration
When a caller requests a record that does not belong to their tenant, returning `403 Forbidden: Belongs to Tenant B` leaks business intelligence. Our domain service returns a clean, generic `Order unavailable.` (404) while recording a redacted decision event for security triage:
```csharp
return order is null
    ? new CallToolResult { IsError = true, Content = [new TextContentBlock { Text = "Order unavailable." }] }
    : new CallToolResult { Content = [new TextContentBlock { Text = JsonSerializer.Serialize(order) }] };
```

---

## 🧪 Automated Negative Assertion Test Suite

Production security boundaries must be proven with automated negative tests. [`PolicySelfTests.cs`](PolicySelfTests.cs) runs **28 automated assertions** against the running HTTP MCP pipeline:

| Test Assertion | Verified Behavior |
|---|---|
| `Owner reads allowed order` | Tenant A owner successfully reads their own record |
| `Cross-tenant request denied` | Tenant A caller requesting Tenant B order is denied |
| `Same tenant owner policy` | Caller in same tenant without record ownership is denied |
| `Claimed tenant membership` | Token with forged tenant claim fails dynamic membership verification |
| `Scope enforcement` | Token with `orders.write` rejected when `orders.read` is required |
| `Unauthenticated denial` | Calls missing authorization headers rejected immediately |
| `Membership revocation` | Mid-session revocation revokes access on existing tokens |
| `Redacted audit trail` | Security audit records both outcomes without exposing sensitive data |

---

## 🚀 Getting Started

### Prerequisites
- [.NET 10 SDK](https://dotnet.microsoft.com/download/dotnet/10.0) (pinned to `10.0.402` in [`global.json`](global.json))

### Run the Automated Self-Test Suite
```bash
# Set a temporary HMAC signing key for the local test run
$env:MCP_LAB_SIGNING_KEY = "test-secret-key-with-at-least-32-bytes!!"

# Execute in-process policy and isolation self-tests
dotnet run -- --self-test
```

### Run the MCP HTTP Server
```bash
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
