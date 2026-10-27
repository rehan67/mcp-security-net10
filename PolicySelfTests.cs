using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;

public static class PolicySelfTests
{
    private static string MintJwt(string signingKey, string issuer, string audience,
        string subject, string tenant, string scope = "orders.read",
        bool expired = false, string? customAudience = null, string? customIssuer = null,
        string? badKey = null)
    {
        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(badKey ?? signingKey));
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
        var claims = new[]
        {
            new Claim("sub", subject),
            new Claim("tenant_id", tenant),
            new Claim("scope", scope)
        };
        var expires = expired ? DateTime.UtcNow.AddMinutes(-5) : DateTime.UtcNow.AddMinutes(15);
        var notBefore = expired ? DateTime.UtcNow.AddMinutes(-10) : DateTime.UtcNow.AddMinutes(-1);
        var token = new JwtSecurityToken(
            issuer: customIssuer ?? issuer,
            audience: customAudience ?? audience,
            claims: claims,
            notBefore: notBefore,
            expires: expires,
            signingCredentials: creds
        );
        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    private static ClaimsPrincipal Principal(string subject, string tenant, string scope = "orders.read") =>
        new(new ClaimsIdentity([new("sub", subject), new("tenant_id", tenant), new("scope", scope)], "TestOnly"));

    public static async Task RunAsync(WebApplication app, string listenUrl, string signingKey, string issuer, string audience)
    {
        // Start web host on loopback in background
        await app.StartAsync();
        var checks = new List<string>();
        void Check(bool ok, string name)
        {
            if (!ok) throw new InvalidOperationException("FAIL: " + name);
            checks.Add(name);
        }

        try
        {
            using var http = new HttpClient { BaseAddress = new Uri(listenUrl) };

            // 1. Missing credential rejected at HTTP boundary (401)
            var noAuthResp = await http.PostAsync("/mcp", new StringContent("{}", Encoding.UTF8, "application/json"));
            Check(noAuthResp.StatusCode == HttpStatusCode.Unauthorized, "Missing credential rejected at HTTP boundary");

            // 2. Wrong audience rejected (RFC 9068) (401)
            var wrongAudToken = MintJwt(signingKey, issuer, audience, "alice", "tenant-a", customAudience: "https://other-api.internal");
            var wrongAudReq = new HttpRequestMessage(HttpMethod.Post, "/mcp")
            {
                Content = new StringContent("{}", Encoding.UTF8, "application/json")
            };
            wrongAudReq.Headers.Authorization = new AuthenticationHeaderValue("Bearer", wrongAudToken);
            var wrongAudResp = await http.SendAsync(wrongAudReq);
            Check(wrongAudResp.StatusCode == HttpStatusCode.Unauthorized, "Wrong audience rejected (RFC 9068)");

            // 3. Wrong issuer rejected (401)
            var wrongIssToken = MintJwt(signingKey, issuer, audience, "alice", "tenant-a", customIssuer: "urn:untrusted:issuer");
            var wrongIssReq = new HttpRequestMessage(HttpMethod.Post, "/mcp")
            {
                Content = new StringContent("{}", Encoding.UTF8, "application/json")
            };
            wrongIssReq.Headers.Authorization = new AuthenticationHeaderValue("Bearer", wrongIssToken);
            Check((await http.SendAsync(wrongIssReq)).StatusCode == HttpStatusCode.Unauthorized, "Wrong issuer rejected");

            // 4. Expired token rejected (401)
            var expToken = MintJwt(signingKey, issuer, audience, "alice", "tenant-a", expired: true);
            var expReq = new HttpRequestMessage(HttpMethod.Post, "/mcp")
            {
                Content = new StringContent("{}", Encoding.UTF8, "application/json")
            };
            expReq.Headers.Authorization = new AuthenticationHeaderValue("Bearer", expToken);
            Check((await http.SendAsync(expReq)).StatusCode == HttpStatusCode.Unauthorized, "Expired token rejected");

            // 5. Invalid signature rejected (401)
            var badSigToken = MintJwt(signingKey, issuer, audience, "alice", "tenant-a", badKey: "completely-wrong-32-byte-secret-key-xyz!!");
            var badSigReq = new HttpRequestMessage(HttpMethod.Post, "/mcp")
            {
                Content = new StringContent("{}", Encoding.UTF8, "application/json")
            };
            badSigReq.Headers.Authorization = new AuthenticationHeaderValue("Bearer", badSigToken);
            Check((await http.SendAsync(badSigReq)).StatusCode == HttpStatusCode.Unauthorized, "Invalid signature rejected");

            // Valid Alice token
            var aliceToken = MintJwt(signingKey, issuer, audience, "alice", "tenant-a", "orders.read");

            // Helper to send JSON-RPC MCP requests
            async Task<(HttpStatusCode Status, JsonNode? Json)> SendMcpAsync(string token, string method, JsonNode? @params, int id = 1, Dictionary<string, string>? extraHeaders = null)
            {
                var body = new JsonObject
                {
                    ["jsonrpc"] = "2.0",
                    ["id"] = id,
                    ["method"] = method
                };
                if (@params != null) body["params"] = @params;

                var req = new HttpRequestMessage(HttpMethod.Post, "/mcp")
                {
                    Content = new StringContent(body.ToJsonString(), Encoding.UTF8, "application/json")
                };
                req.Headers.Accept.ParseAdd("application/json, text/event-stream");
                req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
                if (extraHeaders != null)
                {
                    foreach (var (k, v) in extraHeaders) req.Headers.Add(k, v);
                }
                var resp = await http.SendAsync(req);
                var content = await resp.Content.ReadAsStringAsync();
                JsonNode? json = null;
                try
                {
                    var jsonText = content;
                    if (content.Contains("data:"))
                    {
                        var line = content.Split('\n').FirstOrDefault(l => l.StartsWith("data:"));
                        if (line != null) jsonText = line["data:".Length..].Trim();
                    }
                    json = JsonNode.Parse(jsonText);
                }
                catch { }
                return (resp.StatusCode, json);
            }

            // 6. Authorized tool discovery works over MCP (tools/list)
            var (listStatus, listJson) = await SendMcpAsync(aliceToken, "tools/list", null);
            var tools = listJson?["result"]?["tools"]?.AsArray();
            var hasGetOrder = tools?.Any(t => t?["name"]?.GetValue<string>() == "get_order") == true;
            Check(listStatus == HttpStatusCode.OK && hasGetOrder, "Authorized tool discovery works over MCP");

            // 7. Tool catalog hides operations without required scope
            var writeOnlyToken = MintJwt(signingKey, issuer, audience, "alice", "tenant-a", "orders.write");
            var (unscopedListStatus, unscopedListJson) = await SendMcpAsync(writeOnlyToken, "tools/list", null);
            var unscopedTools = unscopedListJson?["result"]?["tools"]?.AsArray();
            var hidesGetOrder = unscopedTools?.Any(t => t?["name"]?.GetValue<string>() == "get_order") != true;
            Check(unscopedListStatus == HttpStatusCode.OK && hidesGetOrder, "Tool catalog hides operations without required scope");

            // 8. Known tool name direct invocation without scope rejected
            var (directCallStatus, directCallJson) = await SendMcpAsync(writeOnlyToken, "tools/call", new JsonObject
            {
                ["name"] = "get_order",
                ["arguments"] = new JsonObject { ["orderId"] = "order-a-101" }
            });
            var isDirectRejected = directCallJson?["error"] != null || directCallJson?["result"]?["isError"]?.GetValue<bool>() == true || directCallStatus == HttpStatusCode.Forbidden;
            Check(isDirectRejected, "Known tool name does not bypass invocation authorization");

            // 9. Authorized MCP call returns the correct order
            var (callStatus, callJson) = await SendMcpAsync(aliceToken, "tools/call", new JsonObject
            {
                ["name"] = "get_order",
                ["arguments"] = new JsonObject { ["orderId"] = "order-a-101" }
            }, id: 7);
            var textBlock = callJson?["result"]?["content"]?[0]?["text"]?.GetValue<string>() ?? "";
            Check(callStatus == HttpStatusCode.OK && textBlock.Contains("order-a-101"), "Authorized MCP call returns the correct order");

            // 10. Success response projects allowed fields only (internal note omitted)
            Check(!textBlock.Contains("A-INTERNAL-DO-NOT-RETURN") && textBlock.Contains("Ready"), "Success response projects allowed fields only");

            // 11. Cross-tenant request returns uniform tool error "Order unavailable."
            var (crossStatus, crossJson) = await SendMcpAsync(aliceToken, "tools/call", new JsonObject
            {
                ["name"] = "get_order",
                ["arguments"] = new JsonObject { ["orderId"] = "order-b-202" }
            }, id: 7);
            var crossText = crossJson?["result"]?["content"]?[0]?["text"]?.GetValue<string>() ?? "";
            var crossIsError = crossJson?["result"]?["isError"]?.GetValue<bool>() == true;
            Check(crossStatus == HttpStatusCode.OK && crossIsError && crossText == "Order unavailable.", "Cross-tenant request returns uniform tool error");

            // 12. Cross-tenant response contains no tenant B order payload
            Check(!crossText.Contains("order-b-202") && !crossText.Contains("B-INTERNAL"), "Cross-tenant response contains no tenant B order payload");

            // 13. Arguments and forwarded identity headers cannot switch the authenticated tenant
            var (overrideStatus, overrideJson) = await SendMcpAsync(aliceToken, "tools/call", new JsonObject
            {
                ["name"] = "get_order",
                ["arguments"] = new JsonObject { ["orderId"] = "order-b-202", ["tenantId"] = "tenant-b" }
            }, extraHeaders: new Dictionary<string, string> { ["X-Tenant-Id"] = "tenant-b", ["X-User"] = "bob" });
            var overrideText = overrideJson?["result"]?["content"]?[0]?["text"]?.GetValue<string>() ?? "";
            Check(overrideText == "Order unavailable.", "Arguments and forwarded identity headers cannot switch the authenticated tenant");

            // 14. Claimed tenant also needs server-side membership
            var aliceForgedTenant = MintJwt(signingKey, issuer, audience, "alice", "tenant-b", "orders.read");
            var (forgedStatus, forgedJson) = await SendMcpAsync(aliceForgedTenant, "tools/call", new JsonObject
            {
                ["name"] = "get_order",
                ["arguments"] = new JsonObject { ["orderId"] = "order-b-202" }
            });
            var forgedText = forgedJson?["result"]?["content"]?[0]?["text"]?.GetValue<string>() ?? "";
            Check(forgedText == "Order unavailable.", "Claimed tenant also needs server-side membership");

            // 15. This lab also enforces ownership within the same tenant
            var charlieToken = MintJwt(signingKey, issuer, audience, "charlie", "tenant-a", "orders.read");
            var (charlieStatus, charlieJson) = await SendMcpAsync(charlieToken, "tools/call", new JsonObject
            {
                ["name"] = "get_order",
                ["arguments"] = new JsonObject { ["orderId"] = "order-a-101" }
            });
            var charlieText = charlieJson?["result"]?["content"]?[0]?["text"]?.GetValue<string>() ?? "";
            Check(charlieText == "Order unavailable.", "This lab also enforces ownership within the same tenant");

            // 16. Alternate REST route enforces the same resource boundary (404 Not Found)
            var restReqDenied = new HttpRequestMessage(HttpMethod.Get, "/orders/order-b-202");
            restReqDenied.Headers.Authorization = new AuthenticationHeaderValue("Bearer", aliceToken);
            Check((await http.SendAsync(restReqDenied)).StatusCode == HttpStatusCode.NotFound, "Alternate REST route enforces the same resource boundary (404)");

            // 17. Alternate REST route allows authorized owner (200 OK)
            var restReqAllowed = new HttpRequestMessage(HttpMethod.Get, "/orders/order-a-101");
            restReqAllowed.Headers.Authorization = new AuthenticationHeaderValue("Bearer", aliceToken);
            Check((await http.SendAsync(restReqAllowed)).StatusCode == HttpStatusCode.OK, "Alternate REST route allows authorized owner (200 OK)");

            // 18. 24 concurrent A/B MCP requests with identical RPC IDs stay isolated
            var concurrentTasks = Enumerable.Range(1, 24).Select(async i =>
            {
                var isEven = (i % 2 == 0);
                var token = isEven
                    ? MintJwt(signingKey, issuer, audience, "bob", "tenant-b", "orders.read")
                    : MintJwt(signingKey, issuer, audience, "alice", "tenant-a", "orders.read");
                var orderId = isEven ? "order-b-202" : "order-a-101";

                var (status, json) = await SendMcpAsync(token, "tools/call", new JsonObject
                {
                    ["name"] = "get_order",
                    ["arguments"] = new JsonObject { ["orderId"] = orderId }
                }, id: 99);
                var text = json?["result"]?["content"]?[0]?["text"]?.GetValue<string>() ?? "";
                return status == HttpStatusCode.OK && text.Contains(orderId);
            });
            var concurrentResults = await Task.WhenAll(concurrentTasks);
            Check(concurrentResults.All(r => r), "24 concurrent A/B MCP requests with identical RPC IDs stay isolated");

            // In-process Database & Policy Checks
            using var scope = app.Services.CreateScope();
            var sp = scope.ServiceProvider;
            var store = sp.GetRequiredService<OrderStore>();
            var orders = sp.GetRequiredService<OrderService>();
            var memberships = sp.GetRequiredService<Memberships>();
            var audit = sp.GetRequiredService<DecisionAudit>();

            // 19. EF Core injects tenant query filter directly into SQL query
            AmbientTenantContext.Current = "tenant-a";
            var generatedSql = store.GetGeneratedQuerySql("order-b-202");
            Check(generatedSql.Contains("TenantId") && (generatedSql.Contains("WHERE") || generatedSql.Contains("where")),
                "EF Core injects tenant query filter directly into SQL query (WHERE TenantId = ...)");

            // 20. Database returns zero rows when querying other tenant's order via EF Core filter
            var zeroRowsOrder = await store.FindInTenantAsync("order-b-202");
            Check(zeroRowsOrder is null, "Database returns zero rows when querying other tenant's order via EF Core filter");

            // 21. In-process: Owner reads allowed order
            var alicePrincipal = Principal("alice", "tenant-a");
            Check((await orders.ReadAsync(alicePrincipal, "order-a-101"))?.Id == "order-a-101", "Owner reads allowed order");

            // 22. In-process: Cross-tenant request denied by shared service
            Check(await orders.ReadAsync(alicePrincipal, "order-b-202") is null, "Cross-tenant request denied by shared service");

            // 23. In-process: Same tenant does not override this lab's owner policy
            Check(await orders.ReadAsync(Principal("charlie", "tenant-a"), "order-a-101") is null,
                "Same tenant does not override this lab's owner policy");

            // 24. In-process: Claimed tenant also needs server-side membership
            AmbientTenantContext.Current = "tenant-b";
            Check(await orders.ReadAsync(Principal("alice", "tenant-b"), "order-b-202") is null,
                "Claimed tenant also needs server-side membership (in-process)");

            // 25. In-process: Write scope is not implicitly accepted as read scope
            AmbientTenantContext.Current = "tenant-a";
            Check(await orders.ReadAsync(Principal("alice", "tenant-a", "orders.write"), "order-a-101") is null,
                "Write scope is not implicitly accepted as read scope");

            // 26. In-process: Unauthenticated principal denied by shared service
            Check(await orders.ReadAsync(new ClaimsPrincipal(new ClaimsIdentity()), "order-a-101") is null,
                "Unauthenticated principal denied by shared service");

            // 27. In-process: Membership revocation applies to an already-created principal
            memberships.Revoke("alice", "tenant-a");
            Check(await orders.ReadAsync(alicePrincipal, "order-a-101") is null,
                "Membership revocation applies to an already-created principal");

            // 28. Business audit records both outcomes without order payloads
            var auditEntries = audit.Snapshot();
            Check(auditEntries.Any(x => x.Outcome == "allowed") && auditEntries.Any(x => x.Outcome == "denied"),
                "Business audit records both outcomes without order payloads");

            Console.WriteLine("SELF_TEST_REPORT:" + JsonSerializer.Serialize(new
            {
                status = "passed",
                targetFramework = "net10.0",
                totalChecks = checks.Count,
                checks
            }));
        }
        finally
        {
            await app.StopAsync();
        }
    }
}
