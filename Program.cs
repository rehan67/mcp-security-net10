using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.IdentityModel.Tokens;
using ModelContextProtocol.AspNetCore;

var builder = WebApplication.CreateBuilder(args);
// This JWT-only disposable lab does not need a persistent cookie-protection key ring.
builder.Services.AddDataProtection().UseEphemeralDataProtectionProvider();

// This educational host intentionally runs only on loopback in Development.
// Its local signed tokens are test credentials, not a full OAuth server.
if (!builder.Environment.IsDevelopment())
    throw new InvalidOperationException("Run this synthetic lab in Development only.");
var listen = builder.Configuration["urls"] ?? "http://127.0.0.1:7047";
if (!Uri.TryCreate(listen, UriKind.Absolute, out var endpoint) ||
    endpoint.Host != "127.0.0.1" || endpoint.Scheme != "http")
    throw new InvalidOperationException("The lab must bind to http://127.0.0.1 only.");
builder.WebHost.UseUrls(listen);

var signingKey = Environment.GetEnvironmentVariable("MCP_LAB_SIGNING_KEY")
    ?? throw new InvalidOperationException("Set a fresh MCP_LAB_SIGNING_KEY for this run.");
if (Encoding.UTF8.GetByteCount(signingKey) < 32)
    throw new InvalidOperationException("The local signing key must contain at least 32 bytes.");
var issuer = "urn:rehan:mcp-security-lab:issuer";
var audience = listen + "/mcp";

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.MapInboundClaims = false;
        options.IncludeErrorDetails = false;
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = issuer,
            ValidateAudience = true,
            ValidAudience = audience,
            ValidateLifetime = true,
            RequireExpirationTime = true,
            ClockSkew = TimeSpan.Zero,
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(signingKey)),
            ValidAlgorithms = [SecurityAlgorithms.HmacSha256],
            NameClaimType = "sub"
        };
    });
builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("orders.read", policy => policy
        .RequireAuthenticatedUser()
        .RequireAssertion(ctx => OrderPermissions.HasReadScope(ctx.User)));
});
builder.Services.AddSingleton<IAuthorizationHandler, OrderReadHandler>();
builder.Services.AddSingleton<Memberships>();
builder.Services.AddSingleton<OrderStore>();
builder.Services.AddSingleton<DecisionAudit>();
builder.Services.AddScoped<OrderService>();
builder.Services.AddHttpContextAccessor();
builder.Services.AddMcpServer()
    .WithHttpTransport(options => options.SessionMode = HttpServerSessionMode.Stateless)
    .AddAuthorizationFilters()
    .WithTools<OrderTools>();

var app = builder.Build();
if (builder.Configuration.GetValue<bool>("self-test"))
{
    await PolicySelfTests.RunAsync(app.Services);
    return;
}
app.UseAuthentication();
app.UseAuthorization();
app.MapGet("/health", () => Results.Ok(new { status = "synthetic-local-lab" }));
app.MapMcp("/mcp").RequireAuthorization();

// An alternate HTTP entry point uses the SAME business authorization service.
app.MapGet("/orders/{orderId}", async (string orderId, HttpContext http,
    OrderService service, CancellationToken cancellationToken) =>
{
    var result = await service.ReadAsync(http.User, orderId, cancellationToken);
    return result is null ? Results.NotFound() : Results.Ok(result);
}).RequireAuthorization("orders.read");

// There is no unsecured token minting, membership admin, SQL or shell endpoint.
app.Run();
