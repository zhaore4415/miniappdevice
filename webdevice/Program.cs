using System.Collections.Concurrent;
using System.IO.Compression;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Text.Json.Serialization;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();
builder.Services.AddCors(o => o.AddDefaultPolicy(p => p.AllowAnyOrigin().AllowAnyHeader().AllowAnyMethod()));
builder.Services.AddDbContext<AppDb>(o => o.UseSqlite("Data Source=app.db"));
builder.Services.AddSingleton<AuthService>();
builder.Services.ConfigureHttpJsonOptions(o => o.SerializerOptions.Converters.Add(new JsonStringEnumConverter()));
var app = builder.Build();
app.UseSwagger();
app.UseSwaggerUI();
app.UseCors();
app.Use(async (ctx, next) =>
{
    var path = ctx.Request.Path.Value?.ToLowerInvariant() ?? "";
    var auth = ctx.RequestServices.GetRequiredService<AuthService>();
    var protectedPages = new[] { "/", "/index.html" };
    if (protectedPages.Contains(path) && !auth.IsAuthed(ctx))
    {
        var qs = ctx.Request.QueryString.Value ?? "";
        ctx.Response.Redirect("/login.html" + qs);
        return;
    }
    await next();
});
app.UseDefaultFiles();
app.UseStaticFiles();

app.MapGet("/api/devices", async ([FromQuery] string? q, [FromQuery] DeviceStatus? status, [FromQuery] string? product, [FromQuery] int? page, [FromQuery] int? pageSize, AppDb db, HttpContext ctx) =>
{
    var queryable = db.Devices.AsNoTracking().AsQueryable();
    if (status.HasValue) queryable = queryable.Where(d => d.Status == status.Value);
    if (!string.IsNullOrWhiteSpace(q))
        queryable = queryable.Where(d => (d.SN != null && EF.Functions.Like(d.SN, $"%{q}%")) || (d.Name != null && EF.Functions.Like(d.Name, $"%{q}%")));
    if (!string.IsNullOrWhiteSpace(product))
        queryable = queryable.Where(d => d.Product == product);
    var total = await queryable.CountAsync();
    var p = page.GetValueOrDefault(1);
    var ps = pageSize.GetValueOrDefault(20);
    if (p < 1) p = 1;
    if (ps < 1) ps = 20;
    var skip = (p - 1) * ps;
    var result = await queryable.OrderBy(d => d.SN).Skip(skip).Take(ps).ToListAsync();
    ctx.Response.Headers["X-Total-Count"] = total.ToString();
    ctx.Response.Headers["X-Page"] = p.ToString();
    ctx.Response.Headers["X-Page-Size"] = ps.ToString();
    return Results.Ok(result);
});

app.MapGet("/api/devices/{sn}", async (string sn, AppDb db) =>
{
    var d = await db.Devices.AsNoTracking().FirstOrDefaultAsync(x => x.SN == sn);
    return d is null ? Results.NotFound(new { message = "设备不存在" }) : Results.Ok(d);
});

app.MapPost("/api/devices/register", async ([FromBody] IEnumerable<Device> items, AppDb db, HttpContext ctx) =>
{
    var auth = ctx.RequestServices.GetRequiredService<AuthService>();
    if (!auth.IsAuthed(ctx)) return Results.Unauthorized();
    var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
    foreach (var d in items)
    {
        if (string.IsNullOrWhiteSpace(d.SN)) continue;
        if (!seen.Add(d.SN)) continue;
        var existing = await db.Devices.FirstOrDefaultAsync(x => x.SN == d.SN);
        if (existing is null) { db.Devices.Add(d); }
        else
        {
            existing.Name = d.Name;
            existing.Model = d.Model;
            existing.Owner = d.Owner;
            existing.OwnerPhone = d.OwnerPhone;
            existing.Product = d.Product ?? existing.Product;
            db.Devices.Update(existing);
        }
    }
    await db.SaveChangesAsync();
    return Results.Ok(new { count = seen.Count });
});

app.MapPut("/api/devices/{sn}", async (string sn, [FromBody] DeviceUpdateRequest req, AppDb db, HttpContext ctx) =>
{
    var auth = ctx.RequestServices.GetRequiredService<AuthService>();
    if (!auth.IsAuthed(ctx)) return Results.Unauthorized();
    var d = await db.Devices.FirstOrDefaultAsync(x => x.SN == sn);
    if (d is null) return Results.NotFound(new { message = "设备不存在" });
    if (req.Name != null) d.Name = string.IsNullOrWhiteSpace(req.Name) ? null : req.Name;
    if (req.Model != null) d.Model = string.IsNullOrWhiteSpace(req.Model) ? null : req.Model;
    if (req.Owner != null) d.Owner = string.IsNullOrWhiteSpace(req.Owner) ? null : req.Owner;
    if (req.OwnerPhone != null) d.OwnerPhone = string.IsNullOrWhiteSpace(req.OwnerPhone) ? null : req.OwnerPhone;
    if (req.LastShipAddress != null) d.LastShipAddress = string.IsNullOrWhiteSpace(req.LastShipAddress) ? null : req.LastShipAddress;
    if (req.Product != null) d.Product = string.IsNullOrWhiteSpace(req.Product) ? null : req.Product;
    if (req.Remark != null) d.Remark = string.IsNullOrWhiteSpace(req.Remark) ? null : req.Remark;
    db.Devices.Update(d);
    await db.SaveChangesAsync();
    return Results.Ok(d);
});
app.MapDelete("/api/devices", async ([FromBody] DeleteRequest req, AppDb db, HttpContext ctx) =>
{
    var auth = ctx.RequestServices.GetRequiredService<AuthService>();
    if (!auth.IsAuthed(ctx)) return Results.Unauthorized();
    if (req.SNs is null || req.SNs.Count == 0) return Results.BadRequest(new { message = "无 SN" });
    var toDelete = await db.Devices.Where(d => req.SNs.Contains(d.SN)).ToListAsync();
    var logDel = db.Logs.Where(l => req.SNs.Contains(l.SN));
    db.Devices.RemoveRange(toDelete);
    db.Logs.RemoveRange(logDel);
    var count = await db.SaveChangesAsync();
    return Results.Ok(new { deleted = toDelete.Count });
});

app.MapPost("/api/devices/ship", async ([FromBody] ShipRequest req, AppDb db, HttpContext ctx) =>
{
    var auth = ctx.RequestServices.GetRequiredService<AuthService>();
    if (!auth.IsAuthed(ctx)) return Results.Unauthorized();
    try
    {
        var d = await db.Devices.FirstOrDefaultAsync(x => x.SN == req.SN);
        if (d is null) return Results.NotFound(new { message = "设备未登记" });
        if (d.Status == DeviceStatus.Shipping)
            return Results.BadRequest(new { message = "该设备已在寄出中" });
        d.Status = DeviceStatus.Shipping;
        d.LastShipAddress = req.Address;
        d.LastShipBy = req.Operator;
        d.LastShipAt = req.ShipAt ?? DateTimeOffset.UtcNow;
        d.LastEventAt = d.LastShipAt;
        db.Devices.Update(d);
        var at = d.LastShipAt!.Value;
        while (await db.Logs.AnyAsync(l => l.SN == req.SN && l.At == at)) at = at.AddTicks(1);
        db.Logs.Add(new OperationLog { SN = req.SN, Action = "寄出", Operator = req.Operator, At = at, Address = req.Address });
        await db.SaveChangesAsync();
        return Results.Ok(d);
    }
    catch (DbUpdateException ex)
    {
        return Results.BadRequest(new { message = ex.InnerException?.Message ?? ex.Message });
    }
    catch (Exception ex)
    {
        return Results.BadRequest(new { message = ex.Message });
    }
});

app.MapPost("/api/devices/return", async ([FromBody] ReturnRequest req, AppDb db, HttpContext ctx) =>
{
    var auth = ctx.RequestServices.GetRequiredService<AuthService>();
    if (!auth.IsAuthed(ctx)) return Results.Unauthorized();
    try
    {
        var d = await db.Devices.FirstOrDefaultAsync(x => x.SN == req.SN);
        if (d is null) return Results.NotFound(new { message = "设备未登记" });
        if (d.Status == DeviceStatus.Idle)
            return Results.BadRequest(new { message = "设备已空闲，无需归还" });
        d.Status = DeviceStatus.Idle;
        d.LastReturnAt = req.ReturnAt ?? DateTimeOffset.UtcNow;
        d.LastEventAt = d.LastReturnAt;
        db.Devices.Update(d);
        var at = d.LastReturnAt!.Value;
        while (await db.Logs.AnyAsync(l => l.SN == req.SN && l.At == at)) at = at.AddTicks(1);
        db.Logs.Add(new OperationLog { SN = req.SN, Action = "归还", Operator = req.Operator, At = at, Address = null });
        await db.SaveChangesAsync();
        return Results.Ok(d);
    }
    catch (DbUpdateException ex)
    {
        return Results.BadRequest(new { message = ex.InnerException?.Message ?? ex.Message });
    }
    catch (Exception ex)
    {
        return Results.BadRequest(new { message = ex.Message });
    }
});

app.MapGet("/api/logs/{sn}", async (string sn, AppDb db) =>
{
    try
    {
        var logs = await db.Logs.AsNoTracking().Where(x => x.SN == sn).ToListAsync();
        return Results.Ok(logs.OrderByDescending(x => x.At).ToList());
    }
    catch (Exception ex)
    {
        return Results.BadRequest(new { message = ex.Message });
    }
});

app.MapGet("/api/devices/{sn}/history", async (string sn, [FromQuery] int? limit, AppDb db) =>
{
    try
    {
        var logs = await db.Logs.AsNoTracking().Where(x => x.SN == sn).ToListAsync();
        logs = logs.OrderBy(x => x.At).ToList();
        var stack = new Stack<OperationLog>();
        var items = new List<ShipHistoryItem>();
        foreach (var l in logs)
        {
            if (string.Equals(l.Action, "寄出", StringComparison.OrdinalIgnoreCase))
            {
                stack.Push(l);
            }
            else if (string.Equals(l.Action, "归还", StringComparison.OrdinalIgnoreCase))
            {
                if (stack.Count > 0)
                {
                    var s = stack.Pop();
                    var dur = (long)(l.At - s.At).TotalSeconds;
                    items.Add(new ShipHistoryItem(sn, s.At, s.Address, s.Operator, l.At, l.Operator, dur));
                }
                else
                {
                    items.Add(new ShipHistoryItem(sn, null, null, null, l.At, l.Operator, null));
                }
            }
        }
        while (stack.Count > 0)
        {
            var s = stack.Pop();
            items.Add(new ShipHistoryItem(sn, s.At, s.Address, s.Operator, null, null, null));
        }
        items = items.OrderByDescending(x => x.ShipAt ?? x.ReturnAt).ToList();
        var lim = limit.GetValueOrDefault(16);
        if (lim > 0) items = items.Take(lim).ToList();
        if (items.Count == 0)
        {
            var d = await db.Devices.AsNoTracking().FirstOrDefaultAsync(x => x.SN == sn);
            if (d != null && (d.LastShipAt != null || d.LastReturnAt != null))
            {
                items.Add(new ShipHistoryItem(sn, d.LastShipAt, d.LastShipAddress, d.LastShipBy, d.LastReturnAt, null, d.LastShipAt != null && d.LastReturnAt != null ? (long)(d.LastReturnAt.Value - d.LastShipAt.Value).TotalSeconds : null));
            }
        }
        return Results.Ok(items);
    }
    catch (Exception ex)
    {
        try
        {
            var d = await db.Devices.AsNoTracking().FirstOrDefaultAsync(x => x.SN == sn);
            var items = new List<ShipHistoryItem>();
            if (d != null && (d.LastShipAt != null || d.LastReturnAt != null))
            {
                items.Add(new ShipHistoryItem(sn, d.LastShipAt, d.LastShipAddress, d.LastShipBy, d.LastReturnAt, null, d.LastShipAt != null && d.LastReturnAt != null ? (long)(d.LastReturnAt.Value - d.LastShipAt.Value).TotalSeconds : null));
            }
            return Results.Ok(items);
        }
        catch
        {
            return Results.BadRequest(new { message = ex.Message });
        }
    }
});

app.MapPost("/api/qrcode/batch", async ([FromBody] QrBatchRequest req, HttpContext ctx) =>
{
    try
    {
        if (req.SNs is null || req.SNs.Count == 0)
            return Results.BadRequest(new { message = "sn 列表为空" });
        using var ms = new MemoryStream();
        using (var zip = new ZipArchive(ms, ZipArchiveMode.Create, true))
        {
            foreach (var sn in req.SNs)
            {
                var url = $"{ctx.Request.Scheme}://{ctx.Request.Host}/?sn={Uri.EscapeDataString(sn)}";
                var pngBytes = QrGenerator.GeneratePng(url);
                var entry = zip.CreateEntry($"{sn}.png");
                await using var es = entry.Open();
                await es.WriteAsync(pngBytes, 0, pngBytes.Length);
            }
        }
        var bytes = ms.ToArray();
        return Results.File(bytes, "application/zip", "qrcodes.zip");
    }
    catch (Exception ex)
    {
        return Results.BadRequest(new { message = ex.Message });
    }
});

app.MapGet("/api/qrcode/png", ([FromQuery] string sn, [FromQuery] string? token, [FromQuery] string? u, [FromQuery] string? p, HttpContext ctx) =>
{
    var url = $"{ctx.Request.Scheme}://{ctx.Request.Host}/?sn={Uri.EscapeDataString(sn)}";
    if (!string.IsNullOrEmpty(token)) url += $"&token={Uri.EscapeDataString(token)}";
    var png = QrGenerator.GeneratePng(url);
    return Results.File(png, "image/png");
});

app.MapPost("/api/auth/login", async ([FromBody] LoginRequest req, AppDb db, HttpContext ctx) =>
{
    var user = await db.Users.FirstOrDefaultAsync(u => u.Username == req.Username);
    if (user is null) return Results.Unauthorized();
    var ok = PasswordHasher.Verify(req.Password, user.PasswordHash, user.Salt);
    if (!ok) return Results.Unauthorized();
    var auth = ctx.RequestServices.GetRequiredService<AuthService>();
    var token = auth.CreateSession(user.Username);
    ctx.Response.Cookies.Append("auth", token, new CookieOptions { HttpOnly = true, SameSite = SameSiteMode.Lax });
    return Results.Ok(new { username = user.Username });
});

app.MapPost("/api/auth/logout", (HttpContext ctx) =>
{
    var auth = ctx.RequestServices.GetRequiredService<AuthService>();
    var token = ctx.Request.Cookies["auth"];
    if (token != null) auth.RemoveSession(token);
    ctx.Response.Cookies.Delete("auth");
    return Results.Ok();
});

app.MapGet("/api/auth/me", (HttpContext ctx) =>
{
    var auth = ctx.RequestServices.GetRequiredService<AuthService>();
    var me = auth.GetUser(ctx);
    return me is null ? Results.Unauthorized() : Results.Ok(new { username = me });
});

app.MapPost("/api/auth/create-token", async (HttpContext ctx, AppDb db) =>
{
    var auth = ctx.RequestServices.GetRequiredService<AuthService>();
    var me = auth.GetUser(ctx);
    if (me is null) return Results.Unauthorized();
    var t = new AuthToken { Token = Guid.NewGuid().ToString("N"), Username = me, ExpireAt = DateTimeOffset.UtcNow.AddMinutes(30), Consumed = false };
    db.AuthTokens.Add(t);
    await db.SaveChangesAsync();
    return Results.Ok(new TokenCreateResponse(t.Token, t.ExpireAt));
});

app.MapPost("/api/auth/login-token", async ([FromBody] TokenLoginRequest req, AppDb db, HttpContext ctx) =>
{
    var t = await db.AuthTokens.FirstOrDefaultAsync(x => x.Token == req.Token);
    if (t is null) return Results.Unauthorized();
    if (t.Consumed || t.ExpireAt < DateTimeOffset.UtcNow) return Results.Unauthorized();
    var auth = ctx.RequestServices.GetRequiredService<AuthService>();
    var cookieToken = auth.CreateSession(t.Username);
    ctx.Response.Cookies.Append("auth", cookieToken, new CookieOptions { HttpOnly = true, SameSite = SameSiteMode.Lax });
    t.Consumed = true;
    db.AuthTokens.Update(t);
    await db.SaveChangesAsync();
    return Results.Ok(new { username = t.Username });
});
using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<AppDb>();
    db.Database.EnsureCreated();
    using var conn = db.Database.GetDbConnection();
    conn.Open();
    bool HasCol(string name)
    {
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "PRAGMA table_info(Devices)";
        using var r = cmd.ExecuteReader();
        while (r.Read())
        {
            var col = r.GetString(1);
            if (string.Equals(col, name, StringComparison.OrdinalIgnoreCase)) return true;
        }
        return false;
    }
    if (!HasCol("Product")) db.Database.ExecuteSqlRaw("ALTER TABLE Devices ADD COLUMN Product TEXT");
    if (!HasCol("LastEventAt")) db.Database.ExecuteSqlRaw("ALTER TABLE Devices ADD COLUMN LastEventAt TEXT");
    if (!HasCol("Remark")) db.Database.ExecuteSqlRaw("ALTER TABLE Devices ADD COLUMN Remark TEXT");
    db.Database.ExecuteSqlRaw("UPDATE Devices SET LastEventAt = COALESCE(LastReturnAt, LastShipAt) WHERE LastEventAt IS NULL AND (LastReturnAt IS NOT NULL OR LastShipAt IS NOT NULL)");
    if (!await db.Users.AnyAsync())
    {
        var (hash, salt) = PasswordHasher.Hash("admin123");
        db.Users.Add(new User { Username = "admin", PasswordHash = hash, Salt = salt });
        await db.SaveChangesAsync();
    }
}
app.Run();

public enum DeviceStatus
{
    Idle,
    Shipping,
    Returned,
    Repairing,
    Scrapped
}

public record Device
{
    public string SN { get; set; } = string.Empty;
    public string? Name { get; set; }
    public string? Model { get; set; }
    public string? Owner { get; set; }
    public string? OwnerPhone { get; set; }
    public string? Product { get; set; }
    public string? Remark { get; set; }
    public DeviceStatus Status { get; set; } = DeviceStatus.Idle;
    public string? LastShipAddress { get; set; }
    public string? LastShipBy { get; set; }
    public DateTimeOffset? LastShipAt { get; set; }
    public DateTimeOffset? ExpectedReturnAt { get; set; }
    public DateTimeOffset? LastReturnAt { get; set; }
    public DateTimeOffset? LastEventAt { get; set; }
}

public record ShipRequest(string SN, string Address, string? Operator, DateTimeOffset? ShipAt);
public record ReturnRequest(string SN, string? Operator, DateTimeOffset? ReturnAt);
public record QrBatchRequest(List<string> SNs);
public record LoginRequest(string Username, string Password);
public record DeviceUpdateRequest(string? Name, string? Model, string? Owner, string? OwnerPhone, string? LastShipAddress, string? Product, string? Remark);
public record TokenLoginRequest(string Token);
public record TokenCreateResponse(string Token, DateTimeOffset ExpireAt);
public record DeleteRequest(List<string> SNs);
public record ShipHistoryItem(string SN, DateTimeOffset? ShipAt, string? ShipAddress, string? ShipOperator, DateTimeOffset? ReturnAt, string? ReturnOperator, long? DurationSeconds);

public record OperationLog
{
    public string SN { get; init; } = string.Empty;
    public string Action { get; init; } = string.Empty;
    public string? Operator { get; init; }
    public DateTimeOffset At { get; init; }
    public string? Address { get; init; }
}

public class AppDb : DbContext
{
    public AppDb(DbContextOptions<AppDb> options) : base(options) { }
    public DbSet<Device> Devices => Set<Device>();
    public DbSet<OperationLog> Logs => Set<OperationLog>();
    public DbSet<User> Users => Set<User>();
    public DbSet<AuthToken> AuthTokens => Set<AuthToken>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<Device>().HasKey(d => d.SN);
        modelBuilder.Entity<OperationLog>().HasKey(l => new { l.SN, l.At });
        modelBuilder.Entity<User>().HasKey(u => u.Username);
        modelBuilder.Entity<AuthToken>().HasKey(t => t.Token);
    }
}

public record User
{
    public string Username { get; set; } = string.Empty;
    public string PasswordHash { get; set; } = string.Empty;
    public string Salt { get; set; } = string.Empty;
}

public record AuthToken
{
    public string Token { get; set; } = string.Empty;
    public string Username { get; set; } = string.Empty;
    public DateTimeOffset ExpireAt { get; set; }
    public bool Consumed { get; set; }
}

public class AuthService
{
    private readonly ConcurrentDictionary<string, (string user, DateTimeOffset expire)> _sessions = new();
    public string CreateSession(string username)
    {
        var token = Guid.NewGuid().ToString("N");
        _sessions[token] = (username, DateTimeOffset.UtcNow.AddHours(8));
        return token;
    }
    public bool IsAuthed(HttpContext ctx)
    {
        var token = ctx.Request.Cookies["auth"];
        if (token == null) return false;
        if (!_sessions.TryGetValue(token, out var s)) return false;
        if (s.expire < DateTimeOffset.UtcNow) { _sessions.TryRemove(token, out _); return false; }
        return true;
    }
    public string? GetUser(HttpContext ctx)
    {
        var token = ctx.Request.Cookies["auth"];
        if (token == null) return null;
        return _sessions.TryGetValue(token, out var s) ? s.user : null;
    }
    public void RemoveSession(string token) => _sessions.TryRemove(token, out _);
}

public static class PasswordHasher
{
    public static (string hash, string salt) Hash(string password)
    {
        var saltBytes = Guid.NewGuid().ToByteArray();
        using var derive = new System.Security.Cryptography.Rfc2898DeriveBytes(password, saltBytes, 100_000, System.Security.Cryptography.HashAlgorithmName.SHA256);
        var hash = Convert.ToBase64String(derive.GetBytes(32));
        var salt = Convert.ToBase64String(saltBytes);
        return (hash, salt);
    }
    public static bool Verify(string password, string hash, string salt)
    {
        var saltBytes = Convert.FromBase64String(salt);
        using var derive = new System.Security.Cryptography.Rfc2898DeriveBytes(password, saltBytes, 100_000, System.Security.Cryptography.HashAlgorithmName.SHA256);
        var check = Convert.ToBase64String(derive.GetBytes(32));
        return check == hash;
    }
}

public static class QrGenerator
{
    public static byte[] GeneratePng(string content)
    {
        using var gen = new QRCoder.QRCodeGenerator();
        using var data = gen.CreateQrCode(content, QRCoder.QRCodeGenerator.ECCLevel.Q);
        var qr = new QRCoder.PngByteQRCode(data);
        return qr.GetGraphic(12);
    }
}
