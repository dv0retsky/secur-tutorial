|||
|---|---|
|ДИСЦИПЛИНА|Методы защиты информации
|ИНСТИТУТ|ИПИТ
|КАФЕДРА|передовых технологий
|ВИД УЧЕБНОГО МАТЕРИАЛА|Методические указания к практическим занятиям|
|ПРЕПОДАВАТЕЛЬ|Дворецкий Артур Геннадьевич|
|СЕМЕСТР|3 семестр, 2026/2027 уч. год|

Ссылка на материал: <br>
https://github.com/dv0retsky/fastapi-tutorial/blob/main/FAPI1_Introduction/FAPI1_Introduction.md

---

# Практическое занятие 9: XSS, CSRF и Clickjacking: защита веб-приложения

# Часть I. XSS

## 1. Почему браузер доверяет коду страницы

Когда браузер получает HTML-документ с сайта, он предполагает, что находящиеся в нём HTML и JavaScript сформированы самим приложением.

Например:

```html
<h1>Профиль пользователя</h1>
<script>
    console.log("Страница загружена");
</script>
```

Если сервер случайно вставляет в страницу пользовательские данные как HTML-код, браузер не может автоматически определить, что часть содержимого ввёл злоумышленник.

Отсюда возникает фундаментальная проблема:

```text
пользовательские данные
        ↓
попадают в HTML без экранирования
        ↓
браузер воспринимает их как разметку или JavaScript
        ↓
код выполняется в контексте сайта
```

Так появляется XSS.

---

## 2. Что такое XSS

**Cross-Site Scripting (XSS)** — класс уязвимостей веб-приложений, при которых неконтролируемые данные становятся частью HTML/JavaScript страницы и могут привести к выполнению сценария в браузере пользователя.

Важно понимать, что вредоносный код выполняется не «сам по себе», а **с полномочиями страницы**, на которой он оказался.

Из-за этого XSS может использоваться для изменения содержимого страницы, подмены элементов интерфейса, выполнения действий от имени пользователя, чтения части данных страницы и доступа к cookie, если они доступны JavaScript.

---

## 3. Reflected XSS

**Reflected XSS** возникает, когда приложение получает значение из запроса и сразу вставляет его в HTML-ответ.

Например:

```text
/search?q=hello
```

может привести к отображению:

```html
Результаты поиска: hello
```

Если `q` выводится без экранирования, HTML-разметка из параметра тоже попадёт в страницу.

### Уязвимый шаблон Jinja2

```html
{% if search_query %}
<div class="search-results">
    Результаты поиска:
    <strong>{{ search_query|safe }}</strong>
</div>
{% endif %}
```

Фильтр:

```text
|safe
```

явно сообщает Jinja2: «это значение уже безопасно, не экранируй его».

Если значение поступило от пользователя, такое решение опасно.

---

## 4. Практика: Reflected XSS в MiniBank

Откройте учебное приложение и авторизуйтесь.

Перейдите к поиску по гостевой книге и сначала выполните обычный поиск:

```text
alice
```

Затем в локальной лаборатории можно проверить обработку HTML тестовым значением:

```html
<script>alert('XSS')</script>
```

Если страница создаёт всплывающее окно, это означает, что браузер получил пользовательский текст как исполняемый HTML/JavaScript.

Здесь важен не сам `alert`, а факт:

> сервер не разделил пользовательские данные и активный код страницы.

---

## 5. Чем опасен Reflected XSS

В простейшем учебном примере результат — всплывающее окно. В реальной атаке злоумышленник может попытаться заставить пользователя открыть специально сформированную ссылку.

Пользователь при этом может видеть настоящий домен приложения, поэтому внедрённая поддельная форма или изменённый интерфейс могут выглядеть убедительно.

Reflected XSS — это не только риск чтения cookie. Более общий эффект — выполнение недоверенного JavaScript в доверенном контексте.

---

## 6. Исправление Reflected XSS

### Способ 1. Не отключать автоэкранирование

Было:

```html
<strong>{{ search_query|safe }}</strong>
```

Должно быть:

```html
<strong>{{ search_query }}</strong>
```

Jinja2 автоматически преобразует специальные символы HTML. Поэтому строка:

```html
<script>alert('XSS')</script>
```

будет отображена как текст, а не выполнена браузером.

### Способ 2. Явное экранирование

Если обработка должна выполняться в Python:

```python
from markupsafe import escape

query = request.args.get('q', '')
query_safe = escape(query)
```

Однако в шаблонных приложениях предпочтительнее правильно использовать штатное автоэкранирование.

---

## 7. Stored XSS

**Stored XSS** отличается тем, что вредоносные данные сохраняются сервером, например в базе данных, а затем отображаются другим пользователям.

Типичная последовательность:

```text
злоумышленник отправляет комментарий
        ↓
сервер сохраняет его в БД
        ↓
другой пользователь открывает страницу
        ↓
сервер получает комментарий из БД
        ↓
браузер выполняет внедрённый код
```

Stored XSS обычно потенциально опаснее reflected-варианта, поскольку жертве необязательно переходить по специально подготовленной ссылке.

---

## 8. Уязвимость гостевой книги MiniBank

Упрощённый обработчик:

```python
@app.route('/guestbook', methods=['GET', 'POST'])
def guestbook():
    if request.method == 'POST':
        text = request.form.get('text', '')
        username = get_current_user()

        conn = get_db()
        cursor = conn.cursor()

        cursor.execute(
            "INSERT INTO comments (author, text) VALUES (?, ?)",
            (username, text)
        )

        conn.commit()
        conn.close()

        return redirect(url_for('guestbook'))
```

Обратите внимание: SQL здесь уже параметризован. Следовательно, SQL Injection в этом месте отсутствует.

Но это **не означает, что данные безопасны для HTML**.

Это хороший пример различия контекстов:

```text
безопасно для SQL
≠
безопасно для HTML
```

Одна и та же строка должна корректно обрабатываться именно для того контекста, в котором она используется.

---

## 9. Практика: Stored XSS

В гостевой книге учебного приложения добавьте комментарий:

```html
<script>alert('Stored XSS работает!')</script>
```

После отправки обновите страницу.

Если код выполнится снова после обновления, значит строка сохранилась в базе данных.

Затем войдите под другой тестовой учётной записью и откройте ту же страницу.

Если код выполняется и для другого пользователя, получен характерный признак Stored XSS: одна сохранённая запись влияет на множество посетителей.

---

## 10. Почему Stored XSS особенно опасен

При reflected-варианте часто требуется заставить пользователя открыть подготовленный URL. В Stored XSS вредоносное значение уже хранится внутри приложения.

Представим форум с тысячами пользователей. Если вредоносная запись помещена на популярную страницу, каждый её посетитель становится потенциальной жертвой.

Главная особенность Stored XSS — **масштабирование через само приложение**.

---

## 11. Защита от Stored XSS

### Выходное экранирование

Вместо:

```html
{{ comment.text|safe }}
```

используйте:

```html
{{ comment.text }}
```

### Валидация длины и формата

Например:

```python
if len(text) > 500:
    return render_template(
        'guestbook.html',
        error='Комментарий слишком длинный',
        comments=[]
    )
```

Валидация полезна, но она не заменяет экранирование.

### Санитизация

Если приложение сознательно разрешает часть HTML, требуется специализированный HTML sanitizer с белым списком допустимых тегов и атрибутов. Самодельная фильтрация HTML регулярными выражениями для этого ненадёжна.

---

## 12. Content Security Policy

**Content Security Policy (CSP)** — дополнительный механизм браузерной защиты, позволяющий ограничить источники исполняемых ресурсов.

Пример заголовка:

```http
Content-Security-Policy: default-src 'self'; script-src 'self'
```

Во Flask:

```python
@app.after_request
def add_security_headers(response):
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self' 'unsafe-inline';"
    )
    return response
```

CSP не заменяет экранирование. Она работает как дополнительный барьер в модели **Defense in Depth**.

---

## 13. HttpOnly cookies

Если cookie аутентификации доступна JavaScript:

```javascript
document.cookie
```

то XSS может попытаться её прочитать.

Атрибут:

```text
HttpOnly
```

запрещает JavaScript-доступ к cookie.

Во Flask:

```python
response.set_cookie(
    'session_user',
    user['username'],
    httponly=True,
    secure=False,
    samesite='Lax'
)
```

Для боевого HTTPS-приложения должно использоваться:

```python
secure=True
```

`HttpOnly` не устраняет XSS, но уменьшает один из наиболее опасных вариантов его развития.

---

# Часть II. CSRF

## 14. Что такое CSRF

**Cross-Site Request Forgery (CSRF)** — атака, при которой браузер авторизованного пользователя заставляют отправить нежелательный запрос на доверенный сайт.

Главная особенность CSRF состоит в том, что злоумышленнику может быть не нужен пароль пользователя. Браузер сам автоматически прикрепляет cookie к запросу.

Схема:

```text
пользователь вошёл в MiniBank
        ↓
браузер хранит session cookie
        ↓
пользователь открывает другую страницу
        ↓
эта страница отправляет POST в MiniBank
        ↓
браузер добавляет cookie MiniBank
        ↓
сервер считает запрос авторизованным
```

То есть сервер видит корректную сессию, но не может определить, действительно ли пользователь намеревался выполнить действие.

---

## 15. Уязвимая операция перевода

Упрощённый обработчик:

```python
@app.route('/transfer', methods=['GET', 'POST'])
@require_login
def transfer():
    if request.method == 'POST':
        recipient = request.form.get('recipient', '')
        amount = request.form.get('amount', 0)

        # проверка и выполнение перевода...
```

HTML:

```html
<form method="POST" action="{{ url_for('transfer') }}">
    <input type="text" name="recipient" required>
    <input type="number" name="amount" required>
    <button>Перевести</button>
</form>
```

В запросе нет дополнительного подтверждения того, что форма действительно была сформирована MiniBank.

---

## 16. Практика: демонстрация CSRF в локальной лаборатории

Создайте отдельный файл `csrf_attack.html`:

```html
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <title>Учебная страница</title>
</head>
<body>
    <h1>Учебная демонстрация CSRF</h1>

    <button onclick="document.getElementById('csrf').submit()">
        Выполнить действие
    </button>

    <form
        id="csrf"
        action="http://localhost:5000/transfer"
        method="POST"
        style="display:none"
    >
        <input name="recipient" value="admin">
        <input name="amount" value="1000">
    </form>
</body>
</html>
```

Порядок проверки:

1. войдите в MiniBank под тестовым пользователем;
2. не закрывая браузер, откройте `csrf_attack.html`;
3. инициируйте отправку формы;
4. вернитесь в MiniBank и проверьте состояние счёта.

Если операция прошла без дополнительного подтверждения со стороны MiniBank, запрос оказался уязвим для CSRF.

---

## 17. Защита с помощью CSRF-токена

Сервер генерирует случайное значение:

```python
from secrets import token_hex

csrf_token = token_hex(32)
session['csrf_token'] = csrf_token
```

и помещает его в форму:

```html
<input
    type="hidden"
    name="csrf_token"
    value="{{ csrf_token }}"
>
```

При POST-запросе сервер сравнивает:

```python
form_token = request.form.get('csrf_token', '')
session_token = session.get('csrf_token', '')

if not form_token or form_token != session_token:
    return 'CSRF attack detected!', 403
```

Атакующая страница может отправить известные поля формы, но не знает секретный CSRF-токен текущей сессии.

---

## 18. SameSite cookies

Атрибут `SameSite` сообщает браузеру, в каких межсайтовых сценариях cookie можно отправлять.

### Strict

```text
SameSite=Strict
```

Cookie не отправляется при большинстве межсайтовых переходов. Это наиболее строгий режим.

### Lax

```text
SameSite=Lax
```

Компромиссный вариант, подходящий многим приложениям. Он ограничивает отправку cookie в ряде межсайтовых запросов.

### None

```text
SameSite=None
```

Cookie может отправляться в межсайтовых сценариях, но современный браузер требует атрибут `Secure`.

Надёжное приложение обычно сочетает `SameSite` с CSRF-токенами, а не выбирает только один механизм.

---

# Часть III. Clickjacking

## 19. Что такое Clickjacking

**Clickjacking** — атака на пользовательский интерфейс, при которой поверх видимой страницы размещается прозрачный или почти прозрачный `iframe`.

Пользователь думает, что нажимает на элемент одной страницы, но фактически взаимодействует с элементом другой.

Упрощённая схема:

```text
видимая кнопка атакующей страницы
               ↓
прозрачный iframe с доверенным сайтом
               ↓
клик попадает в элемент iframe
```

---

## 20. Практика: демонстрация Clickjacking

В локальной лаборатории создайте `clickjacking.html`:

```html
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <title>Учебная демонстрация Clickjacking</title>

    <style>
        .game {
            position: relative;
            width: 500px;
            height: 400px;
            margin: 0 auto;
        }

        iframe {
            position: absolute;
            inset: 0;
            width: 100%;
            height: 100%;
            opacity: 0;
            z-index: 999;
        }

        .game:hover iframe {
            opacity: 0.4;
        }
    </style>
</head>

<body>
    <h1>Нажмите на область</h1>

    <div class="game">
        <div style="font-size:100px; text-align:center;">
            🐱
        </div>

        <iframe src="http://localhost:5000/transfer"></iframe>
    </div>
</body>
</html>
```

На практике полезно временно изменить `opacity`, чтобы визуально увидеть расположение iframe и понять механику атаки.

---

## 21. Защита от Clickjacking

### X-Frame-Options

Запретить встраивание страницы:

```http
X-Frame-Options: DENY
```

Во Flask:

```python
@app.after_request
def add_security_headers(response):
    response.headers['X-Frame-Options'] = 'DENY'
    return response
```

Также существует:

```text
SAMEORIGIN
```

которое разрешает iframe только страницам того же origin.

### CSP frame-ancestors

Современный механизм:

```http
Content-Security-Policy: frame-ancestors 'none'
```

Во Flask:

```python
response.headers['Content-Security-Policy'] = (
    "default-src 'self'; "
    "frame-ancestors 'none';"
)
```

`frame-ancestors` является более гибким современным механизмом контроля встраивания.

---

# Часть IV. Комплексное укрепление MiniBank

## 22. Почему одной защиты недостаточно

Безопасность веб-приложения редко обеспечивается единственной настройкой.

Например, экранирование защищает от многих XSS-сценариев, но ошибка может появиться в другом шаблоне. CSP уменьшает последствия XSS, но не исправляет небезопасный вывод. `HttpOnly` затрудняет чтение cookie через JavaScript, но XSS всё ещё может выполнять действия в браузере. `SameSite` помогает против CSRF, однако не заменяет проверку CSRF-токена. Параметризованные запросы закрывают SQL Injection, но не защищают от XSS или Clickjacking.

Поэтому используется принцип **Defense in Depth — эшелонированная защита**.

---

## 23. Защищённая конфигурация заголовков

Пример:

```python
@app.after_request
def add_security_headers(response):
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self' 'unsafe-inline'; "
        "frame-ancestors 'none';"
    )

    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-Content-Type-Options'] = 'nosniff'

    return response
```

Для cookie:

```python
response.set_cookie(
    'session_user',
    user['username'],
    httponly=True,
    secure=True,
    samesite='Strict'
)
```

В локальной лаборатории без HTTPS параметр `secure=True` помешает отправке cookie, поэтому при тестировании `http://localhost` его временно оставляют `False`. Это ограничение учебной среды, а не рекомендуемая настройка production-системы.

---

## 24. Защищённый обработчик SQL

```python
query = """
SELECT *
FROM users
WHERE username=?
  AND password=?
"""

cursor.execute(query, (username, password))
```

Параметры передаются отдельно от структуры запроса.

---

## 25. Защищённый вывод пользовательского текста

В Jinja2:

```html
{{ comment.text }}
```

а не:

```html
{{ comment.text|safe }}
```

Если приложение должно принимать форматированный HTML, необходим отдельный механизм санитизации с белым списком разрешённых тегов.

---

## 26. Защищённая форма перевода

Генерация токена:

```python
csrf_token = token_hex(32)
session['csrf_token'] = csrf_token
```

Шаблон:

```html
<form method="POST" action="{{ url_for('transfer') }}">
    <input
        type="hidden"
        name="csrf_token"
        value="{{ csrf_token }}"
    >

    <input
        type="text"
        name="recipient"
        required
    >

    <input
        type="number"
        name="amount"
        required
    >

    <button>Перевести</button>
</form>
```

Проверка:

```python
form_token = request.form.get('csrf_token', '')
session_token = session.get('csrf_token', '')

if not form_token or form_token != session_token:
    return 'CSRF attack detected!', 403
```

---

## 27. Финальная проверка

После внесения исправлений повторите первоначальные тесты.

### Проверка SQL Injection

Специальный ввод больше не должен изменять структуру SQL-запроса.

### Проверка Reflected XSS

Строка:

```html
<script>alert('XSS')</script>
```

должна отображаться как текст.

### Проверка Stored XSS

Комментарий с HTML/JavaScript не должен исполняться ни у автора, ни у других пользователей.

### Проверка CSRF

Запрос без корректного CSRF-токена должен завершаться ошибкой:

```text
403
```

### Проверка Clickjacking

Браузер не должен позволять сторонней странице встроить MiniBank в iframe.

---

## 28. Практическое задание

Проведите мини-аудит MiniBank и заполните таблицу.

| Уязвимость | Причина | Где проявляется | Метод защиты | Результат после исправления |
|------------|---------|-----------------|---------------|-----------------------------|
| SQL Injection |  |  |  |  |
| Reflected XSS |  |  |  |  |
| Stored XSS |  |  |  |  |
| CSRF |  |  |  |  |
| Clickjacking |  |  |  |  |

Для каждой строки требуется объяснить не только название механизма защиты, но и **почему именно он устраняет причину уязвимости**.

---

<div align="center"> Made with ❤️ by <b>dv0retsky</b> </div>