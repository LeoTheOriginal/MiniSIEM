# 🔒 Security Documentation

<div align="center">

**Mechanizmy Bezpieczeństwa miniSIEM**

</div>

---

## Spis Treści

- [Przegląd Zabezpieczeń](#przegląd-zabezpieczeń)
- [Autentykacja](#autentykacja)
- [Autoryzacja](#autoryzacja)
- [Ochrona CSRF](#ochrona-csrf)
- [Hashowanie Haseł](#hashowanie-haseł)
- [Bezpieczeństwo Sesji](#bezpieczeństwo-sesji)
- [Bezpieczeństwo API](#bezpieczeństwo-api)
- [Walidacja Danych](#walidacja-danych)
- [Best Practices](#best-practices)

---

## Przegląd Zabezpieczeń

### Defense in Depth

System miniSIEM implementuje wielowarstwowe zabezpieczenia zgodne z zasadą **Defense in Depth**:

```
┌─────────────────────────────────────────────────────────────────┐
│                    WARSTWY ZABEZPIECZEŃ                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │ WARSTWA 1: PREZENTACJA                                   │    │
│  │ • CSRF Token w każdym formularzu                         │    │
│  │ • X-CSRFToken header w JS fetch                          │    │
│  │ • Sanityzacja wyjścia (Jinja2 auto-escape)              │    │
│  └─────────────────────────────────────────────────────────┘    │
│                              │                                   │
│                              ▼                                   │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │ WARSTWA 2: APLIKACJA                                     │    │
│  │ • @login_required na chronionych endpointach             │    │
│  │ • Session-based authentication                           │    │
│  │ • Flask-WTF form validation                              │    │
│  └─────────────────────────────────────────────────────────┘    │
│                              │                                   │
│                              ▼                                   │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │ WARSTWA 3: DANE                                          │    │
│  │ • Hasła hashowane (PBKDF2-SHA256 + salt)                 │    │
│  │ • ORM (SQLAlchemy) - ochrona przed SQL Injection         │    │
│  │ • Parametryzowane zapytania                              │    │
│  └─────────────────────────────────────────────────────────┘    │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Matryca Zabezpieczeń

| Zagrożenie | Mitygacja | Status |
|------------|-----------|--------|
| SQL Injection | SQLAlchemy ORM | ✅ |
| XSS (Cross-Site Scripting) | Jinja2 auto-escape | ✅ |
| CSRF (Cross-Site Request Forgery) | Flask-WTF + Token Header | ✅ |
| Brute Force | @login_required, ogólne komunikaty | ⚠️ Częściowe |
| Password Cracking | PBKDF2-SHA256 + salt | ✅ |
| Session Hijacking | Secure cookies, SECRET_KEY | ✅ |
| Unauthorized Access | @login_required decorator | ✅ |

---

## Autentykacja

### Implementacja

```python
# app/blueprints/auth.py

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('ui.config'))
    
    form = LoginForm()
    
    if form.validate_on_submit():
        # 1. Pobierz użytkownika po nazwie
        user = User.query.filter_by(username=form.username.data).first()
        
        # 2. Sprawdź hasło (timing-safe comparison)
        if user and user.check_password(form.password.data):
            # 3. Zaloguj użytkownika
            login_user(user)
            flash('Zalogowano pomyślnie!', 'success')
            return redirect(url_for('ui.config'))
        else:
            # 4. Ogólny komunikat (nie zdradzamy czy login czy hasło)
            flash('Nieprawidłowy login lub hasło', 'danger')
    
    return render_template('login.html', form=form)
```

### Dlaczego ogólny komunikat błędu?

```
┌─────────────────────────────────────────────────────────────────┐
│           BEZPIECZNE vs NIEBEZPIECZNE KOMUNIKATY                 │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ❌ NIEBEZPIECZNE:                                              │
│     "Użytkownik 'admin' nie istnieje"                           │
│     → Atakujący wie, że musi szukać innego loginu               │
│                                                                  │
│     "Hasło nieprawidłowe"                                       │
│     → Atakujący wie, że login jest poprawny                     │
│                                                                  │
│  ✅ BEZPIECZNE:                                                 │
│     "Nieprawidłowy login lub hasło"                             │
│     → Atakujący nie wie, co jest źle                            │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## Autoryzacja

### Dekorator @login_required

```python
# app/blueprints/ui.py

@ui_bp.route('/config')
@login_required  # ← Wymaga zalogowania
def config():
    return render_template('config.html')
```

### Konfiguracja LoginManager

```python
# app/__init__.py

login_manager.login_view = 'auth.login'
login_manager.login_message = "Zaloguj się, aby uzyskać dostęp."
login_manager.login_message_category = "warning"

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))
```

### Chronione Endpointy API

```python
# app/blueprints/api/hosts.py

# ❌ PUBLICZNE - nie wymaga logowania
@api_bp.route("/hosts", methods=["GET"])
def get_hosts():
    ...

# ✅ CHRONIONE - wymaga logowania
@api_bp.route("/hosts", methods=["POST"])
@login_required
def add_host():
    ...

@api_bp.route("/hosts/<int:host_id>", methods=["DELETE"])
@login_required
def delete_host(host_id):
    ...
```

### Dlaczego API też musi być chronione?

```
┌─────────────────────────────────────────────────────────────────┐
│                    DLACZEGO @login_required NA API?              │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  Scenariusz ataku bez zabezpieczenia:                           │
│                                                                  │
│  1. Atakujący odkrywa endpoint DELETE /api/hosts/1              │
│                                                                  │
│  2. Wywołuje bezpośrednio:                                      │
│     curl -X DELETE http://target.com/api/hosts/1                │
│                                                                  │
│  3. Host zostaje usunięty mimo braku dostępu do UI!             │
│                                                                  │
│  ────────────────────────────────────────────────────────────   │
│                                                                  │
│  ZASADA: "Przycisk ukryty w HTML" ≠ "Endpoint zabezpieczony"    │
│                                                                  │
│  Zabezpieczenie TYLKO widoku (ui.py) to Security by Obscurity   │
│  Prawdziwe zabezpieczenie = @login_required na KAŻDYM           │
│  endpoincie modyfikującym dane                                  │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## Ochrona CSRF

### Co to jest CSRF?

```
┌─────────────────────────────────────────────────────────────────┐
│                    ATAK CSRF (bez ochrony)                       │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  Ofiara                Evil Website              miniSIEM        │
│    │                        │                        │           │
│    │  1. Odwiedza           │                        │           │
│    │     evil.com           │                        │           │
│    │──────────────────────►│                        │           │
│    │                        │                        │           │
│    │  2. Ukryty form:       │                        │           │
│    │     <form action=      │                        │           │
│    │     "minisiem/api/     │                        │           │
│    │     hosts/1"           │                        │           │
│    │     method="DELETE">   │                        │           │
│    │                        │  3. Auto-submit        │           │
│    │                        │─────────────────────►│           │
│    │                        │     (z cookies        │           │
│    │                        │      ofiary!)         │           │
│    │                        │                        │           │
│    │                        │  4. Host usunięty!    │           │
│    │                        │◄─────────────────────│           │
│    │                        │                        │           │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Implementacja Ochrony

#### 1. Backend - Inicjalizacja

```python
# app/extensions.py
from flask_wtf.csrf import CSRFProtect
csrf = CSRFProtect()

# app/__init__.py
csrf.init_app(app)
# UWAGA: csrf.exempt(api_bp) zostało USUNIĘTE!
```

#### 2. Frontend - Token w HTML

```html
<!-- app/templates/base.html -->
<meta name="csrf-token" content="{{ csrf_token() }}">
```

#### 3. Frontend - Token w JavaScript

```javascript
// app/static/js/api.js

function getCSRFToken() {
    const meta = document.querySelector('meta[name="csrf-token"]');
    return meta ? meta.getAttribute('content') : '';
}

function getHeaders(includeJSON = true) {
    const headers = {
        'X-CSRFToken': getCSRFToken()  // ← Wymagane!
    };
    if (includeJSON) {
        headers['Content-Type'] = 'application/json';
    }
    return headers;
}

// Użycie w każdym żądaniu POST/PUT/DELETE:
export async function removeHost(id) {
    const res = await fetch(`/api/hosts/${id}`, {
        method: 'DELETE',
        headers: getHeaders(false)  // ← Zawiera X-CSRFToken
    });
    ...
}
```

### Przepływ Weryfikacji

```
┌─────────────────────────────────────────────────────────────────┐
│                    WERYFIKACJA CSRF TOKEN                        │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  Browser                   Flask                   Flask-WTF     │
│     │                        │                        │          │
│     │  1. GET /config        │                        │          │
│     │──────────────────────►│                        │          │
│     │                        │                        │          │
│     │  2. HTML + Token       │                        │          │
│     │◄──────────────────────│                        │          │
│     │     <meta csrf=       │                        │          │
│     │      "abc123...">     │                        │          │
│     │                        │                        │          │
│     │  3. DELETE /api/host/1│                        │          │
│     │     X-CSRFToken:      │                        │          │
│     │     "abc123..."       │                        │          │
│     │──────────────────────►│                        │          │
│     │                        │  4. Validate           │          │
│     │                        │─────────────────────►│          │
│     │                        │                        │          │
│     │                        │  5. Token valid!       │          │
│     │                        │◄─────────────────────│          │
│     │                        │                        │          │
│     │  6. 200 OK             │                        │          │
│     │◄──────────────────────│                        │          │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## Hashowanie Haseł

### Implementacja

```python
# app/models.py

from werkzeug.security import generate_password_hash, check_password_hash

class User(UserMixin, db.Model):
    password_hash = db.Column(db.String(256))
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
```

### Algorytm: PBKDF2-SHA256

```
┌─────────────────────────────────────────────────────────────────┐
│                    PBKDF2-SHA256 HASHING                         │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  INPUT: "admin" (plaintext password)                            │
│                                                                  │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │                                                          │    │
│  │  1. Generate random SALT (16 bytes)                      │    │
│  │     salt = os.urandom(16)                                │    │
│  │                                                          │    │
│  │  2. Apply PBKDF2 with 600,000 iterations                 │    │
│  │     hash = PBKDF2(password, salt, iterations=600000,     │    │
│  │                   hash_func=SHA256)                      │    │
│  │                                                          │    │
│  │  3. Encode and concatenate                               │    │
│  │     result = f"pbkdf2:sha256:600000${salt}${hash}"       │    │
│  │                                                          │    │
│  └─────────────────────────────────────────────────────────┘    │
│                                                                  │
│  OUTPUT: "pbkdf2:sha256:600000$Wz0K3Q...$a1b2c3..."             │
│          ─────────────────────── ──────── ────────              │
│                 Method info       Salt     Hash                 │
│                                                                  │
│  ────────────────────────────────────────────────────────────   │
│                                                                  │
│  BEZPIECZEŃSTWO:                                                │
│  • Salt = Każdy user ma inny hash nawet przy tym samym haśle    │
│  • 600k iteracji = Rainbow tables niepraktyczne                 │
│  • SHA256 = Odporny na kolizje                                  │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Porównanie: Plaintext vs Hash

```
┌─────────────────────────────────────────────────────────────────┐
│                    PRZECHOWYWANIE HASEŁ                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ❌ NIEBEZPIECZNE (plaintext):                                  │
│                                                                  │
│  users table:                                                   │
│  ┌────────┬──────────┐                                          │
│  │username│ password │                                          │
│  ├────────┼──────────┤                                          │
│  │ admin  │ admin    │  ← Wyciek bazy = wszystkie hasła         │
│  │ user1  │ qwerty   │    widoczne!                             │
│  └────────┴──────────┘                                          │
│                                                                  │
│  ✅ BEZPIECZNE (hash):                                          │
│                                                                  │
│  users table:                                                   │
│  ┌────────┬─────────────────────────────────────────┐           │
│  │username│ password_hash                           │           │
│  ├────────┼─────────────────────────────────────────┤           │
│  │ admin  │ pbkdf2:sha256:600000$Wz...$a1b2c3...   │           │
│  │ user1  │ pbkdf2:sha256:600000$Xy...$d4e5f6...   │           │
│  └────────┴─────────────────────────────────────────┘           │
│                                                                  │
│  Wyciek bazy = atakujący ma tylko hashe,                        │
│  które są praktycznie niemożliwe do odwrócenia                  │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## Bezpieczeństwo Sesji

### Konfiguracja

```python
# config.py

SECRET_KEY = os.getenv('SECRET_KEY', 'dev-key-bardzo-tajny')
```

**⚠️ WAŻNE:** W produkcji `SECRET_KEY` musi być:

1. Losowy (np. `python -c "import secrets; print(secrets.token_hex(32))"`)
2. Przechowywany bezpiecznie (nie w repozytorium!)
3. Unikalny dla każdej instancji

### Jak działa sesja?

```
┌─────────────────────────────────────────────────────────────────┐
│                    SESSION-BASED AUTH                            │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  Browser                                         Flask           │
│     │                                               │            │
│     │  1. POST /login                               │            │
│     │     (username, password)                      │            │
│     │─────────────────────────────────────────────►│            │
│     │                                               │            │
│     │                                  2. Validate  │            │
│     │                                  3. Create    │            │
│     │                                     session   │            │
│     │                                               │            │
│     │  4. Set-Cookie: session=eyJ...               │            │
│     │◄─────────────────────────────────────────────│            │
│     │     (signed with SECRET_KEY)                 │            │
│     │                                               │            │
│     │  5. GET /config                               │            │
│     │     Cookie: session=eyJ...                    │            │
│     │─────────────────────────────────────────────►│            │
│     │                                               │            │
│     │                                  6. Verify    │            │
│     │                                     signature │            │
│     │                                  7. Load user │            │
│     │                                               │            │
│     │  8. 200 OK (authorized content)              │            │
│     │◄─────────────────────────────────────────────│            │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## Bezpieczeństwo API

### Ochrona przed SQL Injection

```python
# ❌ NIEBEZPIECZNE (raw SQL):
query = f"SELECT * FROM users WHERE username = '{username}'"
# Atak: username = "' OR '1'='1"

# ✅ BEZPIECZNE (SQLAlchemy ORM):
user = User.query.filter_by(username=username).first()
# ORM automatycznie escapuje parametry
```

### Walidacja ID

```python
# ✅ Bezpieczne - Flask automatycznie waliduje int
@api_bp.route("/hosts/<int:host_id>")
def get_host(host_id):  # host_id jest już int
    host = Host.query.get_or_404(host_id)  # 404 jeśli nie istnieje
```

---

## Walidacja Danych

### WTForms Validators

```python
# app/forms.py

from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField
from wtforms.validators import DataRequired

class LoginForm(FlaskForm):
    username = StringField('Użytkownik', validators=[
        DataRequired(message="Podaj login")
    ])
    password = PasswordField('Hasło', validators=[
        DataRequired(message="Podaj hasło")
    ])
```

### API Input Validation

```python
# app/blueprints/api/hosts.py

@api_bp.route("/hosts", methods=["POST"])
@login_required
def add_host():
    data = request.get_json()
    
    # Walidacja obecności danych
    if not data:
        return jsonify({"error": "Brak danych"}), 400
    
    # Walidacja unikalności
    if Host.query.filter_by(ip_address=data.get("ip_address")).first():
        return jsonify({"error": "IP musi być unikalne"}), 409
    
    # Tworzenie obiektu (ORM waliduje typy)
    new_host = Host(
        hostname=data.get("hostname"),
        ip_address=data.get("ip_address"),
        os_type=data.get("os_type")
    )
```

---

## Best Practices

### Checklist Bezpieczeństwa

```
✅ Autentykacja
   [x] Hasła hashowane (nie plaintext)
   [x] Ogólne komunikaty błędów logowania
   [x] Session-based auth z SECRET_KEY
   [ ] Rate limiting na /login (TODO)
   [ ] 2FA (TODO)

✅ Autoryzacja
   [x] @login_required na chronionych endpointach
   [x] API i UI chronione osobno
   [ ] Role-based access control (TODO)

✅ CSRF
   [x] Token w formularzach
   [x] X-CSRFToken header w JS
   [x] csrf.exempt USUNIĘTY z API

✅ Dane
   [x] SQLAlchemy ORM (SQL Injection)
   [x] Jinja2 auto-escape (XSS)
   [x] Walidacja input w API

✅ Konfiguracja
   [x] SECRET_KEY w .env
   [x] Debug wyłączony w produkcji
   [ ] HTTPS (TODO)
   [ ] Security headers (TODO)
```

### Zalecenia dla Produkcji

```python
# Dodatkowe zabezpieczenia dla produkcji:

# 1. Wyłącz debug
FLASK_DEBUG=0

# 2. Silny SECRET_KEY
SECRET_KEY=$(python -c "import secrets; print(secrets.token_hex(32))")

# 3. HTTPS (nginx/reverse proxy)
# 4. Security headers (flask-talisman)
# 5. Rate limiting (flask-limiter)
# 6. Audit logging
# 7. Backup bazy danych
```

---

<div align="center">

**[← Deployment](./DEPLOYMENT.md)** | **[Powrót do README](./README.md)**

</div>