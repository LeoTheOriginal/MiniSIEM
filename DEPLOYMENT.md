# ⚙️ Deployment Guide

<div align="center">

**Instrukcja instalacji i konfiguracji miniSIEM**

</div>

---

## Spis Treści

- [Wymagania Systemowe](#wymagania-systemowe)
- [Instalacja](#instalacja)
- [Konfiguracja](#konfiguracja)
- [Środowisko Testowe](#środowisko-testowe)
- [Generowanie Danych Testowych](#generowanie-danych-testowych)
- [Troubleshooting](#troubleshooting)

---

## Wymagania Systemowe

### Serwer miniSIEM

| Komponent | Minimum | Zalecane |
|-----------|---------|----------|
| OS | Windows 10/11, Ubuntu 20.04+ | Windows 11, Ubuntu 22.04 |
| Python | 3.10 | 3.11+ |
| RAM | 2 GB | 4 GB |
| Dysk | 1 GB | 5 GB (dla logów) |
| Sieć | Dostęp do monitorowanych hostów | - |

### Monitorowane Hosty

**Linux:**
- SSH Server zainstalowany i uruchomiony
- Użytkownik z uprawnieniami sudo
- journalctl dostępny (systemd)

**Windows:**
- PowerShell 5.1+
- Uruchomiony lokalnie (ten sam host co miniSIEM)
- Event Log dostępny

---

## Instalacja

### Krok 1: Klonowanie Repozytorium

```bash
git clone https://github.com/your-repo/minisiem.git
cd minisiem
```

### Krok 2: Środowisko Wirtualne

**Linux/macOS:**

```bash
python3 -m venv venv
source venv/bin/activate
```

**Windows (PowerShell):**

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
```

**Windows (CMD):**

```cmd
python -m venv venv
venv\Scripts\activate.bat
```

### Krok 3: Instalacja Zależności

```bash
pip install -r requirements.txt
```

**Lista zależności:**

```
Flask              # Web framework
Flask-SQLAlchemy   # ORM
Flask-Migrate      # Migracje bazy danych
Flask-Login        # Zarządzanie sesjami
Flask-WTF          # Formularze + CSRF
WTForms            # Walidacja formularzy
paramiko           # Klient SSH
cryptography       # Szyfrowanie
python-dotenv      # Zmienne środowiskowe
psutil             # Metryki systemowe
pandas             # Przetwarzanie danych
pyarrow            # Format Parquet
```

### Krok 4: Inicjalizacja Bazy Danych

```bash
# Utworzenie folderu instance (jeśli nie istnieje)
mkdir -p instance

# Inicjalizacja bazy (automatyczna przy pierwszym uruchomieniu)
# lub ręcznie:
flask shell
>>> from app.extensions import db
>>> db.create_all()
>>> exit()
```

### Krok 5: Utworzenie Administratora

```bash
python quick_create_admin.py
```

**Wyjście:**

```
✅ Użytkownik 'admin' został utworzony!

📋 DANE LOGOWANIA:
   Login: admin
   Hasło: admin

🌐 Uruchom aplikację: flask run
🔗 Otwórz: http://127.0.0.1:5000/login
```

### Krok 6: Uruchomienie Serwera

```bash
flask run
```

**Wyjście:**

```
 * Serving Flask app 'app:create_app'
 * Debug mode: on
 * Running on http://127.0.0.1:5000
```

---

## Konfiguracja

### Zmienne Środowiskowe (.env)

Utwórz plik `.env` w głównym katalogu projektu:

```bash
cp .env.example .env
```

**Zawartość .env:**

```ini
# === FLASK ===
SECRET_KEY=twoj-bardzo-tajny-klucz-zmien-na-produkcji

# === BAZA DANYCH ===
SQLALCHEMY_DATABASE_URI=sqlite:///../instance/lab8.db

# === SSH (Linux hosts) ===
SSH_DEFAULT_HOST=192.168.1.100
SSH_DEFAULT_USER=kali
SSH_DEFAULT_PORT=22
SSH_PASSWORD=kali

# Alternatywnie - klucz SSH:
# SSH_KEY_FILE=/home/user/.ssh/id_rsa
```

### Struktura Konfiguracji

```python
# config.py

class Config:
    SECRET_KEY = os.getenv('SECRET_KEY', 'dev-key-bardzo-tajny')
    
    # Baza danych
    SQLALCHEMY_DATABASE_URI = os.getenv(
        'SQLALCHEMY_DATABASE_URI', 
        'sqlite:///../instance/lab8.db'
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # SSH
    SSH_DEFAULT_HOST = os.getenv('SSH_DEFAULT_HOST', '127.0.0.1')
    SSH_DEFAULT_USER = os.getenv('SSH_DEFAULT_USER', 'kali')
    SSH_DEFAULT_PORT = int(os.getenv('SSH_DEFAULT_PORT', 22))
    SSH_KEY_FILE = os.getenv('SSH_KEY_FILE', '')
    SSH_PASSWORD = os.getenv('SSH_PASSWORD', '')
    
    # Storage
    STORAGE_FOLDER = Path.cwd() / 'storage'
```

### Konfiguracja Flask CLI (.flaskenv)

```ini
FLASK_APP=app:create_app
FLASK_DEBUG=1
```

---

## Środowisko Testowe

### Architektura Testowa

```
┌─────────────────────────────────────────────────────────────────┐
│                    ŚRODOWISKO TESTOWE                            │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │                    HOST WINDOWS                          │    │
│  │                  (Twój komputer)                         │    │
│  │                                                          │    │
│  │  ┌─────────────┐        ┌─────────────────────────┐     │    │
│  │  │  miniSIEM   │        │       VMware/VBox       │     │    │
│  │  │   Server    │◄──────►│                         │     │    │
│  │  │             │  SSH   │  ┌─────────────────┐    │     │    │
│  │  │ localhost   │        │  │   Kali Linux    │    │     │    │
│  │  │   :5000     │        │  │   192.168.x.x   │    │     │    │
│  │  └─────────────┘        │  │   (NAT/Bridge)  │    │     │    │
│  │         │               │  └─────────────────┘    │     │    │
│  │         │               └─────────────────────────┘     │    │
│  │         │                                                │    │
│  │         ▼                                                │    │
│  │  ┌─────────────┐                                        │    │
│  │  │  Windows    │                                        │    │
│  │  │  Event Log  │                                        │    │
│  │  │ (localhost) │                                        │    │
│  │  └─────────────┘                                        │    │
│  │                                                          │    │
│  └─────────────────────────────────────────────────────────┘    │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Konfiguracja VMware (Kali Linux)

#### 1. Tryb sieci: NAT z przekierowaniem portów

**VMware Workstation:**

1. Edit → Virtual Network Editor
2. Wybierz VMnet8 (NAT)
3. NAT Settings → Add Port Forward:
   - Host port: 2222
   - Virtual machine IP: 192.168.x.x (IP Kali)
   - Virtual machine port: 22
   - Protocol: TCP

**W .env:**

```ini
SSH_DEFAULT_HOST=127.0.0.1
SSH_DEFAULT_PORT=2222
```

#### 2. Tryb sieci: Bridged

**Kali Linux:**

```bash
# Sprawdź IP
ip addr show eth0
# Np. 192.168.1.100
```

**W .env:**

```ini
SSH_DEFAULT_HOST=192.168.1.100
SSH_DEFAULT_PORT=22
```

### Konfiguracja SSH na Kali

```bash
# Instalacja SSH Server
sudo apt update
sudo apt install openssh-server

# Uruchomienie usługi
sudo systemctl enable ssh
sudo systemctl start ssh

# Sprawdzenie statusu
sudo systemctl status ssh

# Konfiguracja (opcjonalna) - /etc/ssh/sshd_config
# MaxStartups 10:30:100  # Zwiększ dla wielu połączeń
```

---

## Generowanie Danych Testowych

### Metoda 1: Ataki na Linux (SSH Brute Force)

**Z hosta Windows:**

```bash
# Próby logowania z błędnym hasłem
ssh nonexistent@192.168.1.100
# (podaj dowolne hasło, powtórz 3-5 razy)

ssh admin@192.168.1.100
# (podaj błędne hasło)

ssh root@192.168.1.100
# (podaj błędne hasło)
```

**Wynik w journalctl:**

```
Failed password for invalid user nonexistent from 192.168.1.1 port 54321 ssh2
Invalid user admin from 192.168.1.1 port 54322
```

### Metoda 2: Ataki na Windows (Event 4625)

**PowerShell (jako administrator):**

```powershell
# Próby połączenia z błędnym hasłem
net use \\127.0.0.1\ipc$ /u:fakeuser wrongpassword

# Powtórz 3-5 razy z różnymi użytkownikami
net use \\127.0.0.1\ipc$ /u:admin badpass
net use \\127.0.0.1\ipc$ /u:test wrongpwd
```

**Wynik w Event Viewer:**

```
Event ID: 4625
Logon Type: 3 (Network)
Failure Reason: Unknown user name or bad password
```

### Metoda 3: Automatyczna symulacja (Python)

```python
# attack_simulator.py
import paramiko
import time

TARGET = "192.168.1.100"
PORT = 22
USERS = ["admin", "root", "test", "user", "guest"]
PASSWORDS = ["password", "123456", "admin"]

for user in USERS:
    for pwd in PASSWORDS:
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(TARGET, port=PORT, username=user, password=pwd, timeout=5)
            print(f"[!] SUCCESS: {user}:{pwd}")
            client.close()
        except paramiko.AuthenticationException:
            print(f"[-] Failed: {user}:{pwd}")
        except Exception as e:
            print(f"[X] Error: {e}")
        time.sleep(0.5)
```

### Metoda 4: Cross-Host Attack (dla testu korelacji)

```bash
# Terminal 1: Atakuj hosta Linux
ssh attacker@192.168.1.100  # błędne hasło x3

# Terminal 2: Atakuj hosta Windows (lokalnie)
net use \\127.0.0.1\ipc$ /u:attacker wrongpass

# W miniSIEM:
# 1. Pobierz logi z hosta Linux
# 2. Pobierz logi z hosta Windows
# 3. IP atakującego powinien być automatycznie zbanowany!
```

---

## Troubleshooting

### Problem: "Connection refused" przy SSH

**Przyczyna:** SSH Server nie działa lub firewall blokuje.

**Rozwiązanie:**

```bash
# Na Kali Linux
sudo systemctl start ssh
sudo ufw allow 22/tcp
```

### Problem: "Permission denied" mimo dobrego hasła

**Przyczyna:** sudo wymaga hasła, ale nie jest przekazywane.

**Rozwiązanie:** Upewnij się, że `SSH_PASSWORD` jest ustawione w `.env`.

### Problem: Puste logi z Linux

**Przyczyna:** journalctl nie ma wpisów lub brak uprawnień.

**Rozwiązanie:**

```bash
# Na Kali - sprawdź logi SSH
sudo journalctl -u ssh --since "1 hour ago"

# Jeśli puste - wygeneruj wpisy (patrz: Generowanie Danych)
```

### Problem: "CSRF token missing"

**Przyczyna:** JavaScript nie wysyła nagłówka X-CSRFToken.

**Rozwiązanie:** Sprawdź, czy meta tag istnieje w HTML:

```html
<meta name="csrf-token" content="{{ csrf_token() }}">
```

### Problem: Baza danych nie istnieje

**Przyczyna:** Folder `instance/` nie został utworzony.

**Rozwiązanie:**

```bash
mkdir -p instance
flask shell
>>> from app.extensions import db
>>> db.create_all()
```

### Problem: Alerty się nie wyświetlają

**Przyczyna:** Brak danych w bazie lub błąd JavaScript.

**Rozwiązanie:**

1. Sprawdź konsolę przeglądarki (F12 → Console)
2. Wywołaj API ręcznie: `curl http://localhost:5000/api/alerts`
3. Sprawdź bazę: `flask shell` → `Alert.query.all()`

### Problem: Wykresy Chart.js nie działają

**Przyczyna:** CDN Chart.js niedostępny lub błąd w danych.

**Rozwiązanie:**

1. Sprawdź Network tab w DevTools
2. Sprawdź odpowiedź `/api/alerts/stats`
3. Upewnij się, że są jakiekolwiek alerty w bazie

---

## Checklist Wdrożenia

```
✅ Instalacja
   [ ] Python 3.10+ zainstalowany
   [ ] Środowisko wirtualne utworzone
   [ ] Zależności zainstalowane (pip install -r requirements.txt)
   [ ] Plik .env skonfigurowany

✅ Baza danych
   [ ] Folder instance/ istnieje
   [ ] Baza lab8.db utworzona
   [ ] Admin utworzony (quick_create_admin.py)

✅ SSH (Linux hosts)
   [ ] SSH Server uruchomiony na hoście docelowym
   [ ] Port SSH dostępny (firewall)
   [ ] Credentials w .env poprawne
   [ ] Test: ssh user@host działa

✅ Testy
   [ ] Flask run uruchamia się bez błędów
   [ ] Logowanie admin/admin działa
   [ ] Panel /config dostępny po zalogowaniu
   [ ] Health-check hostów zwraca dane
   [ ] Pobieranie logów działa
   [ ] Alerty wyświetlają się na dashboardzie
```

---

<div align="center">

**[← API](./API.md)** | **[Powrót do README](./README.md)** | **[Security →](./SECURITY.md)**

</div>