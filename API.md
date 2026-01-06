# 🔌 API Documentation

<div align="center">

**miniSIEM REST API Reference**

Base URL: `http://localhost:5000/api`

</div>

---

## Spis Treści

- [Autentykacja](#autentykacja)
- [CSRF Protection](#csrf-protection)
- [Hosts API](#hosts-api)
- [IP Registry API](#ip-registry-api)
- [Alerts API](#alerts-api)
- [Monitoring API](#monitoring-api)
- [Kody Błędów](#kody-błędów)

---

## Autentykacja

System wykorzystuje **session-based authentication** z Flask-Login.

### Login

```http
POST /login
Content-Type: application/x-www-form-urlencoded
```

| Parametr | Typ | Wymagany | Opis |
|----------|-----|----------|------|
| `username` | string | ✅ | Nazwa użytkownika |
| `password` | string | ✅ | Hasło |
| `csrf_token` | string | ✅ | Token CSRF z formularza |

**Odpowiedź sukces:** `302 Redirect` do `/config`

**Odpowiedź błąd:** `200 OK` z flash message "Nieprawidłowy login lub hasło"

### Logout

```http
GET /logout
```

**Wymagana autentykacja:** ✅

**Odpowiedź:** `302 Redirect` do `/`

---

## CSRF Protection

Wszystkie endpointy modyfikujące dane (POST, PUT, DELETE) wymagają tokenu CSRF.

### Pobranie tokenu

Token jest umieszczony w `<meta>` tagu na każdej stronie:

```html
<meta name="csrf-token" content="{{ csrf_token() }}">
```

### Użycie w JavaScript

```javascript
// Pobranie tokenu
function getCSRFToken() {
    return document.querySelector('meta[name="csrf-token"]')
                   .getAttribute('content');
}

// Wysłanie żądania
fetch('/api/hosts', {
    method: 'POST',
    headers: {
        'Content-Type': 'application/json',
        'X-CSRFToken': getCSRFToken()  // ← Wymagane!
    },
    body: JSON.stringify(data)
});
```

---

## Hosts API

### Lista Hostów

```http
GET /api/hosts
```

**Wymagana autentykacja:** ❌

**Odpowiedź:**

```json
[
    {
        "id": 1,
        "hostname": "KALI-VM",
        "ip_address": "192.168.1.100",
        "os_type": "LINUX"
    },
    {
        "id": 2,
        "hostname": "DESKTOP-01",
        "ip_address": "127.0.0.1",
        "os_type": "WINDOWS"
    }
]
```

### Dodaj Hosta

```http
POST /api/hosts
Content-Type: application/json
X-CSRFToken: <token>
```

**Wymagana autentykacja:** ✅

**Body:**

```json
{
    "hostname": "SERVER-01",
    "ip_address": "192.168.1.200",
    "os_type": "LINUX"
}
```

| Pole | Typ | Wymagane | Walidacja |
|------|-----|----------|-----------|
| `hostname` | string | ✅ | Max 100 znaków |
| `ip_address` | string | ✅ | Unikalny, format IP |
| `os_type` | string | ✅ | `LINUX` lub `WINDOWS` |

**Odpowiedź sukces:** `201 Created`

```json
{
    "id": 3,
    "hostname": "SERVER-01",
    "ip_address": "192.168.1.200",
    "os_type": "LINUX"
}
```

**Odpowiedź błąd:** `409 Conflict`

```json
{
    "error": "IP musi być unikalne"
}
```

### Edytuj Hosta

```http
PUT /api/hosts/{id}
Content-Type: application/json
X-CSRFToken: <token>
```

**Wymagana autentykacja:** ✅

**Body:**

```json
{
    "hostname": "SERVER-01-PROD",
    "ip_address": "192.168.1.201",
    "os_type": "LINUX"
}
```

**Odpowiedź:** `200 OK`

```json
{
    "id": 3,
    "hostname": "SERVER-01-PROD",
    "ip_address": "192.168.1.201",
    "os_type": "LINUX"
}
```

### Usuń Hosta

```http
DELETE /api/hosts/{id}
X-CSRFToken: <token>
```

**Wymagana autentykacja:** ✅

**Odpowiedź:** `200 OK`

```json
{
    "message": "Usunięto hosta"
}
```

**Kaskadowe usuwanie:** Automatycznie usuwa powiązane `LogSource`, `LogArchive` i `Alert`.

---

## Monitoring API

### Status Hosta Linux (SSH)

```http
GET /api/hosts/{id}/ssh-info
```

**Wymagana autentykacja:** ❌

**Odpowiedź sukces:** `200 OK`

```json
{
    "free_ram_mb": "1024",
    "disk_info": "45%",
    "disk_total": "20GB",
    "cpu_load": "0.52",
    "uptime_hours": "48h 23m"
}
```

**Odpowiedź błąd:** `500 Internal Server Error`

```json
{
    "error": "Błąd połączenia: Connection refused"
}
```

### Status Hosta Windows (Local)

```http
GET /api/hosts/{id}/windows-info
```

**Wymagana autentykacja:** ❌

**Warunek:** `host.os_type == "WINDOWS"`

**Odpowiedź sukces:** `200 OK`

```json
{
    "free_ram_mb": "8192",
    "disk_info": "62%",
    "disk_total": "256.0GB",
    "cpu_load": "15.3%",
    "uptime_hours": "120h 45m"
}
```

**Odpowiedź błąd:** `400 Bad Request`

```json
{
    "error": "Wrong OS"
}
```

### Pobierz i Analizuj Logi

```http
POST /api/hosts/{id}/logs
X-CSRFToken: <token>
```

**Wymagana autentykacja:** ❌ (ale zalecana dla produkcji)

**Działanie:**

1. Sprawdza/tworzy `LogSource` dla hosta
2. Pobiera logi via SSH (Linux) lub PowerShell (Windows)
3. Zapisuje do pliku Parquet
4. Analizuje zagrożenia (SIEM)
5. Tworzy alerty w bazie

**Odpowiedź sukces:** `200 OK`

```json
{
    "message": "Logi pobrane i przeanalizowane",
    "logs_collected": 15,
    "alerts_generated": 3,
    "filename": "logs_1_20250105_143022.parquet"
}
```

**Odpowiedź brak logów:** `200 OK`

```json
{
    "message": "Brak nowych logów do analizy",
    "logs_collected": 0,
    "alerts_generated": 0
}
```

**Odpowiedź błąd:** `500 Internal Server Error`

```json
{
    "error": "Błąd pobierania logów: SSH connection timeout"
}
```

---

## IP Registry API

### Lista Adresów IP

```http
GET /api/ips
```

**Wymagana autentykacja:** ❌

**Odpowiedź:**

```json
[
    {
        "id": 1,
        "ip_address": "192.168.1.50",
        "status": "BANNED",
        "last_seen": "2025-01-05 14:30:22"
    },
    {
        "id": 2,
        "ip_address": "10.0.0.1",
        "status": "TRUSTED",
        "last_seen": "2025-01-05 12:15:00"
    },
    {
        "id": 3,
        "ip_address": "203.0.113.45",
        "status": "UNKNOWN",
        "last_seen": "2025-01-05 14:28:11"
    }
]
```

### Statusy IP

| Status | Opis | Kolor UI | Severity alertu |
|--------|------|----------|-----------------|
| `TRUSTED` | Zaufane IP (np. admin) | 🟢 Zielony | INFO |
| `UNKNOWN` | Nieznane IP (do monitorowania) | 🔵 Niebieski | WARNING |
| `BANNED` | Zablokowane IP (atakujący) | 🔴 Czerwony | CRITICAL |

### Dodaj IP

```http
POST /api/ips
Content-Type: application/json
X-CSRFToken: <token>
```

**Wymagana autentykacja:** ✅

**Body:**

```json
{
    "ip_address": "192.168.1.75",
    "status": "TRUSTED"
}
```

**Odpowiedź sukces:** `201 Created`

```json
{
    "message": "IP dodany"
}
```

**Odpowiedź błąd:** `409 Conflict`

```json
{
    "error": "IP już istnieje"
}
```

### Edytuj IP

```http
PUT /api/ips/{id}
Content-Type: application/json
X-CSRFToken: <token>
```

**Wymagana autentykacja:** ✅

**Body:**

```json
{
    "ip_address": "192.168.1.75",
    "status": "BANNED"
}
```

**Odpowiedź:** `200 OK`

```json
{
    "message": "Zaktualizowano"
}
```

### Usuń IP

```http
DELETE /api/ips/{id}
X-CSRFToken: <token>
```

**Wymagana autentykacja:** ✅

**Odpowiedź:** `200 OK`

```json
{
    "message": "Usunięto"
}
```

---

## Alerts API

### Lista Alertów

```http
GET /api/alerts
```

**Wymagana autentykacja:** ❌

**Limit:** 20 najnowszych alertów

**Odpowiedź:**

```json
[
    {
        "id": 42,
        "host_id": 1,
        "host_name": "KALI-VM",
        "timestamp": "2025-01-05 14:30:22",
        "alert_type": "FAILED_LOGIN",
        "message": "⚠️ ATAK Z ZBANOWANEGO IP! 192.168.1.50 próbował zalogować się jako 'admin'",
        "severity": "CRITICAL",
        "source_ip": "192.168.1.50"
    },
    {
        "id": 41,
        "host_id": 2,
        "host_name": "DESKTOP-01",
        "timestamp": "2025-01-05 14:28:11",
        "alert_type": "WIN_FAILED_LOGIN",
        "message": "Nieudane logowanie z nieznanego IP 10.0.0.55 jako 'administrator'",
        "severity": "WARNING",
        "source_ip": "10.0.0.55"
    }
]
```

### Typy Alertów

| Typ | System | Opis |
|-----|--------|------|
| `FAILED_LOGIN` | Linux | Nieudane logowanie SSH |
| `INVALID_USER` | Linux | Próba logowania na nieistniejącego użytkownika |
| `SUDO_USAGE` | Linux | Użycie sudo (informacyjne) |
| `WIN_FAILED_LOGIN` | Windows | Event ID 4625 |

### Poziomy Severity

| Poziom | Wyzwalacz | Badge UI |
|--------|-----------|----------|
| `CRITICAL` | IP status = BANNED lub Cross-Host Attack | 🔴 Czerwony |
| `WARNING` | IP status = UNKNOWN | 🟠 Pomarańczowy |
| `INFO` | IP status = TRUSTED | 🔵 Niebieski |

### Statystyki Alertów (dla Chart.js)

```http
GET /api/alerts/stats
```

**Wymagana autentykacja:** ❌

**Odpowiedź:**

```json
{
    "hourly": {
        "labels": ["00:00", "01:00", "02:00", "...", "23:00"],
        "data": [0, 2, 0, 5, 3, 1, 0, 0, 12, 8, 4, 2, 1, 0, 0, 0, 3, 5, 7, 2, 1, 0, 0, 0]
    },
    "top_ips": {
        "labels": ["192.168.1.50", "10.0.0.55", "203.0.113.45", "172.16.0.1", "192.168.1.99"],
        "data": [45, 23, 12, 8, 5]
    },
    "severity": {
        "labels": ["CRITICAL", "WARNING", "INFO"],
        "data": [15, 67, 12]
    }
}
```

**Użycie:**

```javascript
const stats = await fetchAlertStats();

// Wykres liniowy - alerty na godzinę
new Chart(ctx, {
    type: 'line',
    data: {
        labels: stats.hourly.labels,
        datasets: [{
            label: 'Alerty',
            data: stats.hourly.data
        }]
    }
});

// Wykres słupkowy - Top 5 IP
new Chart(ctx, {
    type: 'bar',
    data: {
        labels: stats.top_ips.labels,
        datasets: [{
            label: 'Ataki',
            data: stats.top_ips.data
        }]
    },
    options: { indexAxis: 'y' }
});
```

---

## Kody Błędów

### HTTP Status Codes

| Kod | Znaczenie | Kiedy zwracany |
|-----|-----------|----------------|
| `200` | OK | Sukces operacji GET/PUT/DELETE |
| `201` | Created | Sukces operacji POST (tworzenie) |
| `400` | Bad Request | Brak wymaganych pól, zły format danych |
| `401` | Unauthorized | Brak sesji (wymagane logowanie) |
| `403` | Forbidden | Brak tokenu CSRF |
| `404` | Not Found | Zasób nie istnieje (host, IP, alert) |
| `409` | Conflict | Naruszenie unikalności (duplikat IP) |
| `500` | Server Error | Błąd wewnętrzny (SSH, baza danych) |

### Format Błędów

```json
{
    "error": "Opis błędu po polsku"
}
```

### Przykłady Błędów

**400 - Brak danych:**

```json
{
    "error": "Brak danych"
}
```

**400 - Brak wymaganego pola:**

```json
{
    "error": "Brak adresu IP"
}
```

**403 - Brak CSRF:**

```json
{
    "error": "The CSRF token is missing."
}
```

**404 - Zasób nie istnieje:**

```
Not Found
```

**409 - Duplikat:**

```json
{
    "error": "IP już istnieje"
}
```

**500 - Błąd połączenia:**

```json
{
    "error": "Błąd pobierania logów: Connection timed out"
}
```

---

## Przykłady Użycia (cURL)

### Pobranie listy hostów

```bash
curl -X GET http://localhost:5000/api/hosts
```

### Dodanie hosta (wymaga sesji)

```bash
# Najpierw logowanie (pobierz cookies)
curl -c cookies.txt -X POST http://localhost:5000/login \
  -d "username=admin&password=admin&csrf_token=TOKEN"

# Następnie dodaj hosta
curl -b cookies.txt -X POST http://localhost:5000/api/hosts \
  -H "Content-Type: application/json" \
  -H "X-CSRFToken: TOKEN" \
  -d '{"hostname":"TEST","ip_address":"10.0.0.1","os_type":"LINUX"}'
```

### Pobranie alertów

```bash
curl -X GET http://localhost:5000/api/alerts
```

### Wywołanie analizy logów

```bash
curl -b cookies.txt -X POST http://localhost:5000/api/hosts/1/logs \
  -H "X-CSRFToken: TOKEN"
```

---

## Rate Limiting

⚠️ **Uwaga:** Obecna wersja nie implementuje rate limitingu. Dla środowiska produkcyjnego zalecane jest dodanie:

```python
from flask_limiter import Limiter

limiter = Limiter(key_func=get_remote_address)

@api_bp.route("/hosts/<int:host_id>/logs", methods=["POST"])
@limiter.limit("10 per minute")
def fetch_logs(host_id):
    ...
```

---

<div align="center">

**[← Architektura](./ARCHITECTURE.md)** | **[Powrót do README](./README.md)** | **[Deployment →](./DEPLOYMENT.md)**

</div>