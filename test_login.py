import os
from config import Config
from app.services.remote_client import RemoteClient
from app.services.log_collector import LogCollector


def main():
    # 1. Pobieramy konfigurację z pliku .env (przez Config)
    host = Config.SSH_DEFAULT_HOST
    port = Config.SSH_DEFAULT_PORT
    user = Config.SSH_DEFAULT_USER
    key_path = Config.SSH_KEY_FILE
    password = Config.SSH_PASSWORD

    print(f"--- TEST POŁĄCZENIA SSH: {user}@{host}:{port} ---")

    # 2. Wybór metody autoryzacji
    if password:
        print(f"--- METODA: Logowanie hasłem ---")
        auth_method = {'password': password}
    elif key_path and os.path.exists(key_path):
        print(f"--- METODA: Klucz SSH: {key_path} ---")
        auth_method = {'key_file': key_path}
    else:
        print(f"❌ BŁĄD: Brak metody autoryzacji! Ustaw SSH_PASSWORD lub SSH_KEY_FILE w .env")
        return

    try:
        # 3. Nawiązanie połączenia
        with RemoteClient(host=host, user=user, port=port, **auth_method) as client:
            print("✅ Połączono. Pobieram logi...")

            # 4. Pobranie logów (korzystamy z naszej nowej logiki z Regexami)
            logs = LogCollector.get_linux_logs(client)

            print(f"📊 Znaleziono zdarzeń: {len(logs)}")

            if not logs:
                print("💡 Brak podejrzanych logów (Failed password / Sudo).")
                return

            # 5. Wyświetlenie wyników
            print(f"{'TIMESTAMP':<20} | {'TYP':<15} | {'IP':<15} | {'USER'}")
            print("-" * 65)
            for log in logs:
                print(f"{str(log['timestamp']):<20} | {log['alert_type']:<15} | {log['source_ip']:<15} | {log['user']}")

    except Exception as e:
        print(f"❌ Błąd: {e}")


if __name__ == "__main__":
    main()