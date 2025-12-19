import pandas as pd
from datetime import datetime, timezone, timedelta
from app.extensions import db
from app.models import Alert, IPRegistry, Host
from app.services.data_manager import DataManager


class LogAnalyzer:
    """
    Serce systemu SIEM. Analizuje pliki logów przy użyciu Pandas
    i generuje alerty w bazie danych.

    ⭐ ZADANIE DODATKOWE: Cross-Host Correlation
    System automatycznie banuje IP, które zaatakowało 2+ hosty w ciągu 10 minut
    """

    @staticmethod
    def analyze_parquet(filename, host_id):
        """
        Główna funkcja analityczna.
        """
        # 1. Wczytanie danych
        df = DataManager.load_logs(filename)

        if df.empty:
            return 0

        # Zabezpieczenie przed brakiem kolumn
        if 'alert_type' not in df.columns or 'source_ip' not in df.columns:
            return 0

        # 2. Filtrowanie: Interesują nas tylko ataki
        attack_pattern = ['FAILED_LOGIN', 'INVALID_USER', 'WIN_FAILED_LOGIN']
        threats = df[df['alert_type'].isin(attack_pattern)]

        if threats.empty:
            print("❌ Brak zagrożeń w logach")
            return 0

        print(f"✅ Znaleziono {len(threats)} zagrożeń do analizy")

        alerts_created = 0

        # 3. Iteracja po zagrożeniach
        for index, row in threats.iterrows():
            ip = row['source_ip']
            user = row.get('user', 'unknown')

            # --- FIX: Obsługa daty (Linux Timestamp vs Windows String) ---
            raw_ts = row['timestamp']
            exact_timestamp = None

            # Przypadek 1: Linux (Pandas Timestamp)
            if hasattr(raw_ts, 'to_pydatetime'):
                exact_timestamp = raw_ts.to_pydatetime()

            # Przypadek 2: Windows (String "YYYY-MM-DD HH:MM:SS")
            elif isinstance(raw_ts, str):
                try:
                    # Parsujemy tekst na obiekt daty
                    exact_timestamp = datetime.strptime(raw_ts, '%Y-%m-%d %H:%M:%S')
                except ValueError:
                    # Awaryjnie, jeśli format jest inny
                    print(f"⚠️ Nieznany format daty: {raw_ts}, używam teraz()")
                    exact_timestamp = datetime.now()

            # Przypadek 3: Coś innego/Null
            else:
                exact_timestamp = datetime.now()

            # Najważniejsze: usuwamy strefę czasową (make naive) dla bazy danych
            if exact_timestamp.tzinfo is not None:
                exact_timestamp = exact_timestamp.replace(tzinfo=None)

            print(f"🔍 THREAT: {ip} / {user} / {row['alert_type']} [{exact_timestamp}]")

            # Ignorujemy lokalne
            # if ip in ['LOCAL', 'LOCAL_CONSOLE', '127.0.0.1', '::1']:
            #     print(f"⏭️ Pomijam lokalny IP: {ip}")
            #     continue

            # =======================================================
            # LOGIKA SIEM - THREAT INTELLIGENCE
            # =======================================================

            # 1. Sprawdzenie czy IP jest w bazie
            ip_record = IPRegistry.query.filter_by(ip_address=ip).first()

            # 2. Jeśli NIE MA - dodaj jako UNKNOWN
            if not ip_record:
                ip_record = IPRegistry(
                    ip_address=ip,
                    status='UNKNOWN',
                    last_seen=exact_timestamp  # Używamy czasu z logu
                )
                db.session.add(ip_record)
                db.session.commit()
            else:
                # 3. Jeśli JEST - zaktualizuj last_seen
                # Upewniamy się, że obecny last_seen w bazie też nie ma strefy przed porównaniem
                current_last = ip_record.last_seen
                if current_last and current_last.tzinfo is not None:
                    current_last = current_last.replace(tzinfo=None)

                if not current_last or exact_timestamp > current_last:
                    ip_record.last_seen = exact_timestamp
                    db.session.commit()

            # =======================================================
            # ⭐ CROSS-HOST CORRELATION (ZADANIE DODATKOWE)
            # =======================================================
            auto_banned = LogAnalyzer._check_cross_host_attack(ip, host_id, ip_record)

            # 4. Ustalenie poziomu alertu na podstawie statusu IP
            severity = 'WARNING'
            message = f"Nieudane logowanie z {ip} jako użytkownik '{user}'"

            if ip_record.status == 'BANNED':
                severity = 'CRITICAL'
                if auto_banned:
                    message = f"🚨 MULTI-HOST ATTACK! IP {ip} zaatakował wiele hostów i został automatycznie zbanowany! (user: '{user}')"
                else:
                    message = f"⚠️ ATAK Z ZBANOWANEGO IP! {ip} próbował zalogować się jako '{user}'"
            elif ip_record.status == 'TRUSTED':
                severity = 'INFO'
                message = f"Nieudane logowanie z zaufanego IP {ip} jako '{user}' (możliwy błąd użytkownika)"
            elif ip_record.status == 'UNKNOWN':
                severity = 'WARNING'
                message = f"Nieudane logowanie z nieznanego IP {ip} jako '{user}'"

            # =======================================================
            # DEDUPLIKACJA - Sprawdź czy alert już istnieje
            # =======================================================

            # Szukamy DOKŁADNIE tego wpisu (po dacie z logu, a nie "teraz")
            existing_alert = Alert.query.filter(
                Alert.host_id == host_id,
                Alert.source_ip == ip,
                Alert.alert_type == row['alert_type'],
                Alert.timestamp == exact_timestamp  # Teraz zadziała poprawnie dla obu systemów
            ).first()

            if existing_alert:
                print(f"⏭️ Pomijam duplikat: {ip} / {user} / {row['alert_type']} (już w bazie)")
                continue

            # 5. Utworzenie alertu - ZAPISUJEMY CZAS Z LOGU
            new_alert = Alert(
                host_id=host_id,
                alert_type=row['alert_type'],
                source_ip=ip,
                severity=severity,
                message=message,
                timestamp=exact_timestamp  # <--- TO JEST KLUCZOWE
            )

            db.session.add(new_alert)
            alerts_created += 1
            print(f"✅ Utworzono alert #{alerts_created}: {severity} - {message}")

        print(f"💾 Zapisuję {alerts_created} alertów do bazy...")
        db.session.commit()
        print(f"✅ COMMIT wykonany!")
        return alerts_created

    @staticmethod
    def _check_cross_host_attack(ip_address, current_host_id, ip_record):
        """
        ⭐ CROSS-HOST CORRELATION (ZADANIE DODATKOWE)

        Sprawdza czy dany IP zaatakował więcej niż 1 host w ciągu ostatnich 10 minut.
        Jeśli TAK i IP jest UNKNOWN - automatycznie banuje go i podnosi alarm CRITICAL.

        Args:
            ip_address: Adres IP do sprawdzenia
            current_host_id: ID aktualnie analizowanego hosta
            ip_record: Obiekt IPRegistry dla tego IP

        Returns:
            bool: True jeśli IP zostało automatycznie zbanowane
        """
        # Jeśli IP już jest BANNED lub TRUSTED, nie analizujemy
        if ip_record.status in ['BANNED', 'TRUSTED']:
            return False

        # Sprawdź ataki z ostatnich 10 minut
        # Używamy datetime.now() bez timezone.utc dla spójności
        ten_minutes_ago = datetime.now() - timedelta(minutes=10)

        recent_attacks = Alert.query.filter(
            Alert.source_ip == ip_address,
            Alert.timestamp >= ten_minutes_ago
        ).all()

        attacked_hosts = set()
        for alert in recent_attacks:
            if alert.host_id:
                attacked_hosts.add(alert.host_id)

        attacked_hosts.add(current_host_id)

        if len(attacked_hosts) >= 2:
            print(f"🚨 CROSS-HOST ATTACK DETECTED! IP {ip_address} zaatakował {len(attacked_hosts)} hostów:")
            for host_id in attacked_hosts:
                host = Host.query.get(host_id)
                if host:
                    print(f"   - {host.hostname} ({host.ip_address})")

            print(f"🔨 Automatyczne banowanie IP {ip_address}...")
            ip_record.status = 'BANNED'
            db.session.commit()

            return True

        return False