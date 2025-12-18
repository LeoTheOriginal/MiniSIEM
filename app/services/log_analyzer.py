import pandas as pd
from datetime import datetime, timezone, timedelta
from app.extensions import db
from app.models import Alert, IPRegistry, Host
from app.services.data_manager import DataManager


class LogAnalyzer:
    """
    Serce systemu SIEM. Analizuje pliki logów przy użyciu Pandas
    i generuje alerty w bazie danych.
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

            print(f"🔍 THREAT: {ip} / {user} / {row['alert_type']}")

            # Ignorujemy lokalne
            if ip in ['LOCAL', 'LOCAL_CONSOLE', '127.0.0.1', '::1']:
                print(f"⏭️ Pomijam lokalny IP: {ip}")
                continue

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
                    last_seen=datetime.now(timezone.utc)
                )
                db.session.add(ip_record)
                db.session.commit()
            else:
                # 3. Jeśli JEST - zaktualizuj last_seen
                ip_record.last_seen = datetime.now(timezone.utc)
                db.session.commit()

            # 4. Ustalenie poziomu alertu na podstawie statusu IP
            severity = 'WARNING'
            message = f"Nieudane logowanie z {ip} jako użytkownik '{user}'"

            if ip_record.status == 'BANNED':
                severity = 'CRITICAL'
                message = f"⚠️ ATAK Z ZBANOWANEGO IP! {ip} próbował zalogować się jako '{user}'"
            elif ip_record.status == 'TRUSTED':
                # Możemy pominąć alerty z zaufanych IP lub oznaczyć jako INFO
                severity = 'INFO'
                message = f"Nieudane logowanie z zaufanego IP {ip} jako '{user}' (możliwy błąd użytkownika)"
            elif ip_record.status == 'UNKNOWN':
                severity = 'WARNING'
                message = f"Nieudane logowanie z nieznanego IP {ip} jako '{user}'"

            # =======================================================
            # DEDUPLIKACJA - Sprawdź czy alert już istnieje
            # =======================================================

            # Sprawdzamy czy w ostatnich 5 minutach był już identyczny alert
            five_minutes_ago = datetime.now(timezone.utc) - timedelta(minutes=5)
            existing_alert = Alert.query.filter(
                Alert.host_id == host_id,
                Alert.source_ip == ip,
                Alert.alert_type == row['alert_type'],
                Alert.timestamp >= five_minutes_ago
            ).first()

            if existing_alert:
                print(f"⏭️ Pomijam duplikat: {ip} / {user} / {row['alert_type']} (już w bazie)")
                continue

            # 5. Utworzenie alertu
            new_alert = Alert(
                host_id=host_id,
                alert_type=row['alert_type'],
                source_ip=ip,
                severity=severity,
                message=message,
                timestamp=datetime.now(timezone.utc)
            )

            db.session.add(new_alert)
            alerts_created += 1
            print(f"✅ Utworzono alert #{alerts_created}: {severity} - {message}")

        print(f"💾 Zapisuję {alerts_created} alertów do bazy...")
        db.session.commit()
        print(f"✅ COMMIT wykonany!")
        return alerts_created