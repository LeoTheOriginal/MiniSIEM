#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
🎯 TEST CROSS-HOST CORRELATION
Demonstracja automatycznego banowania IP po ataku na wiele hostów.
"""

import sys
import os
import time
import requests
from datetime import datetime

# Dodaj katalog projektu do ścieżki
sys.path.insert(0, os.path.abspath('..'))

from app import create_app
from app.models import Host, Alert, IPRegistry
from app.extensions import db


class CrossHostTester:
    """Tester korelacji ataków między hostami"""

    def __init__(self, base_url="http://127.0.0.1:5000"):
        self.base_url = base_url
        self.app = create_app()
        self.session = requests.Session()

    def login(self, username="admin", password="admin"):
        """Loguje się do systemu"""
        print(f"🔐 Logowanie jako {username}...")

        # Pobierz stronę logowania (dla CSRF tokena)
        response = self.session.get(f"{self.base_url}/login")

        # Wyciągnij CSRF token (uproszczona wersja)
        login_data = {
            'username': username,
            'password': password
        }

        response = self.session.post(
            f"{self.base_url}/login",
            data=login_data,
            allow_redirects=True
        )

        if response.status_code == 200 and 'Konfiguracja' in response.text:
            print("✅ Zalogowano pomyślnie\n")
            return True
        else:
            print(f"❌ Błąd logowania: {response.status_code}\n")
            return False

    def get_hosts(self):
        """Pobiera listę hostów z systemu"""
        with self.app.app_context():
            hosts = Host.query.all()
            return hosts

    def trigger_log_fetch(self, host_id):
        """Wyzwala pobranie logów dla hosta"""
        print(f"📥 Pobieranie logów dla hosta #{host_id}...", end=" ")

        try:
            response = self.session.post(
                f"{self.base_url}/api/hosts/{host_id}/logs",
                timeout=30
            )

            if response.status_code == 200:
                data = response.json()
                print(f"✅ Pobrano {data.get('logs_collected', 0)} logów, "
                      f"{data.get('alerts_generated', 0)} alertów")
                return True
            else:
                print(f"❌ Błąd {response.status_code}")
                return False

        except Exception as e:
            print(f"❌ Błąd: {e}")
            return False

    def check_ip_status(self, ip_address):
        """Sprawdza status IP w bazie"""
        with self.app.app_context():
            ip_record = IPRegistry.query.filter_by(ip_address=ip_address).first()
            if ip_record:
                return ip_record.status
            return None

    def get_alerts_for_ip(self, ip_address):
        """Pobiera alerty dla danego IP"""
        with self.app.app_context():
            alerts = Alert.query.filter_by(source_ip=ip_address).all()
            return alerts

    def run_cross_host_test(self):
        """Główny test Cross-Host Correlation"""

        print(f"""
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║     🎯 TEST CROSS-HOST CORRELATION - miniSIEM v2.0           ║
║                                                              ║
║  Test automatycznego banowania IP po ataku na wiele hostów  ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝

⚠️  WYMAGANIA:
   1. Minimum 2 hosty skonfigurowane w systemie
   2. Ataki już wykonane na oba hosty (użyj attack_simulator.py)
   3. Flask musi być uruchomiony (flask run)

        """)

        # Zaloguj się
        if not self.login():
            print("❌ Nie udało się zalogować. Test przerwany.")
            return False

        # Pobierz hosty
        hosts = self.get_hosts()

        if len(hosts) < 2:
            print(f"❌ BŁĄD: Znaleziono tylko {len(hosts)} host(ów).")
            print("   Potrzebujesz minimum 2 hostów do testu Cross-Host Correlation!")
            print("\n   Dodaj drugi host w panelu /config:")
            print("   - Nazwa: TEST-HOST-2")
            print("   - IP: 127.0.0.1 (lub inny)")
            print("   - OS: LINUX")
            return False

        print(f"✅ Znaleziono {len(hosts)} hostów w systemie:\n")
        for host in hosts:
            print(f"   {host.id}. {host.hostname} ({host.ip_address}) - {host.os_type}")

        print(f"\n{'=' * 60}")
        print("KROK 1: Stan PRZED analizą")
        print(f"{'=' * 60}\n")

        # Sprawdź ataki na poszczególnych hostach (przykładowe IP)
        test_ips = ["192.168.1.50", "10.0.2.15", "172.16.0.100"]

        print("Sprawdzam status przykładowych IP w bazie...\n")
        for ip in test_ips:
            status = self.check_ip_status(ip)
            if status:
                print(f"   {ip}: {status}")
            else:
                print(f"   {ip}: NIE MA W BAZIE")

        print(f"\n{'=' * 60}")
        print("KROK 2: Pobieranie logów z PIERWSZEGO hosta")
        print(f"{'=' * 60}\n")

        # Pobierz logi z pierwszego hosta
        host1 = hosts[0]
        print(f"Host: {host1.hostname} ({host1.ip_address})\n")

        if not self.trigger_log_fetch(host1.id):
            print("\n⚠️ Nie udało się pobrać logów. Czy są jakieś ataki w logach?")

        time.sleep(2)

        print(f"\n{'=' * 60}")
        print("KROK 3: Pobieranie logów z DRUGIEGO hosta")
        print(f"{'=' * 60}\n")

        # Pobierz logi z drugiego hosta
        host2 = hosts[1]
        print(f"Host: {host2.hostname} ({host2.ip_address})\n")

        if not self.trigger_log_fetch(host2.id):
            print("\n⚠️ Nie udało się pobrać logów. Czy są jakieś ataki w logach?")

        time.sleep(2)

        print(f"\n{'=' * 60}")
        print("KROK 4: Analiza wyników - Status IP PO korelacji")
        print(f"{'=' * 60}\n")

        # Sprawdź wszystkie IP które zaatakowały
        with self.app.app_context():
            all_ips = IPRegistry.query.all()

            if not all_ips:
                print("❌ Brak IP w bazie. Czy były jakieś ataki?")
                print("\n💡 WSKAZÓWKA:")
                print("   1. Uruchom: python tests/attack_simulator.py")
                print("   2. Wybierz opcję 4 (pełna demonstracja)")
                print("   3. Wykonaj ataki na RÓŻNE hosty")
                print("   4. Uruchom ten test ponownie")
                return False

            print(f"Znaleziono {len(all_ips)} adresów IP w bazie:\n")

            banned_ips = []
            unknown_ips = []
            trusted_ips = []

            for ip in all_ips:
                status_color = {
                    'BANNED': '🔴',
                    'UNKNOWN': '🔵',
                    'TRUSTED': '🟢'
                }.get(ip.status, '⚪')

                print(f"   {status_color} {ip.ip_address:<15} - {ip.status:<10} "
                      f"(ostatnio: {ip.last_seen.strftime('%H:%M:%S') if ip.last_seen else 'N/A'})")

                if ip.status == 'BANNED':
                    banned_ips.append(ip)
                elif ip.status == 'UNKNOWN':
                    unknown_ips.append(ip)
                else:
                    trusted_ips.append(ip)

        print(f"\n{'=' * 60}")
        print("KROK 5: Szczegółowa analiza zbanowanych IP")
        print(f"{'=' * 60}\n")

        if not banned_ips:
            print("❌ BRAK ZBANOWANYCH IP!")
            print("\n🤔 MOŻLIWE PRZYCZYNY:")
            print("   1. Ataki były tylko na JEDEN host (potrzeba 2+)")
            print("   2. Ataki były wykonane z różnych IP")
            print("   3. Minęło więcej niż 10 minut między atakami")
            print("\n💡 JAK NAPRAWIĆ:")
            print("   1. Ustaw w .env to samo IP dla obu hostów (np. SSH_DEFAULT_HOST=127.0.0.1)")
            print("   2. Uruchom attack_simulator.py DWUKROTNIE (dla każdego hosta)")
            print("   3. Ataki muszą być w ciągu 10 minut")
            return False

        print(f"✅ Znaleziono {len(banned_ips)} zbanowane IP!\n")

        for ip in banned_ips:
            print(f"🔴 ZBANOWANE IP: {ip.ip_address}")
            print(f"   Status: {ip.status}")
            print(f"   Ostatnio widziane: {ip.last_seen}")

            # Sprawdź alerty dla tego IP
            alerts = self.get_alerts_for_ip(ip.ip_address)

            if alerts:
                print(f"   Alerty ({len(alerts)}):")

                # Grupuj alerty po hostach
                hosts_attacked = set()
                for alert in alerts:
                    if alert.host_id:
                        hosts_attacked.add(alert.host_id)
                        host = Host.query.get(alert.host_id)
                        if host:
                            severity_icon = {
                                'CRITICAL': '🚨',
                                'WARNING': '⚠️',
                                'INFO': 'ℹ️'
                            }.get(alert.severity, '❓')

                            print(f"      {severity_icon} [{alert.timestamp.strftime('%H:%M:%S')}] "
                                  f"Host: {host.hostname} - {alert.severity} - {alert.message[:50]}...")

                if len(hosts_attacked) >= 2:
                    print(f"\n   ✅ CROSS-HOST ATTACK CONFIRMED!")
                    print(f"   IP {ip.ip_address} zaatakował {len(hosts_attacked)} różnych hostów:")
                    for host_id in hosts_attacked:
                        host = Host.query.get(host_id)
                        if host:
                            print(f"      - {host.hostname} ({host.ip_address})")

            print()

        print(f"{'=' * 60}")
        print("📊 PODSUMOWANIE")
        print(f"{'=' * 60}")
        print(f"✅ Cross-Host Correlation działa poprawnie!")
        print(f"   Zbanowanych IP: {len(banned_ips)}")
        print(f"   Nieznanych IP: {len(unknown_ips)}")
        print(f"   Zaufanych IP: {len(trusted_ips)}")
        print(f"{'=' * 60}\n")

        return True


def main():
    tester = CrossHostTester()
    success = tester.run_cross_host_test()

    if success:
        print("""
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║  ✅ TEST ZAKOŃCZONY SUKCESEM!                                ║
║                                                              ║
║  Cross-Host Correlation działa prawidłowo.                   ║
║  IP atakujące wiele hostów są automatycznie banowane.        ║
║                                                              ║
║  📊 Możesz teraz:                                            ║
║  1. Sprawdzić Dashboard (http://127.0.0.1:5000)              ║
║  2. Zobacz sekcję "Wykryte Zagrożenia"                       ║
║  3. Sprawdź wykresy Chart.js                                 ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
        """)
        sys.exit(0)
    else:
        print("""
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║  ⚠️  TEST NIE WYKRYŁ CROSS-HOST ATTACKS                      ║
║                                                              ║
║  Przeczytaj instrukcje powyżej aby poprawnie skonfigurować   ║
║  środowisko testowe.                                         ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
        """)
        sys.exit(1)


if __name__ == "__main__":
    main()