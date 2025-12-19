#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
🎯 ATTACK SIMULATOR - Symulator Ataków na miniSIEM
Automatycznie generuje nieudane próby logowania do testowania systemu SIEM.
"""

import sys
import os
import time
import paramiko
from datetime import datetime

# Dodaj katalog projektu do ścieżki
sys.path.insert(0, os.path.abspath('..'))

from config import Config


class AttackSimulator:
    """Symulator ataków dla demonstracji miniSIEM"""

    def __init__(self, target_host, target_port=22):
        self.target_host = target_host
        self.target_port = target_port
        self.attack_log = []

    def simulate_ssh_attack(self, username, password="wrongpassword", attempts=3):
        """
        Symuluje atak SSH (nieudane logowanie)

        Args:
            username: Nazwa użytkownika do ataku
            password: Błędne hasło
            attempts: Liczba prób
        """
        print(f"\n{'=' * 60}")
        print(f"🎯 SYMULACJA ATAKU SSH")
        print(f"{'=' * 60}")
        print(f"Target: {self.target_host}:{self.target_port}")
        print(f"Username: {username}")
        print(f"Attempts: {attempts}")
        print(f"{'=' * 60}\n")

        successful_attacks = 0

        for i in range(1, attempts + 1):
            print(f"[{i}/{attempts}] Próba ataku jako '{username}'...", end=" ")

            try:
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

                # Próba połączenia z błędnym hasłem (CELOWO ma się nie udać!)
                client.connect(
                    hostname=self.target_host,
                    port=self.target_port,
                    username=username,
                    password=password,
                    timeout=5,
                    look_for_keys=False,
                    allow_agent=False
                )

                print("❌ BŁĄD: Logowanie się POWIODŁO (nie powinno!)")
                client.close()

            except paramiko.AuthenticationException:
                print("✅ Atak wykryty (nieudane logowanie)")
                successful_attacks += 1
                self.attack_log.append({
                    'timestamp': datetime.now(),
                    'target': f"{self.target_host}:{self.target_port}",
                    'username': username,
                    'status': 'DETECTED'
                })

            except Exception as e:
                print(f"⚠️ Błąd połączenia: {e}")

            # Krótka przerwa między atakami
            if i < attempts:
                time.sleep(1)

        print(f"\n{'=' * 60}")
        print(f"✅ Wykonano {successful_attacks}/{attempts} ataków")
        print(f"{'=' * 60}\n")

        return successful_attacks

    def simulate_multi_user_attack(self, usernames_list):
        """
        Symuluje atak słownikowy (wiele nazw użytkowników)

        Args:
            usernames_list: Lista nazw użytkowników do ataku
        """
        print(f"\n🔥 ATAK SŁOWNIKOWY - {len(usernames_list)} użytkowników\n")

        total_attacks = 0
        for username in usernames_list:
            attacks = self.simulate_ssh_attack(username, attempts=2)
            total_attacks += attacks
            time.sleep(0.5)

        print(f"\n{'=' * 60}")
        print(f"📊 PODSUMOWANIE ATAKU SŁOWNIKOWEGO")
        print(f"{'=' * 60}")
        print(f"Próby logowania: {total_attacks}")
        print(f"Unikalnych użytkowników: {len(usernames_list)}")
        print(f"{'=' * 60}\n")

        return total_attacks

    def generate_attack_report(self):
        """Generuje raport z przeprowadzonych ataków"""
        if not self.attack_log:
            print("Brak ataków do raportu.")
            return

        print(f"\n{'=' * 60}")
        print(f"📋 RAPORT ATAKÓW")
        print(f"{'=' * 60}")
        print(f"Całkowita liczba ataków: {len(self.attack_log)}")
        print(f"Pierwszy atak: {self.attack_log[0]['timestamp'].strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Ostatni atak: {self.attack_log[-1]['timestamp'].strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{'=' * 60}\n")

        print("Szczegóły ataków:")
        for i, attack in enumerate(self.attack_log, 1):
            print(f"{i}. [{attack['timestamp'].strftime('%H:%M:%S')}] "
                  f"{attack['target']} - user: {attack['username']} - {attack['status']}")


def main():
    """Główna funkcja demonstracyjna"""

    # Pobierz konfigurację z .env
    target_host = Config.SSH_DEFAULT_HOST
    target_port = Config.SSH_DEFAULT_PORT

    print(f"""
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║          🛡️  ATTACK SIMULATOR - miniSIEM v2.0  🛡️            ║
║                                                              ║
║  Symulator ataków dla demonstracji systemu SIEM              ║
║  ⚠️  UŻYWAJ TYLKO NA WŁASNYCH SYSTEMACH TESTOWYCH!           ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
    """)

    print(f"📡 Target Host: {target_host}:{target_port}")
    print(f"⏰ Start: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

    # Utwórz symulator
    simulator = AttackSimulator(target_host, target_port)

    print("WYBIERZ SCENARIUSZ ATAKU:\n")
    print("1. Pojedynczy atak (3 próby)")
    print("2. Atak słownikowy (5 użytkowników)")
    print("3. Intensywny atak (10 prób)")
    print("4. Wszystkie scenariusze (DEMO)")
    print()

    choice = input("Wybór (1-4): ").strip()

    if choice == "1":
        simulator.simulate_ssh_attack("admin", attempts=3)

    elif choice == "2":
        usernames = ["admin", "root", "user", "test", "guest"]
        simulator.simulate_multi_user_attack(usernames)

    elif choice == "3":
        simulator.simulate_ssh_attack("hacker", attempts=10)

    elif choice == "4":
        print("\n🎬 PEŁNA DEMONSTRACJA - Wszystkie scenariusze\n")

        # Scenariusz 1: Pojedynczy atak
        print("\n--- SCENARIUSZ 1: Pojedynczy atak ---")
        simulator.simulate_ssh_attack("admin", attempts=3)
        time.sleep(2)

        # Scenariusz 2: Atak słownikowy
        print("\n--- SCENARIUSZ 2: Atak słownikowy ---")
        usernames = ["root", "administrator", "ubuntu", "kali"]
        simulator.simulate_multi_user_attack(usernames)
        time.sleep(2)

        # Scenariusz 3: Intensywny atak
        print("\n--- SCENARIUSZ 3: Intensywny atak ---")
        simulator.simulate_ssh_attack("attacker", attempts=5)

    else:
        print("❌ Nieprawidłowy wybór!")
        return

    # Wygeneruj raport
    simulator.generate_attack_report()

    print(f"""
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║  ✅ ATAKI ZAKOŃCZONE                                         ║
║                                                              ║
║  Teraz:                                                      ║
║  1. Otwórz Dashboard miniSIEM (http://127.0.0.1:5000)        ║
║  2. Zaloguj się (admin/admin)                                ║
║  3. Kliknij "Pobierz Logi" na karcie hosta                   ║
║  4. Sprawdź sekcję "Wykryte Zagrożenia"                      ║
║                                                              ║
║  ⚠️  Logi pojawią się po wykonaniu "Pobierz Logi"!           ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
    """)


if __name__ == "__main__":
    main()