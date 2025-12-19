#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
🚀 QUICK START - Launcher Testów miniSIEM
Prosty interfejs do uruchamiania wszystkich testów.
"""

import sys
import os
import subprocess


def print_menu():
    """Wyświetla menu główne"""
    print("""
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║          🛡️  miniSIEM v2.0 - TEST LAUNCHER  🛡️               ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝

WYBIERZ TEST:

1. 🎯 Attack Simulator - Generuj ataki na hosty
2. 🧪 Cross-Host Correlation Test - Test auto-ban
3. 🎬 Pełna Demonstracja - Kompletna prezentacja (polecane!)
4. 📊 Sprawdź Status Systemu

0. ❌ Wyjście

    """)


def run_script(script_name):
    """Uruchamia wybrany skrypt"""
    script_path = os.path.join('tests', script_name)

    if not os.path.exists(script_path):
        print(f"\n❌ Błąd: Plik {script_path} nie istnieje!")
        input("\nNaciśnij Enter...")
        return

    print(f"\n🚀 Uruchamiam: {script_name}\n")
    print("=" * 70)

    try:
        subprocess.call([sys.executable, script_path])
    except KeyboardInterrupt:
        print("\n\n⚠️  Przerwano przez użytkownika.")
    except Exception as e:
        print(f"\n❌ Błąd: {e}")

    input("\n\nNaciśnij Enter aby wrócić do menu...")


def check_system_status():
    """Sprawdza status systemu"""
    print("\n" + "=" * 70)
    print("📊 SPRAWDZANIE STATUSU SYSTEMU")
    print("=" * 70 + "\n")

    # Dodaj projekt do ścieżki
    sys.path.insert(0, os.path.abspath('tests'))

    try:
        from app import create_app
        from app.models import Host, Alert, IPRegistry, User

        app = create_app()

        with app.app_context():
            # Statystyki
            hosts = Host.query.count()
            alerts = Alert.query.count()
            ips = IPRegistry.query.count()
            users = User.query.count()

            print(f"✅ Baza danych: OK")
            print(f"\n📊 Statystyki:")
            print(f"   Hostów: {hosts}")
            print(f"   Alertów: {alerts}")
            print(f"   IP w rejestrze: {ips}")
            print(f"   Użytkowników: {users}")

            if hosts == 0:
                print("\n⚠️  UWAGA: Brak hostów w systemie!")
                print("   Dodaj hosty w panelu /config")

            if users == 0:
                print("\n⚠️  UWAGA: Brak użytkowników!")
                print("   Uruchom: python quick_create_admin.py")

            # Sprawdź Flask
            print(f"\n🌐 Próba połączenia z Flask...")
            import requests
            try:
                response = requests.get("http://127.0.0.1:5000", timeout=3)
                print(f"✅ Flask działa (Status: {response.status_code})")
            except:
                print(f"❌ Flask nie odpowiada")
                print(f"   Uruchom: flask run")

    except Exception as e:
        print(f"❌ Błąd: {e}")
        print("\nUpewnij się że:")
        print("   1. Jesteś w katalogu projektu")
        print("   2. Baza danych jest zainicjalizowana")

    input("\n\nNaciśnij Enter aby wrócić do menu...")


def main():
    """Główna pętla programu"""

    while True:
        # Wyczyść ekran (opcjonalne)
        os.system('cls' if os.name == 'nt' else 'clear')

        print_menu()

        choice = input("Wybór (0-4): ").strip()

        if choice == "1":
            run_script("attack_simulator.py")

        elif choice == "2":
            run_script("test_cross_host_correlation.py")

        elif choice == "3":
            run_script("demo_full.py")

        elif choice == "4":
            check_system_status()

        elif choice == "0":
            print("\n👋 Do zobaczenia!\n")
            break

        else:
            print("\n❌ Nieprawidłowy wybór!")
            input("Naciśnij Enter...")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n👋 Przerwano przez użytkownika.\n")
        sys.exit(0)