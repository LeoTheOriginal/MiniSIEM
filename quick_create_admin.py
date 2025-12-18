#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Szybki skrypt do utworzenia użytkownika admin
Uruchom: python quick_create_admin.py
"""

import sys
import os

# Dodaj katalog projektu do ścieżki
sys.path.insert(0, os.path.abspath('.'))

from app import create_app
from app.extensions import db
from app.models import User


def create_admin():
    app = create_app()

    with app.app_context():
        # Utwórz tabele jeśli nie istnieją
        db.create_all()

        # Sprawdź czy admin istnieje
        admin = User.query.filter_by(username='admin').first()

        if admin:
            print("⚠️  Użytkownik 'admin' już istnieje!")
            response = input("Czy chcesz go usunąć i utworzyć ponownie? (t/n): ")
            if response.lower() != 't':
                print("Anulowano.")
                return
            db.session.delete(admin)
            db.session.commit()

        # Utwórz admina
        admin = User(username='admin')
        admin.set_password('admin')
        db.session.add(admin)
        db.session.commit()

        print("✅ Użytkownik 'admin' został utworzony!")
        print("\n📋 DANE LOGOWANIA:")
        print("   Login: admin")
        print("   Hasło: admin")
        print("\n🌐 Uruchom aplikację: flask run")
        print("🔗 Otwórz: http://127.0.0.1:5000/login")


if __name__ == '__main__':
    create_admin()