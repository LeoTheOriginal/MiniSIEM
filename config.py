import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()


class Config:
    SECRET_KEY = os.getenv('SECRET_KEY', 'dev-key-bardzo-tajny')

    # Baza danych
    SQLALCHEMY_DATABASE_URI = os.getenv('SQLALCHEMY_DATABASE_URI', 'sqlite:///../instance/lab8.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Konfiguracja SSH
    SSH_DEFAULT_HOST = os.getenv('SSH_DEFAULT_HOST', '127.0.0.1')
    SSH_DEFAULT_USER = os.getenv('SSH_DEFAULT_USER', 'kali')
    SSH_DEFAULT_PORT = int(os.getenv('SSH_DEFAULT_PORT', 2222))
    SSH_KEY_FILE = os.getenv('SSH_KEY_FILE', '')
    SSH_PASSWORD = os.getenv('SSH_PASSWORD', '')

    # Folder na logi (Parquet)
    STORAGE_FOLDER = Path.cwd() / 'storage'