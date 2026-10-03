import sqlite3
from pathlib import Path

DATABASE = Path(__file__).parent.parent / "data" / "users.db"

def get_connection():
    return sqlite3.connect(DATABASE)

def initialize_database():
    connection = get_connection()

    connection.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL,
            failed_attempts INTEGER DEFAULT 0,
            locked INTEGER DEFAULT 0
        )
    """)

    connection.commit()
    connection.close()
