from datetime import datetime
from app.database import initialize_database, get_connection
from app.auth import hash_password


initialize_database()


users = [
    ("alice", "Password123!"),
    ("bob", "Welcome123!"),
    ("charlie", "CyberLab2026!"),
    ("admin", "AdminSecure2026!")
]


connection = get_connection()
cursor = connection.cursor()


for username, password in users:

    password_hash = hash_password(password)

    try:
        cursor.execute(
            """
            INSERT INTO users
            (username, password_hash, created_at)
            VALUES (%s, %s, %s)
            """,
            (
                username,
                password_hash,
                datetime.now().isoformat()
            )
        )

    except Exception:
        connection.rollback()
        print(f"{username} already exists.")


connection.commit()

cursor.close()
connection.close()


print("Test users created.")
