import requests
import time

URL = "http://127.0.0.1:5000/login"
USERNAME = "admin"

passwords = [
    "123456",
    "password",
    "admin",
    "admin123",
    "password123",
    "letmein",
    "qwerty",
    "welcome",
    "test123",
    "wrongpassword"
]

print("[*] Starting brute-force simulation...")

for password in passwords:
    data = {
        "username": USERNAME,
        "password": password
    }

    try:
        response = requests.post(URL, data=data, timeout=5)

        print(f"[*] Trying: {password} -> HTTP {response.status_code}")

    except requests.exceptions.RequestException as e:
        print(f"[!] Connection error: {e}")

    time.sleep(1)

print("[+] Brute-force simulation completed.")
