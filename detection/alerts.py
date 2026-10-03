import os
from datetime import datetime

ALERT_FILE = "logs/alerts.log"


def create_alert(
    alert_type,
    source_ip,
    username,
    attempts,
    severity,
    recommendation
):
    os.makedirs("logs", exist_ok=True)

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    alert = f"""
============================================================
SECURITY ALERT
============================================================
Timestamp       : {timestamp}
Attack Type     : {alert_type}
Source IP       : {source_ip}
Username        : {username}
Failed Attempts : {attempts}
Severity        : {severity}
Recommended     : {recommendation}
============================================================
"""

    print(alert)

    with open(ALERT_FILE, "a") as file:
        file.write(alert)


def brute_force_alert(source_ip, username, attempts):
    create_alert(
        "BRUTE FORCE",
        source_ip,
        username,
        attempts,
        "HIGH",
        "Investigate source IP and consider account/IP rate limiting."
    )


def password_spray_alert(source_ip, attempts):
    create_alert(
        "PASSWORD SPRAY",
        source_ip,
        "MULTIPLE",
        attempts,
        "HIGH",
        "Investigate targeted accounts and consider MFA/rate limiting."
    )


def high_rate_alert(source_ip, attempts):
    create_alert(
        "HIGH REQUEST RATE",
        source_ip,
        "MULTIPLE",
        attempts,
        "MEDIUM",
        "Investigate request frequency and apply rate limiting."
    )


if __name__ == "__main__":
    print("[*] Alert generation module loaded.")
