import re
import os
from collections import Counter


AUTH_LOG = "logs/auth.log"
ALERT_LOG = "logs/alerts.log"
RESPONSE_LOG = "logs/response.log"


def read_auth_events():

    events = []

    if not os.path.exists(AUTH_LOG):
        return events

    with open(AUTH_LOG, "r") as file:

        for line in file:

            match = re.search(
                r"username=(\S+).*?"
                r"source_ip=(\S+).*?"
                r"result=(\S+).*?"
                r"reason=(\S+)",
                line
            )

            if match:

                username, source_ip, result, reason = match.groups()

                events.append({
                    "username": username,
                    "source_ip": source_ip,
                    "result": result,
                    "reason": reason
                })

    return events


def count_alerts():

    if not os.path.exists(ALERT_LOG):
        return 0

    with open(ALERT_LOG, "r") as file:
        content = file.read()

    return content.count("SECURITY ALERT")


def count_locked_accounts():

    if not os.path.exists(RESPONSE_LOG):
        return 0

    locked = set()

    with open(RESPONSE_LOG, "r") as file:

        for line in file:

            if "ACCOUNT_TEMPORARILY_LOCKED" in line:

                match = re.search(
                    r"username=(\S+)",
                    line
                )

                if match:
                    locked.add(match.group(1))

    return len(locked)


def detect_attack_types(events):

    attacks = []

    failed_events = [
        event for event in events
        if event["result"] == "FAILED"
    ]

    usernames = Counter(
        event["username"]
        for event in failed_events
    )

    source_ips = Counter(
        event["source_ip"]
        for event in failed_events
    )

    # Brute-force detection
    if any(count >= 5 for count in usernames.values()):
        attacks.append("Brute Force")

    # Password spraying detection
    for ip in set(event["source_ip"] for event in failed_events):

        users = set(
            event["username"]
            for event in failed_events
            if event["source_ip"] == ip
        )

        if len(users) >= 3:
            attacks.append("Password Spray")
            break

    # Dictionary attack detection
    invalid_passwords = sum(
        1
        for event in failed_events
        if event["reason"] == "INVALID_PASSWORD"
    )

    if invalid_passwords >= 5:
        attacks.append("Dictionary Attack")

    return attacks


def display_dashboard():

    events = read_auth_events()

    total_attempts = len(events)

    successful = sum(
        1 for event in events
        if event["result"] == "SUCCESS"
    )

    failed = sum(
        1 for event in events
        if event["result"] == "FAILED"
    )

    alerts = count_alerts()

    locked = count_locked_accounts()

    attack_types = detect_attack_types(events)

    print()
    print("=" * 70)
    print("              PASSWORD SECURITY DASHBOARD")
    print("=" * 70)

    print()
    print(f"Total Authentication Attempts : {total_attempts}")
    print(f"Successful Logins              : {successful}")
    print(f"Failed Logins                  : {failed}")
    print(f"Active Alerts                  : {alerts}")
    print(f"Locked Accounts                : {locked}")

    print()
    print("-" * 70)
    print("Detected Attack Types")
    print("-" * 70)

    if attack_types:

        for attack in attack_types:
            print(f"[!] {attack}")

    else:
        print("[OK] No attack patterns detected.")

    print()
    print("=" * 70)


if __name__ == "__main__":
    display_dashboard()
