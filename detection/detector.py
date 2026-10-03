from alerts import (
    brute_force_alert,
    password_spray_alert,
    high_rate_alert
)
import re
from collections import defaultdict
from datetime import datetime

LOG_FILE = "logs/auth.log"

BRUTE_FORCE_THRESHOLD = 5
SPRAY_THRESHOLD = 3
RATE_THRESHOLD = 5


def parse_log_line(line):
    match = re.search(
        r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}),\d+.*?"
        r"username=(\S+).*?"
        r"source_ip=(\S+).*?"
        r"result=(\S+).*?"
        r"reason=(\S+)",
        line
    )

    if not match:
        return None

    timestamp, username, source_ip, result, reason = match.groups()

    return {
        "timestamp": timestamp,
        "username": username,
        "source_ip": source_ip,
        "result": result,
        "reason": reason
    }


def load_events():
    events = []

    try:
        with open(LOG_FILE, "r") as file:
            for line in file:
                event = parse_log_line(line)

                if event:
                    events.append(event)

    except FileNotFoundError:
        print(f"[!] Log file not found: {LOG_FILE}")
        return []

    return events


def detect_brute_force(events):
    failures = defaultdict(int)
    alerts = []

    for event in events:
        if event["result"] == "FAILED":
            key = (event["username"], event["source_ip"])
            failures[key] += 1

    for (username, source_ip), count in failures.items():
        if count >= BRUTE_FORCE_THRESHOLD:
            alerts.append({
                "type": "BRUTE_FORCE",
                "username": username,
                "source_ip": source_ip,
                "count": count
            })

    return alerts


def detect_password_spraying(events):
    accounts = defaultdict(set)
    alerts = []

    for event in events:
        if event["result"] == "FAILED":
            accounts[event["source_ip"]].add(event["username"])

    for source_ip, usernames in accounts.items():
        if len(usernames) >= SPRAY_THRESHOLD:
            alerts.append({
                "type": "PASSWORD_SPRAY",
                "source_ip": source_ip,
                "accounts": len(usernames),
                "usernames": list(usernames)
            })

    return alerts


def detect_high_request_rate(events):
    ip_counts = defaultdict(int)
    alerts = []

    for event in events:
        if event["result"] == "FAILED":
            ip_counts[event["source_ip"]] += 1

    for source_ip, count in ip_counts.items():
        if count >= RATE_THRESHOLD:
            alerts.append({
                "type": "HIGH_REQUEST_RATE",
                "source_ip": source_ip,
                "count": count
            })

    return alerts


def main():
    print("=" * 60)
    print("       PASSWORD SECURITY DETECTION ENGINE")
    print("=" * 60)

    events = load_events()

    if not events:
        print("[!] No authentication events found.")
        return

    print(f"[*] Events analyzed: {len(events)}")
    print()

    brute_force = detect_brute_force(events)
    password_spray = detect_password_spraying(events)
    high_rate = detect_high_request_rate(events)

    for alert in brute_force:
        brute_force_alert(
             alert["source_ip"],
             alert["username"],
             alert["count"]
        )

    for alert in password_spray:
        password_spray_alert(
            alert["source_ip"],
            alert["accounts"]
        )

    for alert in high_rate:
        high_rate_alert(
            alert["source_ip"],
            alert["count"]
        )

    print("[+] BRUTE-FORCE DETECTION")

    if brute_force:
        for alert in brute_force:
            print(
                f"[ALERT] {alert['type']} | "
                f"user={alert['username']} | "
                f"IP={alert['source_ip']} | "
                f"failures={alert['count']}"
            )
    else:
        print("[OK] No brute-force pattern detected.")

    print()
    print("[+] PASSWORD-SPRAY DETECTION")

    if password_spray:
        for alert in password_spray:
            print(
                f"[ALERT] {alert['type']} | "
                f"IP={alert['source_ip']} | "
                f"accounts={alert['accounts']} | "
                f"users={', '.join(alert['usernames'])}"
            )
    else:
        print("[OK] No password-spraying pattern detected.")

    print()
    print("[+] REQUEST-RATE DETECTION")

    if high_rate:
        for alert in high_rate:
            print(
                f"[ALERT] {alert['type']} | "
                f"IP={alert['source_ip']} | "
                f"failed_requests={alert['count']}"
            )
    else:
        print("[OK] No high request-rate pattern detected.")

    print()
    print("=" * 60)


if __name__ == "__main__":
    main()
