import re
import os
from collections import Counter


AUTH_LOG = "logs/auth.log"


def load_events():

    events = []

    if not os.path.exists(AUTH_LOG):
        print("[!] auth.log not found.")
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


def show_statistics():

    events = load_events()

    if not events:
        print("[!] No authentication events available.")
        return

    total = len(events)

    failed_events = [
        event for event in events
        if event["result"] == "FAILED"
    ]

    successful_events = [
        event for event in events
        if event["result"] == "SUCCESS"
    ]

    failed = len(failed_events)
    successful = len(successful_events)

    username_counter = Counter(
        event["username"]
        for event in failed_events
    )

    ip_counter = Counter(
        event["source_ip"]
        for event in failed_events
    )

    reason_counter = Counter(
        event["reason"]
        for event in failed_events
    )

    print()
    print("=" * 70)
    print("                 ATTACK STATISTICS")
    print("=" * 70)

    print()
    print(f"Total Attempts       : {total}")
    print(f"Failed Attempts      : {failed}")
    print(f"Successful Attempts  : {successful}")

    print()
    print("-" * 70)
    print("Most Targeted Accounts")
    print("-" * 70)

    for username, count in username_counter.most_common(5):

        print(
            f"{username:<20} {count} failed attempts"
        )

    print()
    print("-" * 70)
    print("Most Active Source IPs")
    print("-" * 70)

    for ip, count in ip_counter.most_common(5):

        print(
            f"{ip:<20} {count} failed attempts"
        )

    print()
    print("-" * 70)
    print("Failure Reasons")
    print("-" * 70)

    for reason, count in reason_counter.most_common():

        print(
            f"{reason:<25} {count}"
        )

    print()
    print("-" * 70)
    print("Attack Classification")
    print("-" * 70)

    # Brute Force
    brute_force_users = [
        username
        for username, count in username_counter.items()
        if count >= 5
    ]

    if brute_force_users:

        print(
            "[!] Brute Force detected against:",
            ", ".join(brute_force_users)
        )

    else:

        print("[OK] No brute-force pattern detected.")

    # Password Spray
    spray_detected = False

    for ip in ip_counter:

        users = set(
            event["username"]
            for event in failed_events
            if event["source_ip"] == ip
        )

        if len(users) >= 3:

            print(
                f"[!] Password Spray detected from {ip}"
            )

            spray_detected = True

    if not spray_detected:

        print("[OK] No password-spray pattern detected.")

    # Dictionary attack
    dictionary_attempts = sum(
        1
        for event in failed_events
        if event["reason"] == "INVALID_PASSWORD"
    )

    if dictionary_attempts >= 5:

        print(
            f"[!] Dictionary Attack pattern detected "
            f"({dictionary_attempts} invalid passwords)"
        )

    else:

        print("[OK] No dictionary-attack pattern detected.")

    print()
    print("=" * 70)


if __name__ == "__main__":
    show_statistics()
