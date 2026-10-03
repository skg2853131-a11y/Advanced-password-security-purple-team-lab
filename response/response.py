import os
from datetime import datetime

RESPONSE_LOG = "logs/response.log"

MAX_FAILED_ATTEMPTS = 5
LOCKOUT_DURATION = 300  # 5 minutes


def log_response(username, source_ip, action, attempts):
    os.makedirs("logs", exist_ok=True)

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    entry = (
        f"{timestamp} | "
        f"username={username} | "
        f"source_ip={source_ip} | "
        f"failed_attempts={attempts} | "
        f"ACTION={action}\n"
    )

    with open(RESPONSE_LOG, "a") as file:
        file.write(entry)

    print(entry.strip())


def lock_account(username, source_ip, attempts):
    action = "ACCOUNT_TEMPORARILY_LOCKED"

    print()
    print("=" * 60)
    print("AUTOMATED DEFENSIVE RESPONSE")
    print("=" * 60)
    print(f"Username        : {username}")
    print(f"Source IP       : {source_ip}")
    print(f"Failed Attempts : {attempts}")
    print("Action          : Temporary account lock")
    print("Duration        : 5 minutes")
    print("=" * 60)

    log_response(
        username,
        source_ip,
        action,
        attempts
    )


def rate_limit(source_ip, attempts):
    action = "IP_RATE_LIMIT_APPLIED"

    print()
    print("=" * 60)
    print("RATE LIMITING RESPONSE")
    print("=" * 60)
    print(f"Source IP       : {source_ip}")
    print(f"Failed Attempts : {attempts}")
    print("Action          : Rate limiting applied")
    print("=" * 60)

    log_response(
        "MULTIPLE",
        source_ip,
        action,
        attempts
    )


def evaluate_response(username, source_ip, attempts):

    if attempts >= MAX_FAILED_ATTEMPTS:

        lock_account(
            username,
            source_ip,
            attempts
        )

        rate_limit(
            source_ip,
            attempts
        )

        return "HIGH_RISK_RESPONSE"

    print(
        f"[INFO] {username} has {attempts} failed attempts."
    )

    log_response(
        username,
        source_ip,
        "MONITORING_ONLY",
        attempts
    )

    return "MONITORING"


if __name__ == "__main__":

    print("=" * 60)
    print("       AUTOMATED RESPONSE ENGINE")
    print("=" * 60)

    # Test case
    username = "admin"
    source_ip = "127.0.0.1"
    failed_attempts = 10

    result = evaluate_response(
        username,
        source_ip,
        failed_attempts
    )

    print()
    print(f"[+] Response result: {result}")
