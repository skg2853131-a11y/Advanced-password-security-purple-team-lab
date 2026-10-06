import random
import time
from datetime import datetime, timedelta, timezone

from app.logger import log_auth_event


USERS = {
    "alice": {
        "country": "India",
        "latitude": 17.3850,
        "longitude": 78.4867,
        "source_ips": [f"10.20.1.10", "10.20.1.11"],
        "user_agents": ["PurpleTeam-TestBrowser/1.0"],
        "login_hours": [9, 10, 11, 12],
    },
    "bob": {
        "country": "India",
        "latitude": 17.3850,
        "longitude": 78.4867,
        "source_ips": ["10.20.2.10", "10.20.2.11"],
        "user_agents": ["PurpleTeam-TestBrowser/1.0"],
        "login_hours": [10, 11, 12, 13],
    },
    "charlie": {
        "country": "India",
        "latitude": 17.3850,
        "longitude": 78.4867,
        "source_ips": ["10.20.3.10", "10.20.3.11"],
        "user_agents": ["PurpleTeam-TestBrowser/1.0"],
        "login_hours": [9, 10, 11, 12],
    },
    "admin": {
        "country": "India",
        "latitude": 17.3850,
        "longitude": 78.4867,
        "source_ips": ["10.20.4.10", "10.20.4.11"],
        "user_agents": ["PurpleTeam-AdminConsole/1.0"],
        "login_hours": [9, 10, 11],
    },
}


def generate_event_timestamp(hour):
    """
    Generate a historical timestamp around the selected login hour.
    """
    now = datetime.now(timezone.utc)

    days_ago = random.randint(7, 30)

    timestamp = now - timedelta(days=days_ago)

    timestamp = timestamp.replace(
        hour=hour,
        minute=random.randint(0, 59),
        second=random.randint(0, 59),
        microsecond=0,
    )

    return timestamp


def generate_baseline_events(events_per_user=12):
    print("=" * 70)
    print("        PURPLE TEAM BASELINE GENERATOR")
    print("=" * 70)

    total_events = 0

    for username, profile in USERS.items():

        print(f"\n[+] Generating baseline for: {username}")

        for i in range(events_per_user):

            hour = random.choice(profile["login_hours"])

            timestamp = generate_event_timestamp(hour)

            source_ip = random.choice(profile["source_ips"])
            user_agent = random.choice(profile["user_agents"])

            metadata = {
                "synthetic": True,
                "baseline": True,
                "simulation": "CONTROLLED_LAB",
                "baseline_event": True,
            }

            log_auth_event(
                username=username,
                source_ip=source_ip,
                result="SUCCESS",
                reason="BASELINE_LOGIN",
                event_timestamp=timestamp,
                user_agent=user_agent,
                client_ip=source_ip,
                forwarded_ip=source_ip,
                country=profile["country"],
                latitude=profile["latitude"],
                longitude=profile["longitude"],
                attack_profile="baseline_generation",
                campaign_id="BASELINE",
                mfa_required=False,
                risk_score=0,
                metadata=metadata,
            )

            total_events += 1

            print(
                f"[BASELINE] "
                f"user={username} "
                f"event={i + 1}/{events_per_user} "
                f"hour={hour}:00 "
                f"source={source_ip}"
            )

            time.sleep(0.1)

    print("\n" + "=" * 70)
    print(f"[+] Baseline generation completed")
    print(f"[+] Users: {len(USERS)}")
    print(f"[+] Events generated: {total_events}")
    print("=" * 70)


if __name__ == "__main__":
    generate_baseline_events()
