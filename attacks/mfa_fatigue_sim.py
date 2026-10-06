import json
import random
import time
import uuid

from app.logger import log_auth_event


CAMPAIGN_ID = str(uuid.uuid4())[:8]


TARGET_USERS = [
    "alice",
    "bob",
    "charlie",
    "admin"
]


SYNTHETIC_SOURCES = [
    "10.10.10.51",
    "10.10.10.73",
    "10.10.10.94",
    "10.10.10.121"
]


def generate_mfa_event(
    username,
    source_ip,
    request_number
):

    return {
        "event_id": str(uuid.uuid4()),
        "username": username,
        "source_ip": source_ip,
        "request_number": request_number,
        "attack_profile": "mfa_fatigue",
        "campaign_id": CAMPAIGN_ID
    }


def run_simulation():

    print("=" * 70)
    print("             MFA FATIGUE SIMULATOR")
    print("=" * 70)

    print(
        f"Campaign ID : {CAMPAIGN_ID}"
    )

    print(
        "Attack      : MFA fatigue / push-jamming"
    )

    print(
        "Provider    : MOCK_MFA_PROVIDER"
    )

    print(
        "Targets     : 4 synthetic users"
    )

    print("=" * 70)

    total_events = 0

    for username, source_ip in zip(
        TARGET_USERS,
        SYNTHETIC_SOURCES
    ):

        print(
            f"\n[*] Simulating MFA fatigue against "
            f"{username}"
        )

        print(
            f"    Synthetic Source: {source_ip}"
        )

        for request_number in range(1, 6):

            event = generate_mfa_event(
                username,
                source_ip,
                request_number
            )

            metadata = {
                "request_number": request_number,
                "provider": "MOCK_MFA_PROVIDER",
                "synthetic": True,
                "technique": "T1621",
                "tactic": "Credential Access"
            }

            log_auth_event(
                username=username,
                source_ip=source_ip,
                result="PENDING",
                reason="MFA_PUSH_REQUEST",
                user_agent=(
                    "PurpleTeam-MFAFatigueSimulator/1.0"
                ),
                client_ip=source_ip,
                forwarded_ip=source_ip,
                attack_profile="mfa_fatigue",
                campaign_id=CAMPAIGN_ID,
                mfa_required=True,
                metadata=metadata
            )

            print(
                f"    [MFA] Push request "
                f"{request_number}/5 generated"
            )

            print(
                "    "
                + json.dumps(
                    event,
                    separators=(",", ":")
                )
            )

            total_events += 1

            time.sleep(
                random.uniform(
                    0.3,
                    0.8
                )
            )

    print(
        "\n[+] MFA fatigue simulation completed"
    )

    print("=" * 70)

    print(
        f"Total synthetic MFA events: "
        f"{total_events}"
    )

    print(
        f"Campaign ID: {CAMPAIGN_ID}"
    )

    print("=" * 70)


if __name__ == "__main__":
    run_simulation()
