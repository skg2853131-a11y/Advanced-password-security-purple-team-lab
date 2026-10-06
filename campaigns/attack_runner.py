import json
import random
import time
import uuid

import requests

from app.logger import log_auth_event


LOGIN_URL = "http://127.0.0.1:5000/login"


SYNTHETIC_SOURCE_POOL = [
    "10.10.10.51",
    "10.10.10.73",
    "10.10.10.94",
    "10.10.10.121"
]


def run_password_spray(profile, campaign_id):

    parameters = profile.get(
        "parameters",
        {}
    )

    target_users = parameters.get(
        "target_users",
        []
    )

    attempts_per_user = parameters.get(
        "attempts_per_user",
        1
    )

    jitter_min = parameters.get(
        "jitter_min_seconds",
        1
    )

    jitter_max = parameters.get(
        "jitter_max_seconds",
        3
    )

    password = parameters.get(
        "password",
        "Password123!"
    )

    total_events = 0

    print(
        "\n[*] Starting password spray campaign"
    )

    for index, username in enumerate(target_users):

        source_ip = SYNTHETIC_SOURCE_POOL[
            index % len(SYNTHETIC_SOURCE_POOL)
        ]

        for attempt in range(
            attempts_per_user
        ):

            try:

                response = requests.post(
                    LOGIN_URL,
                    data={
                        "username": username,
                        "password": password
                    },
                    headers={
                        "User-Agent":
                            "PurpleTeam-PasswordSpraySimulator/1.0",
                        "X-Client-IP": source_ip,
                        "X-Forwarded-For": source_ip,
                        "X-Attack-Profile":
                            "low_slow_password_spray",
                        "X-Campaign-ID":
                            campaign_id
                    },
                    timeout=5
                )

                print(
                    f"[SPRAY] "
                    f"user={username} "
                    f"source={source_ip} "
                    f"attempt={attempt + 1} "
                    f"status={response.status_code}"
                )

                total_events += 1

            except Exception as error:

                print(
                    f"[ERROR] Password spray request "
                    f"failed for {username}: {error}"
                )

            time.sleep(
                random.uniform(
                    jitter_min,
                    jitter_max
                )
            )

    return total_events


def run_credential_stuffing(profile, campaign_id):

    parameters = profile.get(
        "parameters",
        {}
    )

    target_users = parameters.get(
        "target_users",
        []
    )

    attempts_per_user = parameters.get(
        "attempts_per_user",
        1
    )

    jitter_min = parameters.get(
        "jitter_min_seconds",
        1
    )

    jitter_max = parameters.get(
        "jitter_max_seconds",
        3
    )

    total_events = 0

    credential_pairs = [
        (
            "alice",
            "WrongPassword1!"
        ),
        (
            "bob",
            "WrongPassword2!"
        ),
        (
            "charlie",
            "WrongPassword3!"
        ),
        (
            "admin",
            "WrongPassword4!"
        )
    ]

    print(
        "\n[*] Starting credential stuffing campaign"
    )

    for index, username in enumerate(target_users):

        source_ip = SYNTHETIC_SOURCE_POOL[
            index % len(SYNTHETIC_SOURCE_POOL)
        ]

        for attempt in range(
            attempts_per_user
        ):

            credential = credential_pairs[
                index % len(credential_pairs)
            ]

            try:

                response = requests.post(
                    LOGIN_URL,
                    data={
                        "username": credential[0],
                        "password": credential[1]
                    },
                    headers={
                        "User-Agent":
                            "PurpleTeam-CredentialStuffingSimulator/1.0",
                        "X-Client-IP": source_ip,
                        "X-Forwarded-For": source_ip,
                        "X-Attack-Profile":
                            "credential_stuffing",
                        "X-Campaign-ID":
                            campaign_id
                    },
                    timeout=5
                )

                print(
                    f"[STUFFING] "
                    f"user={username} "
                    f"source={source_ip} "
                    f"attempt={attempt + 1} "
                    f"status={response.status_code}"
                )

                total_events += 1

            except Exception as error:

                print(
                    f"[ERROR] Credential stuffing request "
                    f"failed for {username}: {error}"
                )

            time.sleep(
                random.uniform(
                    jitter_min,
                    jitter_max
                )
            )

    return total_events


def run_brute_force(profile, campaign_id):

    parameters = profile.get(
        "parameters",
        {}
    )

    target_user = parameters.get(
        "target_user",
        "admin"
    )

    passwords = parameters.get(
        "passwords",
        []
    )

    source_ip = parameters.get(
        "source_ip",
        "10.10.10.51"
    )

    delay_seconds = parameters.get(
        "delay_seconds",
        1
    )

    total_events = 0

    print(
        "\n[*] Starting brute-force campaign"
    )

    for password in passwords:

        try:

            response = requests.post(
                LOGIN_URL,
                data={
                    "username": target_user,
                    "password": password
                },
                headers={
                    "User-Agent":
                        "PurpleTeam-BruteForceSimulator/1.0",
                    "X-Client-IP":
                        source_ip,
                    "X-Forwarded-For":
                        source_ip,
                    "X-Attack-Profile":
                        "brute_force",
                    "X-Campaign-ID":
                        campaign_id
                },
                timeout=5
            )

            print(
                f"[BRUTE] "
                f"user={target_user} "
                f"source={source_ip} "
                f"password={password} "
                f"status={response.status_code}"
            )

            total_events += 1

        except Exception as error:

            print(
                f"[ERROR] Brute-force request failed: "
                f"{error}"
            )

        time.sleep(
            delay_seconds
        )

    return total_events


def run_mfa_fatigue(profile, campaign_id):

    parameters = profile.get(
        "parameters",
        {}
    )

    target_users = parameters.get(
        "target_users",
        []
    )

    push_requests = parameters.get(
        "push_requests_per_user",
        5
    )

    jitter_min = parameters.get(
        "jitter_min_seconds",
        0.3
    )

    jitter_max = parameters.get(
        "jitter_max_seconds",
        0.8
    )

    synthetic_sources = parameters.get(
        "synthetic_sources",
        SYNTHETIC_SOURCE_POOL
    )

    provider = parameters.get(
        "provider",
        "MOCK_MFA_PROVIDER"
    )

    total_events = 0

    print(
        "\n[*] Starting MFA fatigue campaign"
    )

    print(
        f"[*] Provider: {provider}"
    )

    print(
        f"[*] Targets: {len(target_users)}"
    )

    print(
        f"[*] Push requests per user: "
        f"{push_requests}"
    )

    for index, username in enumerate(
        target_users
    ):

        source_ip = synthetic_sources[
            index % len(synthetic_sources)
        ]

        print(
            f"\n[MFA] Target={username} "
            f"Source={source_ip}"
        )

        for request_number in range(
            1,
            push_requests + 1
        ):

            metadata = {
                "request_number":
                    request_number,

                "provider":
                    provider,

                "synthetic":
                    True,

                "technique":
                    "T1621",

                "tactic":
                    "Credential Access",

                "campaign_type":
                    "MFA_FATIGUE",

                "simulation":
                    "CONTROLLED_LAB"
            }

            try:

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
                    campaign_id=campaign_id,
                    mfa_required=True,
                    metadata=metadata
                )

                print(
                    f"[MFA] "
                    f"user={username} "
                    f"push={request_number}/"
                    f"{push_requests} "
                    f"source={source_ip}"
                )

                total_events += 1

            except Exception as error:

                print(
                    f"[ERROR] MFA event failed "
                    f"for {username}: {error}"
                )

            time.sleep(
                random.uniform(
                    jitter_min,
                    jitter_max
                )
            )

    return total_events


def run_attack(profile, campaign_id):

    attack_type = profile.get(
        "attack_type"
    )

    if attack_type == "password_spray":

        return run_password_spray(
            profile,
            campaign_id
        )

    elif attack_type == "credential_stuffing":

        return run_credential_stuffing(
            profile,
            campaign_id
        )

    elif attack_type == "brute_force":

        return run_brute_force(
            profile,
            campaign_id
        )

    elif attack_type == "mfa_fatigue":

        return run_mfa_fatigue(
            profile,
            campaign_id
        )

    else:

        raise ValueError(
            f"Unsupported attack type: "
            f"{attack_type}"
        )


def run(profile, campaign_id):

    return run_attack(
        profile,
        campaign_id
    )
