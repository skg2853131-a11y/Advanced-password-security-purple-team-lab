import json
from pathlib import Path
import uuid
from datetime import datetime, timezone
import time

from app.database import get_connection

from campaigns.attack_runner import run_attack
from detection.campaign_correlation import correlate_campaign



# ============================================================
# Paths
# ============================================================

BASE_DIR = Path(__file__).resolve().parent
PROFILE_DIR = BASE_DIR / "profiles"


# ============================================================
# Load Campaign Profile
# ============================================================

def load_profile(profile_name):

    profile_path = PROFILE_DIR / f"{profile_name}.json"

    if not profile_path.exists():
        raise FileNotFoundError(
            f"Campaign profile not found: {profile_path}"
        )

    with open(profile_path, "r") as file:
        return json.load(file)


# ============================================================
# Create Campaign
# ============================================================

def create_campaign(profile):

    campaign_id = str(uuid.uuid4())[:8]

    attack_type = profile.get(
        "attack_type",
        "unknown"
    )

    mitre_attack = profile.get(
        "mitre_attack",
        {}
    )

    mitre_technique = mitre_attack.get(
        "technique"
    )

    mitre_tactic = mitre_attack.get(
        "tactic"
    )

    started_at = datetime.now(timezone.utc)

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        INSERT INTO campaigns (
            campaign_id,
            profile,
            attack_type,
            mitre_technique,
            mitre_tactic,
            started_at,
            status
        )
        VALUES (%s, %s, %s, %s, %s, %s, %s)
        """,
        (
            campaign_id,
            profile["name"],
            attack_type,
            mitre_technique,
            mitre_tactic,
            started_at,
            "CREATED"
        )
    )

    connection.commit()

    cursor.close()
    connection.close()

    return {
        "campaign_id": campaign_id,
        "profile": profile["name"],
        "attack_type": attack_type,
        "mitre_technique": mitre_technique,
        "mitre_tactic": mitre_tactic,
        "started_at": started_at
    }


# ============================================================
# Mark Campaign Completed
# ============================================================

def complete_campaign(campaign_id):

    completed_at = datetime.now(timezone.utc)

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        UPDATE campaigns
        SET
            completed_at = %s,
            status = %s
        WHERE campaign_id = %s
        """,
        (
            completed_at,
            "COMPLETED",
            campaign_id
        )
    )

    connection.commit()

    cursor.close()
    connection.close()

    print(
        f"[+] Campaign completion saved: {campaign_id}"
    )


# ============================================================
# Calculate Campaign Metrics
# ============================================================

def update_campaign_metrics(campaign_id):

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT
            COUNT(*) AS total_events,
            COUNT(DISTINCT username) AS unique_users,
            COUNT(DISTINCT client_ip) AS unique_sources,
            COALESCE(MAX(risk_score), 0) AS max_risk_score,
            CASE
                WHEN COUNT(*) = 0 THEN 0
                ELSE
                    COUNT(*) FILTER (
                        WHERE risk_score > 0
                    )::DOUBLE PRECISION
                    / COUNT(*) * 100
            END AS detection_rate
        FROM auth_events
        WHERE campaign_id = %s
        """,
        (campaign_id,)
    )

    result = cursor.fetchone()

    total_events = result[0]
    unique_users = result[1]
    unique_sources = result[2]
    max_risk_score = result[3]
    detection_rate = result[4]

    cursor.execute(
        """
        UPDATE campaigns
        SET
            total_events = %s,
            unique_users = %s,
            unique_sources = %s,
            max_risk_score = %s,
            detection_rate = %s
        WHERE campaign_id = %s
        """,
        (
            total_events,
            unique_users,
            unique_sources,
            max_risk_score,
            detection_rate,
            campaign_id
        )
    )

    connection.commit()

    cursor.close()
    connection.close()

    print()
    print("=" * 70)
    print("              CAMPAIGN METRICS")
    print("=" * 70)
    print(f"Campaign ID     : {campaign_id}")
    print(f"Total Events    : {total_events}")
    print(f"Unique Users    : {unique_users}")
    print(f"Unique Sources  : {unique_sources}")
    print(f"Maximum Risk    : {max_risk_score}")
    print(f"Detection Rate  : {detection_rate:.2f}%")
    print("=" * 70)


# ============================================================
# Generate Final Campaign Report
# ============================================================

def generate_campaign_report(campaign_id):

    connection = get_connection()
    cursor = connection.cursor()

    # --------------------------------------------------------
    # Campaign information
    # --------------------------------------------------------

    cursor.execute(
        """
        SELECT
            campaign_id,
            profile,
            attack_type,
            mitre_technique,
            mitre_tactic,
            started_at,
            completed_at,
            status,
            total_events,
            unique_users,
            unique_sources,
            max_risk_score,
            detection_rate,
            campaign_type,
            correlation_status,
            correlation_score
        FROM campaigns
        WHERE campaign_id = %s
        """,
        (campaign_id,)
    )

    campaign = cursor.fetchone()

    if not campaign:

        print(
            f"[!] Campaign not found: {campaign_id}"
        )

        cursor.close()
        connection.close()

        return

    (
        campaign_id,
        profile,
        attack_type,
        mitre_technique,
        mitre_tactic,
        started_at,
        completed_at,
        status,
        total_events,
        unique_users,
        unique_sources,
        max_risk_score,
        detection_rate,
        campaign_type,
        correlation_status,
        correlation_score
    ) = campaign

    # --------------------------------------------------------
    # Alert statistics
    # --------------------------------------------------------

    cursor.execute(
        """
        SELECT
            COUNT(*) AS total_alerts,

            COUNT(*) FILTER (
                WHERE severity = 'CRITICAL'
            ) AS critical_alerts,

            COUNT(*) FILTER (
                WHERE severity = 'HIGH'
            ) AS high_alerts,

            COUNT(*) FILTER (
                WHERE severity = 'MEDIUM'
            ) AS medium_alerts,

            COUNT(*) FILTER (
                WHERE severity = 'LOW'
            ) AS low_alerts

        FROM alerts
        WHERE campaign_id = %s
        """,
        (campaign_id,)
    )

    alert_stats = cursor.fetchone()

    (
        total_alerts,
        critical_alerts,
        high_alerts,
        medium_alerts,
        low_alerts
    ) = alert_stats

    # --------------------------------------------------------
    # MTTD / MTTR statistics
    # --------------------------------------------------------

    cursor.execute(
        """
        SELECT
            COALESCE(AVG(detection_latency_ms), 0),
            COALESCE(MIN(detection_latency_ms), 0),
            COALESCE(MAX(detection_latency_ms), 0),
            COALESCE(AVG(response_latency_ms), 0),
            COALESCE(MIN(response_latency_ms), 0),
            COALESCE(MAX(response_latency_ms), 0)
        FROM alerts
        WHERE campaign_id = %s
          AND detection_latency_ms IS NOT NULL
        """,
        (campaign_id,)
    )

    performance_stats = cursor.fetchone()

    (
        average_mttd,
        minimum_mttd,
        maximum_mttd,
        average_mttr,
        minimum_mttr,
        maximum_mttr
    ) = performance_stats

    # --------------------------------------------------------
    # Adaptive response statistics
    # --------------------------------------------------------
    #
    # IMPORTANT:
    # Use the alerts table here because every alert stores
    # the response that SOAR actually executed.
    #
    # user_response_states stores only the CURRENT state
    # for a user, so it cannot reconstruct historical
    # campaign responses.
    # --------------------------------------------------------

    cursor.execute(
        """
        SELECT

            COUNT(*) FILTER (
                WHERE response_action = 'MONITOR'
            ),

            COUNT(*) FILTER (
                WHERE response_action = 'CAPTCHA'
            ),

            COUNT(*) FILTER (
                WHERE response_action = 'STEP_UP_MFA'
            ),

            COUNT(*) FILTER (
                WHERE response_action = 'TEMPORARY_RESTRICTION'
            )

        FROM alerts
        WHERE campaign_id = %s
        """,
        (campaign_id,)
    )

    response_stats = cursor.fetchone()

    monitor_count = response_stats[0]
    captcha_count = response_stats[1]
    mfa_count = response_stats[2]
    restriction_count = response_stats[3]

    # --------------------------------------------------------
    # Campaign duration
    # --------------------------------------------------------

    duration_seconds = 0

    if started_at and completed_at:

        duration_seconds = (
            completed_at - started_at
        ).total_seconds()

    # --------------------------------------------------------
    # Response effectiveness
    # --------------------------------------------------------
    #
    # Every alert receiving a SOAR decision counts as handled.
    #
    # MONITOR
    # CAPTCHA
    # STEP_UP_MFA
    # TEMPORARY_RESTRICTION
    #
    # are all valid response actions.
    # --------------------------------------------------------

    if total_alerts > 0:

        response_actions = (
            monitor_count
            + captcha_count
            + mfa_count
            + restriction_count
        )

        response_effectiveness = min(
            (
                response_actions
                / total_alerts
            ) * 100,
            100
        )

    else:

        response_effectiveness = 0

    # --------------------------------------------------------
    # Save response effectiveness
    # --------------------------------------------------------

    cursor.execute(
        """
        UPDATE campaigns
        SET
            response_effectiveness = %s
        WHERE campaign_id = %s
        """,
        (
            response_effectiveness,
            campaign_id
        )
    )

    connection.commit()

    cursor.close()
    connection.close()

    # --------------------------------------------------------
    # Final Report
    # --------------------------------------------------------

    print()

    print("=" * 70)
    print("              PURPLE TEAM CAMPAIGN REPORT")
    print("=" * 70)

    print()

    print("CAMPAIGN")
    print("-" * 70)

    print(f"Campaign ID       : {campaign_id}")
    print(f"Profile           : {profile}")
    print(f"Attack Type       : {attack_type}")
    print(f"Campaign Status   : {status}")

    print()

    print("MITRE ATT&CK")
    print("-" * 70)

    print(f"Technique         : {mitre_technique}")
    print(f"Tactic            : {mitre_tactic}")

    print()

    print("CAMPAIGN ACTIVITY")
    print("-" * 70)

    print(f"Events Generated  : {total_events}")
    print(f"Users Targeted    : {unique_users}")
    print(f"Sources Observed  : {unique_sources}")
    print(f"Campaign Duration : {duration_seconds:.2f} seconds")

    print()

    print("DETECTION")
    print("-" * 70)

    print(f"Detection Rate    : {detection_rate:.2f}%")
    print(f"Maximum Risk      : {max_risk_score}")
    print(f"Alerts Generated  : {total_alerts}")
    print(f"Critical Alerts   : {critical_alerts}")
    print(f"High Alerts       : {high_alerts}")
    print(f"Medium Alerts     : {medium_alerts}")
    print(f"Low Alerts        : {low_alerts}")

    print()

    # --------------------------------------------------------
    # Performance Metrics
    # --------------------------------------------------------

    print("PERFORMANCE")
    print("-" * 70)

    print(f"Average MTTD      : {average_mttd:.2f} ms")
    print(f"Minimum MTTD      : {minimum_mttd:.2f} ms")
    print(f"Maximum MTTD      : {maximum_mttd:.2f} ms")

    print()

    print(f"Average MTTR      : {average_mttr:.2f} ms")
    print(f"Minimum MTTR      : {minimum_mttr:.2f} ms")
    print(f"Maximum MTTR      : {maximum_mttr:.2f} ms")

    print()

    print("ADAPTIVE RESPONSE")
    print("-" * 70)

    print(f"Monitor Responses : {monitor_count}")
    print(f"CAPTCHA Responses : {captcha_count}")
    print(f"Step-up MFA       : {mfa_count}")
    print(f"Temp Restrictions : {restriction_count}")

    print(
        f"Response Effect.  : "
        f"{response_effectiveness:.2f}%"
    )

    print()

    print("CAMPAIGN CORRELATION")
    print("-" * 70)

    print(f"Campaign Type     : {campaign_type}")
    print(f"Correlation       : {correlation_status}")
    print(f"Correlation Score : {correlation_score}")

    print()

    print("=" * 70)
    print("                 END OF REPORT")
    print("=" * 70)


# ============================================================
# Main Campaign Execution
# ============================================================

def run_campaign(profile_name):
    """
    Run one complete purple-team campaign.
    """

    print()
    print("=" * 70)
    print(f"              RUNNING: {profile_name}")
    print("=" * 70)

    print()
    print(f"[+] Loading profile: {profile_name}")

    profile = load_profile(profile_name)

    campaign = create_campaign(profile)

    campaign_id = campaign["campaign_id"]

    print(
        f"[+] Campaign created: {campaign_id}"
    )

    print(
        f"[+] Attack type: "
        f"{campaign['attack_type']}"
    )

    print(
        f"[+] MITRE technique: "
        f"{campaign['mitre_technique']}"
    )

    print()
    print("[+] Starting attack simulation...")
    print("=" * 70)

    run_attack(
        profile,
        campaign_id
    )

    print()
    print("[+] Attack simulation completed.")

    print(
        "[+] Waiting for detection pipeline..."
    )

    time.sleep(3)

    complete_campaign(
        campaign_id
    )

    update_campaign_metrics(
        campaign_id
    )

    print()
    print("[+] Running campaign correlation...")

    correlate_campaign(
        campaign_id
    )

    print()
    print("[+] Campaign correlation completed.")

    print()
    print("[+] Generating final campaign report...")

    generate_campaign_report(
        campaign_id
    )

    print()
    print(
        f"[+] Campaign {campaign_id} "
        f"completed successfully."
    )

    return campaign_id


# ============================================================
# Interactive Campaign Menu
# ============================================================

def main():

    print()
    print("=" * 70)
    print("             PURPLE TEAM CAMPAIGN")
    print("=" * 70)

    print()
    print("Available attack profiles:")
    print()
    print("1. brute_force")
    print("2. password_spray")
    print("3. credential_stuffing")
    print("4. mfa_fatigue")
    print("5. all")
    print()

    choice = input("Select attack: ").strip()

    attack_profiles = {
        "1": "brute_force",
        "2": "low_slow_spray",
        "3": "credential_stuffing",
        "4": "mfa_fatigue"
    }

    # --------------------------------------------------------
    # Run selected attack
    # --------------------------------------------------------

    if choice in attack_profiles:

        profile_name = attack_profiles[choice]

        run_campaign(
            profile_name
        )

    # --------------------------------------------------------
    # Run all attacks
    # --------------------------------------------------------

    elif choice == "5":

        all_profiles = [
            "brute_force",
            "low_slow_spray",
            "credential_stuffing",
            "mfa_fatigue"
        ]

        print()
        print("=" * 70)
        print("             RUNNING ALL ATTACKS")
        print("=" * 70)

        campaign_ids = []

        for profile_name in all_profiles:

            campaign_id = run_campaign(
                profile_name
            )

            campaign_ids.append(
                campaign_id
            )

            print()
            print("=" * 70)
            print(
                f"[+] Finished: {profile_name}"
            )
            print(
                f"[+] Campaign ID: {campaign_id}"
            )
            print("=" * 70)

            time.sleep(2)

        print()
        print("=" * 70)
        print("             ALL CAMPAIGNS COMPLETED")
        print("=" * 70)

        print()
        print("Campaign IDs:")

        for campaign_id in campaign_ids:
            print(
                f"  - {campaign_id}"
            )

        print()
        print("=" * 70)

    # --------------------------------------------------------
    # Invalid option
    # --------------------------------------------------------

    else:

        print()
        print(
            "[!] Invalid selection."
        )

        print(
            "[!] Please choose an option "
            "from 1 to 5."
        )


# ============================================================
# Entry Point
# ============================================================

if __name__ == "__main__":
    main()
