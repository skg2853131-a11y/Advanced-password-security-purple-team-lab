import json
from app.database import get_connection

# ============================================================
# Advanced Correlation Configuration
# ============================================================

# Events belonging to the same campaign are considered
# temporally correlated if they occur within this window.
CORRELATION_WINDOW_SECONDS = 300


# ============================================================
# Helper Functions
# ============================================================

def calculate_time_span_seconds(first_timestamp, last_timestamp):
    """
    Calculate campaign activity duration in seconds.
    """

    if first_timestamp is None or last_timestamp is None:
        return 0.0

    return max(
        0.0,
        (last_timestamp - first_timestamp).total_seconds()
    )


def build_correlation_score(
    total_events,
    unique_users,
    unique_sources,
    max_risk_score,
    average_risk_score,
    time_span_seconds,
    technique_count,
    attack_profile_count
):
    """
    Calculate a 0-100 campaign correlation confidence score.

    Scoring factors:

    User spread          -> 20
    Source spread        -> 20
    Event volume         -> 15
    Risk evidence        -> 15
    Time-window match    -> 10
    Technique consistency-> 10
    Attack-profile match -> 10
    """

    score = 0

    # --------------------------------------------------------
    # User spread
    # --------------------------------------------------------

    if unique_users >= 2:
        score += 20

    # --------------------------------------------------------
    # Source spread
    # --------------------------------------------------------

    if unique_sources >= 2:
        score += 20

    # --------------------------------------------------------
    # Event volume
    # --------------------------------------------------------

    if total_events >= 4:
        score += 15

    elif total_events >= 2:
        score += 8

    # --------------------------------------------------------
    # Risk evidence
    # --------------------------------------------------------

    if max_risk_score >= 80:
        score += 15

    elif max_risk_score >= 60:
        score += 12

    elif max_risk_score >= 30:
        score += 8

    elif average_risk_score > 0:
        score += 4

    # --------------------------------------------------------
    # Time-window correlation
    # --------------------------------------------------------

    if total_events >= 2:

        if time_span_seconds <= CORRELATION_WINDOW_SECONDS:
            score += 10

    # --------------------------------------------------------
    # MITRE technique consistency
    # --------------------------------------------------------

    if technique_count == 1:
        score += 10

    elif technique_count > 1:
        score += 5

    # --------------------------------------------------------
    # Attack profile consistency
    # --------------------------------------------------------

    if attack_profile_count == 1:
        score += 10

    elif attack_profile_count > 1:
        score += 5

    return min(score, 100)


def determine_campaign_type(
    attack_type,
    total_events,
    unique_users,
    time_span_seconds
):
    """
    Determine the campaign classification while considering
    both event spread and temporal correlation.
    """

    temporally_correlated = (
        total_events >= 2
        and time_span_seconds <= CORRELATION_WINDOW_SECONDS
    )

    distributed = (
        total_events >= 2
        and unique_users >= 2
        and temporally_correlated
    )

    # --------------------------------------------------------
    # Password Spray
    # --------------------------------------------------------

    if attack_type == "password_spray":

        if distributed:

            return (
                "DISTRIBUTED_PASSWORD_SPRAY",
                "CORRELATED"
            )

        elif total_events > 0:

            return (
                "PASSWORD_SPRAY",
                "PARTIAL"
            )

        else:

            return (
                "NO_ACTIVITY",
                "NO_EVENTS"
            )

    # --------------------------------------------------------
    # Credential Stuffing
    # --------------------------------------------------------

    if attack_type == "credential_stuffing":

        if distributed:

            return (
                "DISTRIBUTED_CREDENTIAL_STUFFING",
                "CORRELATED"
            )

        elif total_events > 0:

            return (
                "CREDENTIAL_STUFFING",
                "PARTIAL"
            )

        else:

            return (
                "NO_ACTIVITY",
                "NO_EVENTS"
            )

    # --------------------------------------------------------
    # Generic Attack Types
    # --------------------------------------------------------

    if distributed:

        return (
            "DISTRIBUTED_" + attack_type.upper(),
            "CORRELATED"
        )

    elif total_events > 0:

        return (
            attack_type.upper(),
            "PARTIAL"
        )

    return (
        "NO_ACTIVITY",
        "NO_EVENTS"
    )


# ============================================================
# Campaign Correlation
# ============================================================

def correlate_campaign(campaign_id):

    connection = get_connection()
    cursor = connection.cursor()

    try:

        # ----------------------------------------------------
        # Get campaign information
        # ----------------------------------------------------

        cursor.execute(
            """
            SELECT
                attack_type,
                mitre_technique,
                mitre_tactic
            FROM campaigns
            WHERE campaign_id = %s
            """,
            (campaign_id,)
        )

        campaign = cursor.fetchone()

        if campaign is None:

            print(
                f"[!] Campaign not found: {campaign_id}"
            )

            return

        attack_type = campaign[0]
        mitre_technique = campaign[1]
        mitre_tactic = campaign[2]

        # ----------------------------------------------------
        # Campaign event summary
        # ----------------------------------------------------

        cursor.execute(
            """
            SELECT
                COUNT(*) AS total_events,
                COUNT(DISTINCT username) AS unique_users,
                COUNT(DISTINCT client_ip) AS unique_sources,
                COALESCE(MAX(risk_score), 0) AS max_risk_score,
                COALESCE(AVG(risk_score), 0) AS average_risk_score,
                MIN(timestamp) AS first_event,
                MAX(timestamp) AS last_event,
                COUNT(DISTINCT attack_profile)
                    FILTER (
                        WHERE attack_profile IS NOT NULL
                    ) AS attack_profile_count
            FROM auth_events
            WHERE campaign_id = %s
            """,
            (campaign_id,)
        )

        summary = cursor.fetchone()

        total_events = summary[0]
        unique_users = summary[1]
        unique_sources = summary[2]
        max_risk_score = summary[3]
        average_risk_score = float(summary[4])
        first_event = summary[5]
        last_event = summary[6]
        attack_profile_count = summary[7]

        # ----------------------------------------------------
        # Time-window analysis
        # ----------------------------------------------------

        time_span_seconds = calculate_time_span_seconds(
            first_event,
            last_event
        )

        # ----------------------------------------------------
        # Distinct MITRE / attack-profile evidence
        #
        # auth_events stores attack_profile.
        # MITRE technique comes from the campaign itself.
        # ----------------------------------------------------

        cursor.execute(
            """
            SELECT COUNT(DISTINCT attack_profile)
            FROM auth_events
            WHERE campaign_id = %s
              AND attack_profile IS NOT NULL
            """,
            (campaign_id,)
        )

        technique_result = cursor.fetchone()

        technique_count = (
            technique_result[0]
            if technique_result
            else 0
        )

        # If the campaign has a single known MITRE technique,
        # treat it as consistent evidence.
        if mitre_technique:
            technique_count = max(1, technique_count)

        # ----------------------------------------------------
        # Correlated users
        # ----------------------------------------------------

        cursor.execute(
            """
            SELECT DISTINCT username
            FROM auth_events
            WHERE campaign_id = %s
              AND username IS NOT NULL
            ORDER BY username
            """,
            (campaign_id,)
        )

        users = [
            row[0]
            for row in cursor.fetchall()
        ]

        # ----------------------------------------------------
        # Correlated sources
        # ----------------------------------------------------

        cursor.execute(
            """
            SELECT DISTINCT client_ip::text
            FROM auth_events
            WHERE campaign_id = %s
              AND client_ip IS NOT NULL
            ORDER BY client_ip::text
            """,
            (campaign_id,)
        )

        sources = [
            row[0]
            for row in cursor.fetchall()
        ]

        # ----------------------------------------------------
        # Determine Campaign Type
        # ----------------------------------------------------

        campaign_type, correlation_status = determine_campaign_type(
            attack_type,
            total_events,
            unique_users,
            time_span_seconds
        )

        # ----------------------------------------------------
        # Advanced Correlation Score
        # ----------------------------------------------------

        correlation_score = build_correlation_score(
            total_events=total_events,
            unique_users=unique_users,
            unique_sources=unique_sources,
            max_risk_score=max_risk_score,
            average_risk_score=average_risk_score,
            time_span_seconds=time_span_seconds,
            technique_count=technique_count,
            attack_profile_count=attack_profile_count
        )

        # ----------------------------------------------------
        # Build detailed correlation metadata
        #
        # Stored inside existing JSONB metadata column.
        # No database schema change required.
        # ----------------------------------------------------

        correlation_metadata = {
            "correlation_engine": "advanced_v2",
            "correlation_window_seconds":
                CORRELATION_WINDOW_SECONDS,

            "total_events": total_events,
            "unique_users": unique_users,
            "unique_sources": unique_sources,

            "first_event":
                first_event.isoformat()
                if first_event
                else None,

            "last_event":
                last_event.isoformat()
                if last_event
                else None,

            "time_span_seconds":
                round(time_span_seconds, 3),

            "temporally_correlated":
                (
                    total_events >= 2
                    and time_span_seconds
                    <= CORRELATION_WINDOW_SECONDS
                ),

            "max_risk_score":
                max_risk_score,

            "average_risk_score":
                round(average_risk_score, 2),

            "attack_profile_count":
                attack_profile_count,

            "technique_count":
                technique_count,

            "user_spread":
                unique_users,

            "source_spread":
                unique_sources,

            "mitre_technique":
                mitre_technique,

            "mitre_tactic":
                mitre_tactic
        }

        # ----------------------------------------------------
        # Update Campaign
        # ----------------------------------------------------

        cursor.execute(
            """
            UPDATE campaigns
            SET
                campaign_type = %s,
                correlation_status = %s,
                correlated_users = %s::jsonb,
                correlated_sources = %s::jsonb,
                correlation_score = %s,
                metadata = COALESCE(metadata, '{}'::jsonb)
                    || %s::jsonb
            WHERE campaign_id = %s
            """,
            (
                campaign_type,
                correlation_status,
                json.dumps(users),
                json.dumps(sources),
                correlation_score,
                json.dumps({
                    "correlation": correlation_metadata
                }),
                campaign_id
            )
        )

        connection.commit()

        # ====================================================
        # Display Results
        # ====================================================

        print()
        print("=" * 70)
        print("              ADVANCED CAMPAIGN CORRELATION")
        print("=" * 70)

        print(
            f"Campaign ID       : {campaign_id}"
        )

        print(
            f"Attack Type       : {attack_type}"
        )

        print(
            f"MITRE Technique   : {mitre_technique}"
        )

        print(
            f"MITRE Tactic      : {mitre_tactic}"
        )

        print(
            f"Campaign Type     : {campaign_type}"
        )

        print(
            f"Correlation       : {correlation_status}"
        )

        print()

        print("CORRELATION EVIDENCE")
        print("-" * 70)

        print(
            f"Events            : {total_events}"
        )

        print(
            f"Unique Users      : {unique_users}"
        )

        print(
            f"Unique Sources    : {unique_sources}"
        )

        print(
            f"Attack Profiles   : {attack_profile_count}"
        )

        print(
            f"Techniques        : {technique_count}"
        )

        print(
            f"Maximum Risk      : {max_risk_score}"
        )

        print(
            f"Average Risk      : {average_risk_score:.2f}"
        )

        print(
            f"Time Span         : {time_span_seconds:.2f} seconds"
        )

        print(
            f"Correlation Window: {CORRELATION_WINDOW_SECONDS} seconds"
        )

        print(
            "Temporal Match    : "
            + (
                "YES"
                if (
                    total_events >= 2
                    and time_span_seconds
                    <= CORRELATION_WINDOW_SECONDS
                )
                else "NO"
            )
        )

        print()

        print("CORRELATION CONFIDENCE")
        print("-" * 70)

        print(
            f"Correlation Score : {correlation_score}/100"
        )

        print()

        print("[+] Correlated Users:")

        if users:

            for user in users:

                print(
                    f"    - {user}"
                )

        else:

            print("    - None")

        print()

        print("[+] Correlated Sources:")

        if sources:

            for source in sources:

                print(
                    f"    - {source}"
                )

        else:

            print("    - None")

        print()

        print("[+] Correlation Metadata:")

        print(
            f"    Time Window    : "
            f"{CORRELATION_WINDOW_SECONDS}s"
        )

        print(
            f"    User Spread    : "
            f"{unique_users} users"
        )

        print(
            f"    Source Spread  : "
            f"{unique_sources} sources"
        )

        print(
            f"    Risk Evidence  : "
            f"{max_risk_score} max / "
            f"{average_risk_score:.2f} avg"
        )

        print(
            f"    MITRE Mapping  : "
            f"{mitre_technique}"
        )

        print()
        print("=" * 70)

    except Exception as error:

        connection.rollback()

        print(
            f"[!] Campaign correlation error: {error}"
        )

        raise

    finally:

        cursor.close()
        connection.close()


# ============================================================
# Standalone Test
# ============================================================

if __name__ == "__main__":

    print(
        "Usage:"
    )

    print(
        "python3 -c "
        "\"from detection.campaign_correlation "
        "import correlate_campaign; "
        "correlate_campaign('CAMPAIGN_ID')\""
    )
