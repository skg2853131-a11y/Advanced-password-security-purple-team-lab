import json
import math
from datetime import datetime, timezone

from app.database import get_connection

# ============================================================
# LOAD USER BASELINE
# ============================================================

def load_baseline(username):

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT
            average_login_hour,
            login_hour_stddev,
            average_daily_logins,
            common_source_ips,
            common_countries,
            common_user_agents,
            last_login_timestamp,
            last_latitude,
            last_longitude,
            total_events
        FROM user_baselines
        WHERE username = %s
        """,
        (username,)
    )

    baseline = cursor.fetchone()

    cursor.close()
    connection.close()

    if not baseline:
        return None

    return {
        "average_login_hour": baseline[0],
        "login_hour_stddev": baseline[1],
        "average_daily_logins": baseline[2],
        "common_source_ips": baseline[3] or [],
        "common_countries": baseline[4] or [],
        "common_user_agents": baseline[5] or [],
        "last_login_timestamp": baseline[6],
        "last_latitude": baseline[7],
        "last_longitude": baseline[8],
        "total_events": baseline[9]
    }


# ============================================================
# LOGIN HOUR DIFFERENCE
# ============================================================

def calculate_hour_difference(current_hour, baseline_hour):

    difference = abs(current_hour - baseline_hour)

    # Handle midnight crossover.
    return min(difference, 24 - difference)


# ============================================================
# DISTANCE CALCULATION
# HAVERSINE FORMULA
# ============================================================

def calculate_distance_km(
    lat1,
    lon1,
    lat2,
    lon2
):

    if None in (
        lat1,
        lon1,
        lat2,
        lon2
    ):
        return None

    earth_radius_km = 6371.0

    lat1_rad = math.radians(lat1)
    lat2_rad = math.radians(lat2)

    delta_lat = math.radians(
        lat2 - lat1
    )

    delta_lon = math.radians(
        lon2 - lon1
    )

    a = (
        math.sin(delta_lat / 2) ** 2
        +
        math.cos(lat1_rad)
        *
        math.cos(lat2_rad)
        *
        math.sin(delta_lon / 2) ** 2
    )

    c = 2 * math.atan2(
        math.sqrt(a),
        math.sqrt(1 - a)
    )

    return earth_radius_km * c


# ============================================================
# PARSE DATETIME
# ============================================================

def parse_event_datetime(value):

    if not value:
        return None

    if isinstance(value, datetime):
        return value

    try:

        parsed = datetime.fromisoformat(
            value.replace(
                "Z",
                "+00:00"
            )
        )

        if parsed.tzinfo is None:
            parsed = parsed.replace(
                tzinfo=timezone.utc
            )

        return parsed

    except Exception:

        return None


# ============================================================
# BEHAVIORAL DETECTION ENGINE
# ============================================================

def detect_behavior(event):

    username = event.get("username")

    baseline = load_baseline(username)

    # --------------------------------------------------------
    # NO BASELINE
    # --------------------------------------------------------

    if not baseline:

        return {
            "username": username,
            "risk_score": 20,
            "severity": "LOW",
            "anomalies": [
                "NO_BASELINE"
            ]
        }

    risk_score = 0
    anomalies = []

    # ========================================================
    # EVENT TIMESTAMP
    # ========================================================

    timestamp = event.get("timestamp")

    if not timestamp:
        timestamp = datetime.now(timezone.utc)

    if isinstance(timestamp, str):

        try:

            timestamp = datetime.fromisoformat(
                timestamp.replace(
                    "Z",
                    "+00:00"
                )
            )

        except ValueError:

            timestamp = datetime.now(timezone.utc)

    if timestamp.tzinfo is None:

        timestamp = timestamp.replace(
            tzinfo=timezone.utc
        )

    # ========================================================
    # EVENT CONTEXT
    # ========================================================

    attack_profile = event.get(
        "attack_profile"
    )

    metadata = event.get(
        "metadata",
        {}
    ) or {}

    source_ip = event.get(
        "source_ip"
    )

    client_ip = event.get(
        "client_ip"
    )

    user_agent = event.get(
        "user_agent"
    ) or ""

    # ========================================================
    # 1. UNUSUAL LOGIN HOUR
    # ========================================================

    try:

        current_hour = timestamp.hour

        baseline_hour = (
            baseline["average_login_hour"]
        )

        hour_stddev = (
            baseline["login_hour_stddev"]
            or 4
        )

        hour_difference = calculate_hour_difference(
            current_hour,
            baseline_hour
        )

        threshold = max(
            hour_stddev * 2,
            2
        )

        if (
            baseline["total_events"] >= 5
            and hour_difference > threshold
        ):

            risk_score += 20

            anomalies.append(
                "UNUSUAL_LOGIN_HOUR"
            )

    except Exception:

        pass

    # ========================================================
    # 2. NEW SOURCE IP
    # ========================================================

    common_source_ips = (
        baseline["common_source_ips"]
        or []
    )

    observed_source = (
        client_ip
        or source_ip
    )

    if (
        observed_source
        and observed_source not in common_source_ips
    ):

        risk_score += 15

        anomalies.append(
            "NEW_SOURCE_IP"
        )

    # ========================================================
    # 3. NEW USER AGENT
    # ========================================================

    common_user_agents = (
        baseline["common_user_agents"]
        or []
    )

    if (
        user_agent
        and user_agent not in common_user_agents
    ):

        risk_score += 10

        anomalies.append(
            "NEW_USER_AGENT"
        )

    # ========================================================
    # 4. UNUSUAL COUNTRY
    # ========================================================

    country = event.get(
        "country"
    )

    common_countries = (
        baseline["common_countries"]
        or []
    )

    if (
        country
        and country not in common_countries
    ):

        risk_score += 15

        anomalies.append(
            "UNUSUAL_COUNTRY"
        )

    # ========================================================
    # 5. AUTOMATION USER AGENT
    # ========================================================

    suspicious_agents = [
        "headless",
        "selenium",
        "playwright",
        "phantomjs",
        "python-requests",
        "curl",
        "wget"
    ]

    user_agent_lower = (
        user_agent.lower()
    )

    if any(
        keyword in user_agent_lower
        for keyword in suspicious_agents
    ):

        risk_score += 15

        anomalies.append(
            "AUTOMATION_USER_AGENT"
        )

    # ========================================================
    # 6. FAILED AUTHENTICATION
    # ========================================================

    if event.get("result") == "FAILED":

        risk_score += 10

        anomalies.append(
            "FAILED_AUTHENTICATION"
        )

    # ========================================================
    # 6A. BRUTE-FORCE ACTIVITY
    # ========================================================

    if attack_profile == "brute_force":

        source_for_detection = (
            event.get("client_ip")
            or event.get("source_ip")
        )

        try:

            connection = get_connection()
            cursor = connection.cursor()

            cursor.execute(
                """
                SELECT COUNT(*)
                FROM auth_events
                WHERE username = %s
                  AND result IN ('FAILED', 'BLOCKED')
                  AND timestamp >= (
                      %s::timestamptz
                      - INTERVAL '5 minutes'
                  )
                  AND (
                      client_ip = %s
                      OR source_ip = %s
                  )
                """,
                (
                    username,
                    timestamp,
                    source_for_detection,
                    source_for_detection
                )
            )

            recent_failures = (
                cursor.fetchone()[0]
            )

            cursor.close()
            connection.close()

        except Exception:

            recent_failures = 0

        # 3+ attempts
        if recent_failures >= 3:

            risk_score += 25

            anomalies.append(
                "BRUTE_FORCE_ACTIVITY"
            )

        # 5+ attempts
        if recent_failures >= 5:

            risk_score += 25

            anomalies.append(
                "BRUTE_FORCE_ESCALATION"
            )

        # 8+ attempts
        if recent_failures >= 8:

            risk_score += 35

            anomalies.append(
                "BRUTE_FORCE_CRITICAL"
            )

    # ========================================================
    # 7. DATACENTER IP SIMULATION
    # ========================================================

    if metadata.get(
        "datacenter_ip"
    ) is True:

        risk_score += 15

        anomalies.append(
            "DATACENTER_IP"
        )

    # ========================================================
    # 8. TOR NODE SIMULATION
    # ========================================================

    if metadata.get(
        "tor_exit_node"
    ) is True:

        risk_score += 20

        anomalies.append(
            "TOR_EXIT_NODE"
        )

    # ========================================================
    # 9. HEADLESS CLIENT
    # ========================================================

    if metadata.get(
        "headless"
    ) is True:

        risk_score += 15

        anomalies.append(
            "HEADLESS_CLIENT"
        )

    # ========================================================
    # 10. IMPOSSIBLE TRAVEL
    #
    # Compare:
    #
    # previous baseline location
    #        ↓
    # current event location
    #
    # previous login time
    #        ↓
    # current event time
    #
    # distance / elapsed time = travel speed
    # ========================================================

    baseline_latitude = baseline.get(
        "last_latitude"
    )

    baseline_longitude = baseline.get(
        "last_longitude"
    )

    baseline_timestamp = baseline.get(
        "last_login_timestamp"
    )

    event_latitude = event.get(
        "latitude"
    )

    event_longitude = event.get(
        "longitude"
    )

    event_timestamp = event.get(
        "timestamp"
    )

    current_timestamp = parse_event_datetime(
        event_timestamp
    )

    previous_timestamp = parse_event_datetime(
        baseline_timestamp
    )

    if (
        baseline_latitude is not None
        and baseline_longitude is not None
        and event_latitude is not None
        and event_longitude is not None
        and current_timestamp is not None
        and previous_timestamp is not None
    ):

        try:

            distance_km = calculate_distance_km(
                baseline_latitude,
                baseline_longitude,
                event_latitude,
                event_longitude
            )

            elapsed_seconds = (
                current_timestamp
                - previous_timestamp
            ).total_seconds()

            # Only evaluate forward movement in time.
            if (
                distance_km is not None
                and elapsed_seconds > 0
            ):

                elapsed_hours = (
                    elapsed_seconds / 3600
                )

                if elapsed_hours > 0:

                    travel_speed_kmh = (
                        distance_km
                        / elapsed_hours
                    )

                    # Controlled lab threshold.
                    #
                    # Distance must be at least 500 km
                    # and calculated speed must exceed
                    # 900 km/h.
                    if (
                        distance_km >= 500
                        and travel_speed_kmh > 900
                    ):

                        risk_score += 30

                        anomalies.append(
                            "IMPOSSIBLE_TRAVEL"
                        )

                        # Store useful investigation
                        # information in event metadata.
                        metadata[
                            "impossible_travel"
                        ] = True

                        metadata[
                            "travel_distance_km"
                        ] = round(
                            distance_km,
                            2
                        )

                        metadata[
                            "travel_elapsed_hours"
                        ] = round(
                            elapsed_hours,
                            4
                        )

                        metadata[
                            "travel_speed_kmh"
                        ] = round(
                            travel_speed_kmh,
                            2
                        )

        except Exception:

            pass

    # ========================================================
    # 11. PASSWORD SPRAY DETECTION
    # ========================================================

    if attack_profile == "low_slow_password_spray":

        risk_score += 10

        anomalies.append(
            "PASSWORD_SPRAY_ACTIVITY"
        )

    # ========================================================
    # 12. CREDENTIAL STUFFING DETECTION
    # ========================================================

    if attack_profile == "credential_stuffing":

        risk_score += 20

        anomalies.append(
            "CREDENTIAL_STUFFING_ACTIVITY"
        )

    # ========================================================
    # 13. DISTRIBUTED SOURCE SIMULATION
    # ========================================================

    if attack_profile in [
        "low_slow_password_spray",
        "credential_stuffing"
    ]:

        if (
            client_ip
            and client_ip != source_ip
        ):

            risk_score += 5

            anomalies.append(
                "SYNTHETIC_SOURCE_IDENTITY"
            )

    # ========================================================
    # 14. LOW-AND-SLOW ACTIVITY
    # ========================================================

    if attack_profile == "low_slow_password_spray":

        jitter_min = metadata.get(
            "jitter_min_seconds"
        )

        jitter_max = metadata.get(
            "jitter_max_seconds"
        )

        if (
            jitter_min is not None
            and jitter_max is not None
        ):

            anomalies.append(
                "LOW_AND_SLOW_ACTIVITY"
            )

    # ========================================================
    # 15. CREDENTIAL STUFFING CONTEXT
    # ========================================================

    if attack_profile == "credential_stuffing":

        credential_source = metadata.get(
            "credential_source"
        )

        if credential_source == "synthetic":

            anomalies.append(
                "SYNTHETIC_CREDENTIAL_SET"
            )

    # ========================================================
    # 16. MFA FATIGUE / PUSH-JAMMING
    # ========================================================

    if attack_profile == "mfa_fatigue":

        request_number = metadata.get(
            "request_number",
            1
        )

        # Every MFA push request is suspicious
        # in this controlled simulation.
        risk_score += 10

        anomalies.append(
            "MFA_PUSH_REQUEST"
        )

        # 3 or more requests.
        if request_number >= 3:

            risk_score += 15

            anomalies.append(
                "MFA_FATIGUE_ACTIVITY"
            )

        # 5 or more requests.
        if request_number >= 5:

            risk_score += 15

            anomalies.append(
                "MFA_PUSH_BURST"
            )

    # ========================================================
    # CAP RISK SCORE
    # ========================================================

    risk_score = min(
        risk_score,
        100
    )

    # ========================================================
    # SEVERITY
    # ========================================================

    if risk_score >= 80:

        severity = "CRITICAL"

    elif risk_score >= 60:

        severity = "HIGH"

    elif risk_score >= 30:

        severity = "MEDIUM"

    else:

        severity = "LOW"

    # ========================================================
    # RETURN DETECTION RESULT
    # ========================================================

    return {
        "username": username,
        "risk_score": risk_score,
        "severity": severity,
        "anomalies": anomalies
    }
