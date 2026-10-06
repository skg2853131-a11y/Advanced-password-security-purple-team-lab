import json
from app.database import get_connection
from datetime import datetime, timezone


# ============================================================
# MITRE ATT&CK MAPPING
# ============================================================

ATTACK_MAPPING = {

    "FAILED_AUTHENTICATION": {
        "technique": "T1110",
        "tactic": "Credential Access"
    },

    "BRUTE_FORCE_ACTIVITY": {
        "technique": "T1110.001",
        "tactic": "Credential Access"
    },

    "BRUTE_FORCE_ESCALATION": {
        "technique": "T1110.001",
        "tactic": "Credential Access"
    },

    "BRUTE_FORCE_CRITICAL": {
        "technique": "T1110.001",
        "tactic": "Credential Access"
    },

    "PASSWORD_SPRAY_ACTIVITY": {
        "technique": "T1110.003",
        "tactic": "Credential Access"
    },

    "CREDENTIAL_STUFFING_ACTIVITY": {
        "technique": "T1110.004",
        "tactic": "Credential Access"
    },

    "MFA_PUSH_REQUEST": {
        "technique": "T1621",
        "tactic": "Credential Access"
    },

    "MFA_FATIGUE_ACTIVITY": {
        "technique": "T1621",
        "tactic": "Credential Access"
    },

    "MFA_PUSH_BURST": {
        "technique": "T1621",
        "tactic": "Credential Access"
    },

    "AUTOMATION_USER_AGENT": {
        "technique": "T1110",
        "tactic": "Credential Access"
    },

    "HEADLESS_CLIENT": {
        "technique": "T1110",
        "tactic": "Credential Access"
    },

    "DATACENTER_IP": {
        "technique": "T1078",
        "tactic": "Defense Evasion"
    },

    "TOR_EXIT_NODE": {
        "technique": "T1078",
        "tactic": "Defense Evasion"
    },

    "IMPOSSIBLE_TRAVEL": {
        "technique": "T1078",
        "tactic": "Defense Evasion"
    },

    "SYNTHETIC_SOURCE_IDENTITY": {
        "technique": "T1078",
        "tactic": "Defense Evasion"
    },

    "SYNTHETIC_CREDENTIAL_SET": {
        "technique": "T1110.004",
        "tactic": "Credential Access"
    }
}

# ============================================================
# DATABASE CONNECTION
# ============================================================

def get_connection():

    connection = get_connection()
    


# ============================================================
# MITRE ATT&CK MAPPING
# ============================================================

def determine_attack_mapping(anomalies):
    """
    Select the most specific MITRE ATT&CK mapping
    based on detected behavioral anomalies.
    """

    if "CREDENTIAL_STUFFING_ACTIVITY" in anomalies:

        return ATTACK_MAPPING[
            "CREDENTIAL_STUFFING_ACTIVITY"
        ]

    if "PASSWORD_SPRAY_ACTIVITY" in anomalies:

        return ATTACK_MAPPING[
            "PASSWORD_SPRAY_ACTIVITY"
        ]

    if "MFA_PUSH_BURST" in anomalies:

        return ATTACK_MAPPING[
            "MFA_PUSH_BURST"
        ]

    if "MFA_FATIGUE_ACTIVITY" in anomalies:

        return ATTACK_MAPPING[
            "MFA_FATIGUE_ACTIVITY"
        ]

    if "MFA_PUSH_REQUEST" in anomalies:

        return ATTACK_MAPPING[
            "MFA_PUSH_REQUEST"
        ]

    if "BRUTE_FORCE_CRITICAL" in anomalies:

        return ATTACK_MAPPING[
            "BRUTE_FORCE_CRITICAL"
        ]

    if "BRUTE_FORCE_ESCALATION" in anomalies:

        return ATTACK_MAPPING[
            "BRUTE_FORCE_ESCALATION"
        ]

    if "BRUTE_FORCE_ACTIVITY" in anomalies:

        return ATTACK_MAPPING[
            "BRUTE_FORCE_ACTIVITY"
        ]

    for anomaly in anomalies:

        if anomaly in ATTACK_MAPPING:

            return ATTACK_MAPPING[
                anomaly
            ]

    return {
        "technique": "UNKNOWN",
        "tactic": "Unknown"
    }


# ============================================================
# ALERT TYPE PRIORITY
# ============================================================

def determine_alert_type(anomalies):
    """
    Select the most meaningful alert type.

    This prevents secondary anomalies such as
    NEW_SOURCE_IP from hiding the primary attack
    behavior such as MFA_PUSH_BURST.
    """

    ALERT_PRIORITY = [

        "MFA_PUSH_BURST",
        "MFA_FATIGUE_ACTIVITY",
        "MFA_PUSH_REQUEST",

        "CREDENTIAL_STUFFING_ACTIVITY",
        "PASSWORD_SPRAY_ACTIVITY",

        "BRUTE_FORCE_CRITICAL",
        "BRUTE_FORCE_ESCALATION",
        "BRUTE_FORCE_ACTIVITY",

        "IMPOSSIBLE_TRAVEL",

        "HEADLESS_CLIENT",
        "AUTOMATION_USER_AGENT",

        "TOR_EXIT_NODE",
        "DATACENTER_IP",

        "SYNTHETIC_SOURCE_IDENTITY",
        "SYNTHETIC_CREDENTIAL_SET",

        "FAILED_AUTHENTICATION",

        "NEW_SOURCE_IP",
        "NEW_USER_AGENT",
        "UNUSUAL_LOGIN_HOUR",
        "UNUSUAL_COUNTRY"
    ]

    for anomaly in ALERT_PRIORITY:

        if anomaly in anomalies:

            return anomaly

    if anomalies:

        return anomalies[0]

    return "AUTHENTICATION_ACTIVITY"


# ============================================================
# EVENT TIMESTAMP PARSER
# ============================================================

def parse_event_timestamp(event_timestamp):
    """
    Convert an event timestamp into a
    timezone-aware datetime.
    """

    if not event_timestamp:

        return None

    if isinstance(
        event_timestamp,
        datetime
    ):

        if event_timestamp.tzinfo is None:

            return event_timestamp.replace(
                tzinfo=timezone.utc
            )

        return event_timestamp

    try:

        parsed = datetime.fromisoformat(
            str(event_timestamp).replace(
                "Z",
                "+00:00"
            )
        )

        if parsed.tzinfo is None:

            parsed = parsed.replace(
                tzinfo=timezone.utc
            )

        return parsed

    except (
        ValueError,
        TypeError
    ):

        return None


# ============================================================
# CREATE ALERT
# ============================================================

def create_alert(event, detection_result):
    """
    Create an alert in PostgreSQL from the
    behavioral detection result.

    MTTD is calculated from the telemetry
    ingestion time when available.

    This allows historical/synthetic event
    timestamps to be used without producing
    artificially huge MTTD values.
    """

    connection = get_connection()
    cursor = connection.cursor()

    try:

        # ====================================================
        # RISK SCORE
        # ====================================================

        risk_score = int(
            detection_result.get(
                "risk_score",
                0
            )
        )

        # ====================================================
        # ANOMALIES
        # ====================================================

        anomalies = detection_result.get(
            "anomalies",
            []
        )

        if not isinstance(
            anomalies,
            list
        ):

            anomalies = [
                str(anomalies)
            ]

        # ====================================================
        # MITRE ATT&CK
        # ====================================================

        attack_mapping = determine_attack_mapping(
            anomalies
        )

        attack_technique = attack_mapping.get(
            "technique",
            "UNKNOWN"
        )

        attack_tactic = attack_mapping.get(
            "tactic",
            "Unknown"
        )

        # ====================================================
        # SEVERITY
        # ====================================================

        if risk_score >= 80:

            severity = "CRITICAL"

        elif risk_score >= 60:

            severity = "HIGH"

        elif risk_score >= 30:

            severity = "MEDIUM"

        else:

            severity = "LOW"

        # ====================================================
        # ALERT TYPE
        # ====================================================

        alert_type = determine_alert_type(
            anomalies
        )

        # ====================================================
        # DESCRIPTION
        # ====================================================

        description = (
            "Authentication security event detected: "
            +
            (
                ", ".join(anomalies)
                if anomalies
                else "No specific anomaly"
            )
        )

        # ====================================================
        # DETECTION TIME
        # ====================================================

        detected_at = datetime.now(
            timezone.utc
        )

        # ====================================================
        # MTTD CALCULATION
        #
        # IMPORTANT:
        #
        # event.timestamp =
        #     simulated/historical event time
        #
        # event.ingested_at =
        #     time telemetry entered the
        #     detection pipeline
        #
        # MTTD uses ingested_at.
        # ====================================================

        ingestion_timestamp = (
            event.get("ingested_at")
        )

        ingestion_time = parse_event_timestamp(
            ingestion_timestamp
        )

        # Fallback for older events that do not
        # have ingested_at.
        if ingestion_time is None:

            ingestion_time = detected_at

        detection_latency_ms = (
            detected_at - ingestion_time
        ).total_seconds() * 1000

        # Never allow negative latency.

        if detection_latency_ms < 0:

            detection_latency_ms = 0.0

        # ====================================================
        # EVENT TIMESTAMP
        #
        # Used only for metadata/reference.
        # NOT used for MTTD.
        # ====================================================

        event_timestamp = parse_event_timestamp(
            event.get("timestamp")
        )

        # ====================================================
        # METADATA
        # ====================================================

        metadata = {

            "event_id":
                event.get("event_id"),

            "event_type":
                event.get("event_type"),

            "result":
                event.get("result"),

            "reason":
                event.get("reason"),

            "source_ip":
                event.get("source_ip"),

            "client_ip":
                event.get("client_ip"),

            "forwarded_ip":
                event.get("forwarded_ip"),

            "user_agent":
                event.get("user_agent"),

            "attack_profile":
                event.get("attack_profile"),

            "campaign_id":
                event.get("campaign_id"),

            "anomalies":
                anomalies,

            "risk_score":
                risk_score,

            "event_timestamp":
                event_timestamp.isoformat()
                if event_timestamp
                else None,

            "ingested_at":
                ingestion_time.isoformat(),

            "detection_latency_ms":
                detection_latency_ms
        }

        # ====================================================
        # INSERT ALERT
        # ====================================================

        cursor.execute(
            """
            INSERT INTO alerts (
                timestamp,
                username,
                risk_score,
                severity,
                alert_type,
                description,
                attack_technique,
                attack_tactic,
                campaign_id,
                status,
                metadata,
                detected_at,
                detection_latency_ms
            )
            VALUES (
                %s,
                %s,
                %s,
                %s,
                %s,
                %s,
                %s,
                %s,
                %s,
                %s,
                %s,
                %s,
                %s
            )
            RETURNING id
            """,
            (
                detected_at,

                event.get(
                    "username"
                ),

                risk_score,

                severity,

                alert_type,

                description,

                attack_technique,

                attack_tactic,

                event.get(
                    "campaign_id"
                ),

                "OPEN",

                json.dumps(
                    metadata
                ),

                detected_at,

                detection_latency_ms
            )
        )

        alert_id = cursor.fetchone()[0]

        connection.commit()

        # ====================================================
        # TERMINAL OUTPUT
        # ====================================================

        print(
            f"[ALERT] "
            f"ID={alert_id} "
            f"USER={event.get('username')} "
            f"RISK={risk_score} "
            f"SEVERITY={severity} "
            f"TYPE={alert_type} "
            f"MITRE={attack_technique} "
            f"MTTD={detection_latency_ms:.2f} ms"
        )

        return alert_id

    except Exception:

        connection.rollback()

        raise

    finally:

        cursor.close()

        connection.close()
