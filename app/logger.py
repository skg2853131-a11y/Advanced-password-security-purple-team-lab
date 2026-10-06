import logging
import json
from pathlib import Path
from datetime import datetime, timezone

import redis
from app.database import get_connection

# ============================================================
# PATHS
# ============================================================

LOG_DIR = Path(__file__).parent.parent / "logs"
LOG_DIR.mkdir(parents=True, exist_ok=True)

LEGACY_LOG_FILE = LOG_DIR / "auth.log"
JSON_LOG_FILE = LOG_DIR / "auth_events.jsonl"


# ============================================================
# REDIS CONFIGURATION
# ============================================================

REDIS_CONFIG = {
    "host": "127.0.0.1",
    "port": 6379,
    "decode_responses": True
}


# ============================================================
# LEGACY FILE LOGGER
# ============================================================

logging.basicConfig(
    filename=LEGACY_LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s | %(message)s"
)

logger = logging.getLogger("authenticator")


# ============================================================
# CONNECTION HELPERS
# ============================================================

def get_db_connection():
    return get_connection()


def get_redis_connection():
    return redis.Redis(**REDIS_CONFIG)


# ============================================================
# AUTHENTICATION EVENT LOGGER
# ============================================================

def log_auth_event(
    username,
    source_ip,
    result,
    reason,
    user_agent=None,
    client_ip=None,
    forwarded_ip=None,
    country=None,
    latitude=None,
    longitude=None,
    attack_profile=None,
    campaign_id=None,
    mfa_required=False,
    risk_score=0,
    metadata=None,
    event_timestamp=None
):
    """
    Records an authentication event into:

    1. Legacy auth.log
    2. PostgreSQL
    3. Structured JSONL telemetry
    4. Redis Stream

    Important timestamps:

    timestamp:
        Time the authentication event supposedly occurred.

    ingested_at:
        Real time the event entered the telemetry pipeline.

    Detection latency / MTTD should be calculated from ingested_at,
    not from timestamp.
    """

    # --------------------------------------------------------
    # Event occurrence time
    # --------------------------------------------------------

    timestamp = event_timestamp or datetime.now(timezone.utc)

    # --------------------------------------------------------
    # Telemetry ingestion time
    # --------------------------------------------------------

    ingested_at = datetime.now(timezone.utc)

    metadata = metadata or {}

    # Preserve telemetry ingestion time in PostgreSQL metadata.
    # This is required for accurate MTTD measurement.
    metadata["ingested_at"] = ingested_at.isoformat()

    event_id = None


    # ========================================================
    # 1. LEGACY LOGGING
    # ========================================================

    logger.info(
        f"username={username} "
        f"source_ip={source_ip} "
        f"result={result} "
        f"reason={reason}"
    )


    # ========================================================
    # 2. POSTGRESQL TELEMETRY
    # ========================================================

    try:

        connection = get_db_connection()

        cursor = connection.cursor()

        cursor.execute(
            """
            INSERT INTO auth_events (
                timestamp,
                event_type,
                username,
                source_ip,
                client_ip,
                forwarded_ip,
                user_agent,
                result,
                reason,
                country,
                latitude,
                longitude,
                attack_profile,
                campaign_id,
                mfa_required,
                risk_score,
                metadata
            )
            VALUES (
                %s, %s, %s, %s, %s, %s, %s,
                %s, %s, %s, %s, %s, %s, %s,
                %s, %s, %s
            )
            RETURNING event_id
            """,
            (
                timestamp,
                "authentication",
                username,
                source_ip,
                client_ip,
                forwarded_ip,
                user_agent,
                result,
                reason,
                country,
                latitude,
                longitude,
                attack_profile,
                campaign_id,
                mfa_required,
                risk_score,
                json.dumps(metadata)
            )
        )

        event_id = cursor.fetchone()[0]

        connection.commit()

        cursor.close()

        connection.close()

    except Exception as error:

        print(
            f"[!] PostgreSQL telemetry error: {error}"
        )

        return


    # ========================================================
    # STRUCTURED EVENT
    # ========================================================

    event = {

        "event_id": str(event_id),

        # Event/simulation occurrence time
        "timestamp": timestamp.isoformat(),

        # Actual pipeline entry time
        "ingested_at": ingested_at.isoformat(),

        "event_type": "authentication",

        "username": username,

        "source_ip": source_ip,

        "client_ip": client_ip,

        "forwarded_ip": forwarded_ip,

        "user_agent": user_agent,

        "result": result,

        "reason": reason,

        "country": country,

        "latitude": latitude,

        "longitude": longitude,

        "attack_profile": attack_profile,

        "campaign_id": campaign_id,

        "mfa_required": mfa_required,

        "risk_score": risk_score,

        "metadata": metadata
    }


    # ========================================================
    # 3. JSONL TELEMETRY
    # ========================================================

    try:

        with open(
            JSON_LOG_FILE,
            "a",
            encoding="utf-8"
        ) as file:

            file.write(
                json.dumps(event)
                + "\n"
            )

    except Exception as error:

        print(
            f"[!] JSON telemetry error: {error}"
        )


    # ========================================================
    # 4. REDIS STREAM
    # ========================================================

    try:

        redis_client = get_redis_connection()

        redis_client.xadd(
            "auth_events",
            {
                "event": json.dumps(event)
            },
            maxlen=10000,
            approximate=True
        )

        redis_client.close()

    except Exception as error:

        print(
            f"[!] Redis telemetry error: {error}"
        )
