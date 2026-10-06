import json
import redis
from app.database import get_connection

from detection.behavioral import detect_behavior
from detection.alert_engine import create_alert
from response.soar import execute_response


REDIS_HOST = "127.0.0.1"
REDIS_PORT = 6379

STREAM_NAME = "auth_events"

# Start with NEW events only.
# Old Redis events will not be replayed.
LAST_ID = "$"



# ============================================================
# Redis Connection
# ============================================================

def get_redis_connection():

    return redis.Redis(
        host=REDIS_HOST,
        port=REDIS_PORT,
        decode_responses=True
    )




# ============================================================
# Update Original Event Risk
# ============================================================

def update_event_risk(event_id, risk_score):

    if not event_id:

        print(
            "[!] No event_id found. "
            "Cannot update auth_events."
        )

        return

    try:

        connection = get_db_connection()
        cursor = connection.cursor()

        cursor.execute(
            """
            UPDATE auth_events
            SET risk_score = %s
            WHERE event_id = %s
            """,
            (
                risk_score,
                event_id
            )
        )

        connection.commit()

        if cursor.rowcount == 1:

            print(
                f"[+] Updated auth_events "
                f"event_id={event_id} "
                f"risk_score={risk_score}"
            )

        else:

            print(
                f"[!] No auth_events row found "
                f"for event_id={event_id}"
            )

        cursor.close()
        connection.close()

    except Exception as error:

        print(
            f"[!] PostgreSQL risk update error: "
            f"{error}"
        )


# ============================================================
# Analyze Authentication Event
# ============================================================

def analyze_event(event):

    print()
    print("=" * 70)
    print("             REAL-TIME DETECTION")
    print("=" * 70)

    print(
        f"[*] Event ID    : "
        f"{event.get('event_id')}"
    )

    print(
        f"[*] Username    : "
        f"{event.get('username')}"
    )

    print(
        f"[*] Source IP   : "
        f"{event.get('source_ip')}"
    )

    print(
        f"[*] User-Agent  : "
        f"{event.get('user_agent')}"
    )

    print(
        f"[*] Result      : "
        f"{event.get('result')}"
    )

    print(
        f"[*] Reason      : "
        f"{event.get('reason')}"
    )

    # ========================================================
    # Behavioral Analysis
    # ========================================================

    result = detect_behavior(
        event
    )

    risk_score = result.get(
        "risk_score",
        0
    )

    # ========================================================
    # Update Original Telemetry
    # ========================================================

    update_event_risk(
        event.get("event_id"),
        risk_score
    )

    # ========================================================
    # Create Alert
    # ========================================================

    alert_id = create_alert(
        event,
        result
    )

    # ========================================================
    # Adaptive SOAR
    # ========================================================

    response = execute_response(
        event.get("username"),
        risk_score,
        alert_id
    )

    # ========================================================
    # Detection / Response Summary
    # ========================================================

    print()
    print("[+] Behavioral Analysis")

    print(
        f"    Risk Score : "
        f"{risk_score}"
    )

    print(
        f"    Severity   : "
        f"{result.get('severity')}"
    )

    print(
        f"    Alert ID   : "
        f"{alert_id if alert_id else 'NONE'}"
    )

    print(
        f"    SOAR Action: "
        f"{response}"
    )

    # ========================================================
    # Anomaly Details
    # ========================================================

    if result.get("anomalies"):

        print()
        print("[!] Anomalies detected:")

        for anomaly in result["anomalies"]:

            print(
                f"    - {anomaly}"
            )

    else:

        print()
        print(
            "[OK] No behavioral anomalies detected"
        )

    print("=" * 70)


# ============================================================
# Main Detection Worker
# ============================================================

def main():

    redis_client = get_redis_connection()

    print("=" * 70)
    print("       REAL-TIME BEHAVIORAL DETECTION WORKER")
    print("=" * 70)

    print(
        f"[*] Listening to stream: "
        f"{STREAM_NAME}"
    )

    print(
        "[*] Waiting for NEW authentication events..."
    )

    print()

    global LAST_ID

    try:

        while True:

            try:

                events = redis_client.xread(
                    {
                        STREAM_NAME: LAST_ID
                    },
                    count=10,
                    block=5000
                )

            except redis.exceptions.TimeoutError:

                # No event arrived during the wait period.
                # Keep the worker alive.
                continue

            if not events:

                continue

            for stream_name, messages in events:

                for message_id, fields in messages:

                    LAST_ID = message_id

                    raw_event = fields.get(
                        "event"
                    )

                    if not raw_event:

                        continue

                    try:

                        event = json.loads(
                            raw_event
                        )

                        analyze_event(
                            event
                        )

                    except json.JSONDecodeError:

                        print(
                            "[!] Invalid JSON event received"
                        )

                    except Exception as error:

                        print(
                            f"[!] Event processing error: "
                            f"{error}"
                        )

    except KeyboardInterrupt:

        print()

        print(
            "[*] Detection worker stopped."
        )

    finally:

        redis_client.close()


# ============================================================
# Entry Point
# ============================================================

if __name__ == "__main__":

    main()
