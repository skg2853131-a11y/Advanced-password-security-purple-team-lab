from app.database import get_connection
from datetime import datetime, timezone, timedelta



# ============================================================
# Determine Adaptive Response
# ============================================================

def determine_response(risk_score):
    """
    Determine the adaptive SOAR response based on risk score.
    """

    if risk_score >= 80:
        return "TEMPORARY_RESTRICTION"

    elif risk_score >= 60:
        return "STEP_UP_MFA"

    elif risk_score >= 30:
        return "CAPTCHA"

    else:
        return "MONITOR"


# ============================================================
# Store User Response State
# ============================================================

def store_response_state(username, response_action):
    """
    Store or update the active response state for a user.
    """

    if response_action == "MONITOR":
        return

    # Response durations for the lab.
    if response_action == "CAPTCHA":
        duration_minutes = 15

    elif response_action == "STEP_UP_MFA":
        duration_minutes = 30

    elif response_action == "TEMPORARY_RESTRICTION":
        duration_minutes = 30

    else:
        duration_minutes = 15

    created_at = datetime.now(timezone.utc)

    expires_at = (
        created_at +
        timedelta(minutes=duration_minutes)
    )

    conn = get_connection()

    cursor = None

    try:

        cursor = conn.cursor()

        cursor.execute(
            """
            INSERT INTO user_response_states (
                username,
                response_action,
                active,
                created_at,
                expires_at
            )
            VALUES (
                %s,
                %s,
                TRUE,
                %s,
                %s
            )

            ON CONFLICT (username)
            DO UPDATE SET
                response_action = EXCLUDED.response_action,
                active = TRUE,
                created_at = EXCLUDED.created_at,
                expires_at = EXCLUDED.expires_at
            """,
            (
                username,
                response_action,
                created_at,
                expires_at
            )
        )

        conn.commit()

        print(
            f"[+] Response state stored: "
            f"{username} -> {response_action}"
        )

    finally:

        if cursor:
            cursor.close()

        conn.close()


# ============================================================
# Record Response Against Exact Alert
# ============================================================

def record_alert_response(
    alert_id,
    response_action,
    response_at,
    response_latency_ms
):
    """
    Record the SOAR response against the exact alert.
    """

    if not alert_id:
        return

    conn = get_connection()

    cursor = None

    try:

        cursor = conn.cursor()

        cursor.execute(
            """
            UPDATE alerts
            SET
                response_action = %s,
                response_at = %s,
                response_latency_ms = %s,
                status = 'RESPONDED'
            WHERE id = %s
            """,
            (
                response_action,
                response_at,
                response_latency_ms,
                alert_id
            )
        )

        conn.commit()

        if cursor.rowcount > 0:

            print(
                f"[+] Alert response recorded: "
                f"Alert {alert_id} -> {response_action}"
            )

    finally:

        if cursor:
            cursor.close()

        conn.close()


# ============================================================
# Execute Adaptive SOAR Response
# ============================================================

def execute_response(
    username,
    risk_score,
    alert_id=None
):
    """
    Determine and execute the adaptive SOAR response.

    alert_id is optional for backward compatibility.
    """

    # --------------------------------------------------------
    # Determine response
    # --------------------------------------------------------

    response = determine_response(
        risk_score
    )

    # --------------------------------------------------------
    # Response timestamp
    # --------------------------------------------------------

    response_at = datetime.now(
        timezone.utc
    )

    print()

    print("=" * 70)
    print("                 ADAPTIVE SOAR")
    print("=" * 70)

    print(
        f"Username   : {username}"
    )

    print(
        f"Risk Score : {risk_score}"
    )

    print(
        f"Response   : {response}"
    )

    if alert_id:
        print(
            f"Alert ID   : {alert_id}"
        )

    # --------------------------------------------------------
    # Display response action
    # --------------------------------------------------------

    if response == "MONITOR":

        print(
            "[+] Action: Continue monitoring"
        )

    elif response == "CAPTCHA":

        print(
            "[!] Action: CAPTCHA challenge required"
        )

    elif response == "STEP_UP_MFA":

        print(
            "[!] Action: Step-up MFA required"
        )

    elif response == "TEMPORARY_RESTRICTION":

        print(
            "[!] Action: Temporary account restriction"
        )

    print("=" * 70)

    # --------------------------------------------------------
    # Store state
    # --------------------------------------------------------

    store_response_state(
        username,
        response
    )

    # --------------------------------------------------------
    # Calculate response latency
    # --------------------------------------------------------
    #
    # The alert engine stores detected_at.
    # We calculate:
    #
    # response_at - detected_at
    #
    # for the exact alert.
    # --------------------------------------------------------

    response_latency_ms = None

    if alert_id:

        conn = get_connection()

        cursor = None

        try:

            cursor = conn.cursor()

            cursor.execute(
                """
                SELECT detected_at
                FROM alerts
                WHERE id = %s
                """,
                (alert_id,)
            )

            result = cursor.fetchone()

            if result and result[0]:

                detected_at = result[0]

                if detected_at.tzinfo is None:

                    detected_at = detected_at.replace(
                        tzinfo=timezone.utc
                    )

                response_latency_ms = (
                    response_at -
                    detected_at
                ).total_seconds() * 1000

                # Prevent negative values from clock issues.
                response_latency_ms = max(
                    response_latency_ms,
                    0
                )

        finally:

            if cursor:
                cursor.close()

            conn.close()

    # --------------------------------------------------------
    # Record exact alert response
    # --------------------------------------------------------

    record_alert_response(
        alert_id,
        response,
        response_at,
        response_latency_ms
    )

    # --------------------------------------------------------
    # Display MTTR value
    # --------------------------------------------------------

    if response_latency_ms is not None:

        print(
            f"[+] Response latency: "
            f"{response_latency_ms:.2f} ms"
        )

    return response


# ============================================================
# SOAR Test
# ============================================================

if __name__ == "__main__":

    print("=" * 70)
    print("                    SOAR TEST")
    print("=" * 70)

    test_scores = [
        20,
        50,
        70,
        90
    ]

    for score in test_scores:

        response = determine_response(
            score
        )

        print(
            f"Risk {score:>3} -> {response}"
        )

    print("=" * 70)
