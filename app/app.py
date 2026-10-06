from flask import Flask, request, render_template_string
from app.database import initialize_database, get_connection
from app.auth import verify_password
from app.logger import log_auth_event

from datetime import datetime, timezone


app = Flask(__name__)


LOGIN_PAGE = """
<!DOCTYPE html>
<html>
<head>
    <title>Password Security Lab</title>
</head>
<body>
    <h1>Password Security & Attack Detection Lab</h1>

    <form method="POST" action="/login">
        <label>Username:</label>
        <input type="text" name="username" required>
        <br><br>

        <label>Password:</label>
        <input type="password" name="password" required>
        <br><br>

        <button type="submit">Login</button>
    </form>

    {% if message %}
        <h3>{{ message }}</h3>
    {% endif %}
</body>
</html>
"""


def get_active_response_state(connection, username):
    """
    Retrieve the user's active SOAR response state.

    Expired states are automatically deactivated.
    """

    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT response_action, expires_at
        FROM user_response_states
        WHERE username = %s
          AND active = TRUE
        """,
        (username,)
    )

    state = cursor.fetchone()

    if state is None:
        cursor.close()
        return None

    response_action, expires_at = state

    now = datetime.now(timezone.utc)

    # Handle expired response state.
    if expires_at is not None and expires_at <= now:

        cursor.execute(
            """
            UPDATE user_response_states
            SET active = FALSE
            WHERE username = %s
            """,
            (username,)
        )

        connection.commit()
        cursor.close()

        return None

    cursor.close()

    return response_action


@app.route("/", methods=["GET"])
def home():
    return render_template_string(
        LOGIN_PAGE,
        message=None
    )


@app.route("/login", methods=["POST"])
def login():

    username = request.form.get("username", "")
    password = request.form.get("password", "")

    source_ip = request.remote_addr

    user_agent = request.headers.get("User-Agent")
    client_ip = request.headers.get("X-Client-IP")
    forwarded_ip = request.headers.get("X-Forwarded-For")

    attack_profile = request.headers.get("X-Attack-Profile")
    campaign_id = request.headers.get("X-Campaign-ID")

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT id, username, password_hash, failed_attempts, locked
        FROM users
        WHERE username = %s
        """,
        (username,)
    )

    user = cursor.fetchone()

    # ---------------------------------------------------------
    # USER DOES NOT EXIST
    # ---------------------------------------------------------

    if user is None:

        log_auth_event(
            username,
            source_ip,
            "FAILED",
            "USER_NOT_FOUND",
            user_agent=user_agent,
            client_ip=client_ip,
            forwarded_ip=forwarded_ip,
            attack_profile=attack_profile,
            campaign_id=campaign_id
        )

        cursor.close()
        connection.close()

        return render_template_string(
            LOGIN_PAGE,
            message="Login failed"
        )

    user_id, db_username, password_hash, failed_attempts, locked = user

    # ---------------------------------------------------------
    # CHECK ACCOUNT LOCK
    # ---------------------------------------------------------

    if locked:

        log_auth_event(
            username,
            source_ip,
            "FAILED",
            "ACCOUNT_LOCKED",
            user_agent=user_agent,
            client_ip=client_ip,
            forwarded_ip=forwarded_ip,
            attack_profile=attack_profile,
            campaign_id=campaign_id
        )

        cursor.close()
        connection.close()

        return render_template_string(
            LOGIN_PAGE,
            message="Account is locked"
        )

    # ---------------------------------------------------------
    # CHECK ACTIVE SOAR RESPONSE
    # ---------------------------------------------------------

    response_action = get_active_response_state(
        connection,
        username
    )

    if response_action == "CAPTCHA":

        log_auth_event(
            username,
            source_ip,
            "BLOCKED",
            "SOAR_CAPTCHA_REQUIRED",
            user_agent=user_agent,
            client_ip=client_ip,
            forwarded_ip=forwarded_ip,
            attack_profile=attack_profile,
            campaign_id=campaign_id
        )

        cursor.close()
        connection.close()

        return render_template_string(
            LOGIN_PAGE,
            message="Additional CAPTCHA verification required"
        )

    elif response_action == "STEP_UP_MFA":

        log_auth_event(
            username,
            source_ip,
            "BLOCKED",
            "SOAR_MFA_REQUIRED",
            user_agent=user_agent,
            client_ip=client_ip,
            forwarded_ip=forwarded_ip,
            attack_profile=attack_profile,
            campaign_id=campaign_id
        )

        cursor.close()
        connection.close()

        return render_template_string(
            LOGIN_PAGE,
            message="Step-up MFA verification required"
        )

    elif response_action == "TEMPORARY_RESTRICTION":

        log_auth_event(
            username,
            source_ip,
            "BLOCKED",
            "SOAR_TEMPORARY_RESTRICTION",
            user_agent=user_agent,
            client_ip=client_ip,
            forwarded_ip=forwarded_ip,
            attack_profile=attack_profile,
            campaign_id=campaign_id
        )

        cursor.close()
        connection.close()

        return render_template_string(
            LOGIN_PAGE,
            message="Login temporarily restricted"
        )

    # ---------------------------------------------------------
    # VERIFY PASSWORD
    # ---------------------------------------------------------

    if verify_password(password_hash, password):

        cursor.execute(
            """
            UPDATE users
            SET failed_attempts = 0
            WHERE id = %s
            """,
            (user_id,)
        )

        connection.commit()

        cursor.close()
        connection.close()

        log_auth_event(
            username,
            source_ip,
            "SUCCESS",
            "VALID_PASSWORD",
            user_agent=user_agent,
            client_ip=client_ip,
            forwarded_ip=forwarded_ip,
            attack_profile=attack_profile,
            campaign_id=campaign_id
        )

        return render_template_string(
            LOGIN_PAGE,
            message="Login successful"
        )

    # ---------------------------------------------------------
    # INVALID PASSWORD
    # ---------------------------------------------------------

    else:

        new_failed_attempts = failed_attempts + 1

        cursor.execute(
            """
            UPDATE users
            SET failed_attempts = %s
            WHERE id = %s
            """,
            (new_failed_attempts, user_id)
        )

        connection.commit()

        cursor.close()
        connection.close()

        log_auth_event(
            username,
            source_ip,
            "FAILED",
            "INVALID_PASSWORD",
            user_agent=user_agent,
            client_ip=client_ip,
            forwarded_ip=forwarded_ip,
            attack_profile=attack_profile,
            campaign_id=campaign_id
        )

        return render_template_string(
            LOGIN_PAGE,
            message="Login failed"
        )


if __name__ == "__main__":

    initialize_database()

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False
    )
