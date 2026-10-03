from flask import Flask, request, render_template_string
from app.database import initialize_database, get_connection
from app.auth import verify_password
from app.logger import log_auth_event

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


@app.route("/", methods=["GET"])
def home():
    return render_template_string(LOGIN_PAGE, message=None)


@app.route("/login", methods=["POST"])
def login():

    username = request.form.get("username", "")
    password = request.form.get("password", "")

    source_ip = request.remote_addr

    connection = get_connection()

    user = connection.execute(
        """
        SELECT id, username, password_hash, failed_attempts, locked
        FROM users
        WHERE username = ?
        """,
        (username,)
    ).fetchone()

    # User does not exist
    if user is None:
        log_auth_event(
            username,
            source_ip,
            "FAILED",
            "USER_NOT_FOUND"
        )

        connection.close()

        return render_template_string(
            LOGIN_PAGE,
            message="Login failed"
        )

    user_id, db_username, password_hash, failed_attempts, locked = user

    # Check whether account is locked
    if locked:
        log_auth_event(
            username,
            source_ip,
            "FAILED",
            "ACCOUNT_LOCKED"
        )

        connection.close()

        return render_template_string(
            LOGIN_PAGE,
            message="Account is locked"
        )

    # Verify password
    if verify_password(password_hash, password):

        connection.execute(
            """
            UPDATE users
            SET failed_attempts = 0
            WHERE id = ?
            """,
            (user_id,)
        )

        connection.commit()
        connection.close()

        log_auth_event(
            username,
            source_ip,
            "SUCCESS",
            "VALID_PASSWORD"
        )

        return render_template_string(
            LOGIN_PAGE,
            message="Login successful"
        )

    else:

        new_failed_attempts = failed_attempts + 1

        connection.execute(
            """
            UPDATE users
            SET failed_attempts = ?
            WHERE id = ?
            """,
            (new_failed_attempts, user_id)
        )

        connection.commit()
        connection.close()

        log_auth_event(
            username,
            source_ip,
            "FAILED",
            "INVALID_PASSWORD"
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
