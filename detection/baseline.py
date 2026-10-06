import json
import math
from collections import Counter
from datetime import datetime, timezone

from app.database import get_connection

def calculate_stddev(values, mean):

    if len(values) < 2:
        return 0.0

    variance = sum(
        (value - mean) ** 2
        for value in values
    ) / len(values)

    return math.sqrt(variance)


def build_baseline(username):

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT
            timestamp,
            source_ip,
            country,
            user_agent,
            latitude,
            longitude
        FROM auth_events
        WHERE username = %s
          AND attack_profile = 'baseline_generation'
          AND metadata->>'baseline' = 'true'
        ORDER BY timestamp ASC
        """,
        (username,)
    )

    events = cursor.fetchall()

    cursor.close()
    connection.close()

    if not events:
        print(f"[!] No events found for user: {username}")
        return

    login_hours = []
    source_ips = []
    countries = []
    user_agents = []

    last_timestamp = None
    last_latitude = None
    last_longitude = None

    for event in events:

        (
            timestamp,
            source_ip,
            country,
            user_agent,
            latitude,
            longitude
        ) = event

        if timestamp:

            login_hours.append(
                timestamp.hour
                + timestamp.minute / 60
            )

            last_timestamp = timestamp

        if source_ip:
            source_ips.append(str(source_ip))

        if country:
            countries.append(country)

        if user_agent:
            user_agents.append(user_agent)

        if latitude is not None:
            last_latitude = latitude

        if longitude is not None:
            last_longitude = longitude

    average_login_hour = (
        sum(login_hours) / len(login_hours)
        if login_hours
        else 12
    )

    login_hour_stddev = calculate_stddev(
        login_hours,
        average_login_hour
    )

    # --------------------------------------------------
    # Calculate daily login average
    # --------------------------------------------------

    daily_counts = Counter()

    for event in events:

        timestamp = event[0]

        if timestamp:
            date_key = timestamp.date().isoformat()
            daily_counts[date_key] += 1

    average_daily_logins = (
        sum(daily_counts.values())
        / len(daily_counts)
        if daily_counts
        else 0
    )

    # --------------------------------------------------
    # Most common contextual values
    # --------------------------------------------------

    common_source_ips = [
        value
        for value, count
        in Counter(source_ips).most_common(5)
    ]

    common_countries = [
        value
        for value, count
        in Counter(countries).most_common(5)
    ]

    common_user_agents = [
        value
        for value, count
        in Counter(user_agents).most_common(5)
    ]

    # --------------------------------------------------
    # Save baseline
    # --------------------------------------------------

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        INSERT INTO user_baselines (
            username,
            average_login_hour,
            login_hour_stddev,
            average_daily_logins,
            common_source_ips,
            common_countries,
            common_user_agents,
            last_login_timestamp,
            last_latitude,
            last_longitude,
            total_events,
            updated_at
        )
        VALUES (
            %s, %s, %s, %s, %s, %s, %s,
            %s, %s, %s, %s, CURRENT_TIMESTAMP
        )
        ON CONFLICT (username)
        DO UPDATE SET
            average_login_hour = EXCLUDED.average_login_hour,
            login_hour_stddev = EXCLUDED.login_hour_stddev,
            average_daily_logins = EXCLUDED.average_daily_logins,
            common_source_ips = EXCLUDED.common_source_ips,
            common_countries = EXCLUDED.common_countries,
            common_user_agents = EXCLUDED.common_user_agents,
            last_login_timestamp = EXCLUDED.last_login_timestamp,
            last_latitude = EXCLUDED.last_latitude,
            last_longitude = EXCLUDED.last_longitude,
            total_events = EXCLUDED.total_events,
            updated_at = CURRENT_TIMESTAMP
        """,
        (
            username,
            average_login_hour,
            login_hour_stddev,
            average_daily_logins,
            json.dumps(common_source_ips),
            json.dumps(common_countries),
            json.dumps(common_user_agents),
            last_timestamp,
            last_latitude,
            last_longitude,
            len(events)
        )
    )

    connection.commit()

    cursor.close()
    connection.close()

    print()
    print("=" * 60)
    print("USER BEHAVIORAL BASELINE")
    print("=" * 60)
    print(f"Username             : {username}")
    print(f"Events analyzed      : {len(events)}")
    print(f"Average login hour   : {average_login_hour:.2f}")
    print(f"Login hour stddev    : {login_hour_stddev:.2f}")
    print(f"Average daily logins : {average_daily_logins:.2f}")
    print(f"Common source IPs    : {common_source_ips}")
    print(f"Common countries     : {common_countries}")
    print(f"Common user agents   : {common_user_agents}")
    print("=" * 60)


def build_all_baselines():

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT username
        FROM users
        ORDER BY username
        """
    )

    users = [
        row[0]
        for row in cursor.fetchall()
    ]

    cursor.close()
    connection.close()

    for username in users:
        build_baseline(username)


if __name__ == "__main__":
    build_all_baselines()
