def calculate_risk(
    failed_attempts=0,
    multiple_accounts=False,
    high_request_rate=False,
    successful_after_failures=False,
    account_locked=False
):
    score = 0

    # 5+ failed attempts
    if failed_attempts >= 5:
        score += 20

    # 10+ failed attempts
    if failed_attempts >= 10:
        score += 30

    # Multiple accounts targeted
    if multiple_accounts:
        score += 25

    # High request rate
    if high_request_rate:
        score += 20

    # Successful login after repeated failures
    if successful_after_failures:
        score += 40

    # Account locked
    if account_locked:
        score += 20

    # Maximum score = 100
    score = min(score, 100)

    if score >= 70:
        severity = "CRITICAL"
    elif score >= 50:
        severity = "HIGH"
    elif score >= 25:
        severity = "MEDIUM"
    else:
        severity = "LOW"

    return score, severity


def display_risk(score, severity):

    print()
    print("=" * 50)
    print("              RISK ASSESSMENT")
    print("=" * 50)
    print(f"Risk Score : {score}/100")
    print(f"Severity   : {severity}")
    print("=" * 50)


if __name__ == "__main__":

    # Test example
    score, severity = calculate_risk(
        failed_attempts=10,
        multiple_accounts=True,
        high_request_rate=True
    )

    display_risk(score, severity)
