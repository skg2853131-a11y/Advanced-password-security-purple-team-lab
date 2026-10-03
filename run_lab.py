import subprocess
import os
from datetime import datetime


def run_command(command):
    print()
    print("=" * 70)
    print(f"RUNNING: {command}")
    print("=" * 70)

    result = subprocess.run(
        command,
        shell=True
    )

    return result.returncode


def main():

    print("=" * 70)
    print("       ADVANCED PASSWORD SECURITY & ATTACK DETECTION LAB")
    print("=" * 70)

    print()
    print(f"[*] Started: {datetime.now()}")

    # --------------------------------------------------
    # STAGE 14 - Detection
    # --------------------------------------------------

    print()
    print("[1] Running detection engine...")

    detection_result = run_command(
        "python3 detection/detector.py"
    )

    # --------------------------------------------------
    # STAGE 17 - Automated response
    # --------------------------------------------------

    print()
    print("[2] Running defensive response engine...")

    response_result = run_command(
        "python3 response/response.py"
    )

    # --------------------------------------------------
    # STAGE 18 - Dashboard
    # --------------------------------------------------

    print()
    print("[3] Generating security dashboard...")

    dashboard_result = run_command(
        "python3 dashboard/dashboard.py"
    )

    # --------------------------------------------------
    # STAGE 19 - Statistics
    # --------------------------------------------------

    print()
    print("[4] Generating attack statistics...")

    statistics_result = run_command(
        "python3 dashboard/statistics.py"
    )

    # --------------------------------------------------
    # Final status
    # --------------------------------------------------

    print()
    print("=" * 70)
    print("                    LAB SUMMARY")
    print("=" * 70)

    print(
        f"Detection Engine : "
        f"{'SUCCESS' if detection_result == 0 else 'FAILED'}"
    )

    print(
        f"Response Engine  : "
        f"{'SUCCESS' if response_result == 0 else 'FAILED'}"
    )

    print(
        f"Dashboard        : "
        f"{'SUCCESS' if dashboard_result == 0 else 'FAILED'}"
    )

    print(
        f"Statistics       : "
        f"{'SUCCESS' if statistics_result == 0 else 'FAILED'}"
    )

    print()
    print(f"[*] Completed: {datetime.now()}")

    print("=" * 70)


if __name__ == "__main__":
    main()
