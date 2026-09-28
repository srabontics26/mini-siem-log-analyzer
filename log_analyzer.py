from collections import Counter
from datetime import datetime


LOG_FILE = "auth.log"


def analyze_log():
    print("=" * 60)
    print("              Mini SIEM - Log Analyzer")
    print("=" * 60)

    failed_logins = []
    successful_logins = []
    ip_addresses = []

    try:
        with open(LOG_FILE, "r") as file:
            for line in file:
                parts = line.strip().split()

                if not parts:
                    continue

                if "FAILED_LOGIN" in line:
                    failed_logins.append(line.strip())

                    for part in parts:
                        if part.startswith("IP="):
                            ip_addresses.append(part.split("=")[1])

                elif "SUCCESS_LOGIN" in line:
                    successful_logins.append(line.strip())

    except FileNotFoundError:
        print(f"\nError: {LOG_FILE} was not found.")
        return

    print(f"\nAnalysis time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    print("\nLogin Summary")
    print("-" * 60)
    print(f"Failed logins    : {len(failed_logins)}")
    print(f"Successful logins: {len(successful_logins)}")

    print("\nFailed Login Attempts")
    print("-" * 60)

    if failed_logins:
        for login in failed_logins:
            print(login)
    else:
        print("No failed login attempts found.")

    print("\nSuspicious IP Addresses")
    print("-" * 60)

    ip_counts = Counter(ip_addresses)

    suspicious_found = False

    for ip, count in ip_counts.items():
        if count >= 3:
            print(f"{ip:<18} {count} failed attempts")
            suspicious_found = True

    if not suspicious_found:
        print("No suspicious IP activity detected.")

    print("\nAnalysis completed.")


if __name__ == "__main__":
    analyze_log()
