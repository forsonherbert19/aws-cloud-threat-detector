import json
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path


def load_events(file_path):
    with open(file_path, "r", encoding="utf-8") as file:
        data = json.load(file)

    return data["Records"]


def is_failed_login(event):
    return (
        event.get("eventName") == "ConsoleLogin"
        and (event.get("responseElements") or {}).get("ConsoleLogin") == "Failure"
    )


def detect_cloudtrail_deletion(event):
    return event.get("eventName") == "DeleteTrail"


def collect_failed_logins(events):
    failed_logins = defaultdict(list)

    for event in events:
        if not is_failed_login(event):
            continue

        ip_address = event.get("sourceIPAddress")
        event_time = event.get("eventTime")

        if not ip_address or not event_time:
            continue

        timestamp = datetime.fromisoformat(
            event_time.replace("Z", "+00:00")
        )

        failed_logins[ip_address].append(timestamp)

    return failed_logins


def detect_repeated_failed_logins(
    failed_logins,
    threshold=3,
    window_minutes=5
):
    findings = []

    for ip_address, timestamps in failed_logins.items():
        timestamps = sorted(timestamps)

        for index in range(len(timestamps) - threshold + 1):
            first = timestamps[index]
            last = timestamps[index + threshold - 1]

            if last - first <= timedelta(minutes=window_minutes):
                findings.append({
                    "rule_id": "AWS-002",
                    "severity": "HIGH",
                    "threat_type": "RepeatedFailedLogins",
                    "source_ip": ip_address,
                    "first_seen": first.isoformat(),
                    "last_seen": last.isoformat(),
                    "failed_attempts": threshold,
                    "description": (
                        "Possible password-guessing activity "
                        "requiring investigation."
                    )
                })
                break

    return findings


def generate_alerts(events):
    alerts = []

    for event in events:
        if detect_cloudtrail_deletion(event):
            alerts.append({
                "rule_id": "AWS-001",
                "severity": "HIGH",
                "threat_type": "CloudTrailDeletionEvent",
                "source_ip": event.get("sourceIPAddress"),
                "event_time": event.get("eventTime"),
                "description": (
                    "CloudTrail deletion API activity detected. "
                    "Investigate whether it succeeded."
                )
            })

    failed_logins = collect_failed_logins(events)
    alerts.extend(
        detect_repeated_failed_logins(failed_logins)
    )

    return alerts


def save_report(events, alerts, report_file):
    report = {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "total_events_analyzed": len(events),
        "total_alerts": len(alerts),
        "alerts": alerts
    }

    report_file.write_text(
        json.dumps(report, indent=2) + "\n",
        encoding="utf-8"
    )


def main():
    project_directory = Path(__file__).parent

    log_file = project_directory / "sample_cloudtrail_events.json"
    report_file = project_directory / "security_alerts.json"

    events = load_events(log_file)

    print("AWS Cloud Threat Detection System")
    print("---------------------------------")

    for event in events:
        event_name = event.get("eventName", "Unknown")
        ip_address = event.get("sourceIPAddress", "Unknown")

        if detect_cloudtrail_deletion(event):
            print(
                f"[HIGH ALERT] CloudTrail deletion event "
                f"from {ip_address}"
            )

        elif is_failed_login(event):
            print(
                f"[WARNING] Failed AWS login "
                f"from {ip_address}"
            )

        else:
            print(
                f"[NORMAL] {event_name} "
                f"from {ip_address}"
            )

    alerts = generate_alerts(events)

    print("---------------------------------")
    print(f"Total events analyzed: {len(events)}")

    print("\nSecurity Findings")
    print("---------------------------------")

    for alert in alerts:
        print(
            f"[{alert['severity']}] "
            f"{alert['rule_id']} - "
            f"{alert['threat_type']}"
        )

    save_report(events, alerts, report_file)

    print("\nSecurity Report Generated")
    print("---------------------------------")
    print(f"Security findings: {len(alerts)}")
    print(f"Report saved: {report_file.name}")


if __name__ == "__main__":
    main()
