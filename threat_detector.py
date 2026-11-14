# AWS Cloud Threat Detection System
# Project by Herbert Forson

import json
from pathlib import Path

# Find the JSON log file
log_file = Path(__file__).with_name("sample_cloudtrail_events.json")

# Read simulated AWS CloudTrail events
with open(log_file, "r", encoding="utf-8") as file:
    data = json.load(file)

events = data["Records"]

print("AWS Cloud Threat Detection System")
print("---------------------------------")

for event in events:
    event_name = event["eventName"]
    ip_address = event["sourceIPAddress"]

    if event_name == "DeleteTrail":
        print(f"[HIGH ALERT] CloudTrail deletion event from {ip_address}")

    elif (
        event_name == "ConsoleLogin"
        and event.get("responseElements", {}).get("ConsoleLogin") == "Failure"
    ):
        print(f"[WARNING] Failed AWS login from {ip_address}")

    else:
        print(f"[NORMAL] {event_name} from {ip_address}")

print("---------------------------------")
print(f"Total events analyzed: {len(events)}")

# Step 5B: Detect repeated failed logins

from collections import defaultdict
from datetime import datetime, timedelta

failed_logins = defaultdict(list)

# Collect timestamps of failed logins by IP
for event in events:
    if event.get("eventName") != "ConsoleLogin":
        continue

    response = event.get("responseElements") or {}

    if response.get("ConsoleLogin") != "Failure":
        continue

    ip = event.get("sourceIPAddress")
    time_string = event.get("eventTime")

    if not ip or not time_string:
        continue

    login_time = datetime.fromisoformat(
        time_string.replace("Z", "+00:00")
    )

    failed_logins[ip].append(login_time)

print("\nRepeated Failed Login Detection")
print("---------------------------------")

alert_found = False

# Check each IP for 3 failures within 5 minutes
for ip, timestamps in failed_logins.items():
    timestamps.sort()

    for i in range(len(timestamps) - 2):
        first = timestamps[i]
        third = timestamps[i + 2]

        if third - first <= timedelta(minutes=5):
            print(
                f"[HIGH ALERT] Possible brute-force activity: "
                f"3 failed logins from {ip} within 5 minutes"
            )
            alert_found = True
            break

if not alert_found:
    print("No repeated-login threat detected")


# Step 6: Generate a structured security report

from datetime import timezone

alerts = []

# Record CloudTrail deletion-related events
for event in events:
    if event.get("eventName") == "DeleteTrail":
        alerts.append({
            "rule_id": "AWS-001",
            "severity": "HIGH",
            "threat_type": "CloudTrailDeletionEvent",
            "source_ip": event.get("sourceIPAddress"),
            "event_time": event.get("eventTime"),
            "description": "CloudTrail deletion API activity detected. Investigate whether it succeeded."
        })

# Record repeated failed login findings
for ip, timestamps in failed_logins.items():
    times = sorted(timestamps)

    for i in range(len(times) - 2):
        if times[i + 2] - times[i] <= timedelta(minutes=5):
            alerts.append({
                "rule_id": "AWS-002",
                "severity": "HIGH",
                "threat_type": "RepeatedFailedLogins",
                "source_ip": ip,
                "first_seen": times[i].isoformat(),
                "last_seen": times[i + 2].isoformat(),
                "failed_attempts": 3,
                "description": "Possible password-guessing activity requiring investigation."
            })
            break

report = {
    "generated_at_utc": datetime.now(timezone.utc).isoformat(),
    "total_events_analyzed": len(events),
    "total_alerts": len(alerts),
    "alerts": alerts
}

report_file = Path(__file__).with_name("security_alerts.json")

report_file.write_text(
    json.dumps(report, indent=2) + "\n",
    encoding="utf-8"
)

print("\nSecurity Report Generated")
print("---------------------------------")
print(f"Events analyzed: {len(events)}")
print(f"Security findings: {len(alerts)}")
print(f"Report saved: {report_file.name}")
