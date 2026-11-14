import json
import os
import boto3

from threat_detector import detect_cloudtrail_deletion, is_failed_login


sns = boto3.client("sns")
SNS_TOPIC_ARN = os.environ.get("SNS_TOPIC_ARN")


def send_security_alert(alert):
    if not SNS_TOPIC_ARN:
        print("[ERROR] SNS_TOPIC_ARN is not configured")
        return

    message = (
        f"AWS Cloud Security Alert\n\n"
        f"Rule ID: {alert['rule_id']}\n"
        f"Severity: {alert['severity']}\n"
        f"Event: {alert['event']}\n"
        f"Event Name: {alert['event_name']}\n"
        f"Source IP: {alert['source_ip']}\n"
        f"Description: {alert['description']}"
    )

    response = sns.publish(
        TopicArn=SNS_TOPIC_ARN,
        Subject=f"[{alert['severity']}] AWS Cloud Threat Alert",
        Message=message,
    )

    print(f"SNS security alert sent: {response['MessageId']}")


def lambda_handler(event, context):
    print("Received AWS event:")
    print(json.dumps(event))

    cloudtrail_event = event.get("detail", event)

    event_name = cloudtrail_event.get("eventName", "Unknown")
    source_ip = cloudtrail_event.get("sourceIPAddress", "Unknown")

    alert = None

    if detect_cloudtrail_deletion(cloudtrail_event):
        alert = {
            "rule_id": "AWS-001",
            "severity": "HIGH",
            "event": "CloudTrailDeletionEvent",
            "event_name": event_name,
            "source_ip": source_ip,
            "description": (
                "CloudTrail deletion activity detected. "
                "Investigate whether the action was authorized."
            ),
        }

        print("[HIGH ALERT] CloudTrail deletion activity detected")
        send_security_alert(alert)

    elif is_failed_login(cloudtrail_event):
        alert = {
            "rule_id": "AWS-LOGIN",
            "severity": "WARNING",
            "event": "FailedConsoleLogin",
            "event_name": event_name,
            "source_ip": source_ip,
            "description": "Failed AWS console login detected.",
        }

        print("[WARNING] Failed AWS console login detected")

    else:
        print(f"[NORMAL] {event_name} from {source_ip}")

    return {
        "statusCode": 200,
        "alert": alert,
    }
