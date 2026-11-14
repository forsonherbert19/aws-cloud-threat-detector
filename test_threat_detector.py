import unittest
from collections import defaultdict
from datetime import datetime, timezone

from threat_detector import (
    is_failed_login,
    detect_cloudtrail_deletion,
    detect_repeated_failed_logins,
    generate_alerts,
)


class TestThreatDetector(unittest.TestCase):

    def test_failed_login_is_detected(self):
        event = {
            "eventName": "ConsoleLogin",
            "responseElements": {
                "ConsoleLogin": "Failure"
            }
        }

        self.assertTrue(is_failed_login(event))

    def test_successful_login_is_not_failed_login(self):
        event = {
            "eventName": "ConsoleLogin",
            "responseElements": {
                "ConsoleLogin": "Success"
            }
        }

        self.assertFalse(is_failed_login(event))

    def test_cloudtrail_deletion_is_detected(self):
        event = {
            "eventName": "DeleteTrail"
        }

        self.assertTrue(detect_cloudtrail_deletion(event))

    def test_repeated_failed_logins_trigger_alert(self):
        failed_logins = defaultdict(list)

        failed_logins["203.0.113.10"] = [
            datetime(2026, 11, 13, 10, 10, tzinfo=timezone.utc),
            datetime(2026, 11, 13, 10, 11, tzinfo=timezone.utc),
            datetime(2026, 11, 13, 10, 12, tzinfo=timezone.utc),
        ]

        findings = detect_repeated_failed_logins(failed_logins)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["rule_id"], "AWS-002")

    def test_repeated_logins_outside_window_do_not_alert(self):
        failed_logins = defaultdict(list)

        failed_logins["203.0.113.20"] = [
            datetime(2026, 11, 13, 10, 0, tzinfo=timezone.utc),
            datetime(2026, 11, 13, 10, 10, tzinfo=timezone.utc),
            datetime(2026, 11, 13, 10, 20, tzinfo=timezone.utc),
        ]

        findings = detect_repeated_failed_logins(failed_logins)

        self.assertEqual(len(findings), 0)

    def test_generate_alerts_returns_two_findings(self):
        events = [
            {
                "eventName": "DeleteTrail",
                "sourceIPAddress": "198.51.100.23",
                "eventTime": "2026-11-13T10:05:00Z"
            },
            {
                "eventName": "ConsoleLogin",
                "sourceIPAddress": "203.0.113.10",
                "eventTime": "2026-11-13T10:10:00Z",
                "responseElements": {
                    "ConsoleLogin": "Failure"
                }
            },
            {
                "eventName": "ConsoleLogin",
                "sourceIPAddress": "203.0.113.10",
                "eventTime": "2026-11-13T10:11:00Z",
                "responseElements": {
                    "ConsoleLogin": "Failure"
                }
            },
            {
                "eventName": "ConsoleLogin",
                "sourceIPAddress": "203.0.113.10",
                "eventTime": "2026-11-13T10:12:00Z",
                "responseElements": {
                    "ConsoleLogin": "Failure"
                }
            }
        ]

        alerts = generate_alerts(events)

        self.assertEqual(len(alerts), 2)

        rule_ids = {
            alert["rule_id"]
            for alert in alerts
        }

        self.assertIn("AWS-001", rule_ids)
        self.assertIn("AWS-002", rule_ids)


if __name__ == "__main__":
    unittest.main()
