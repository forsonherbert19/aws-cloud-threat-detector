import unittest
from datetime import datetime, timedelta, timezone


def detect_repeated_failed_logins(timestamps):
    timestamps = sorted(timestamps)

    for i in range(len(timestamps) - 2):
        if timestamps[i + 2] - timestamps[i] <= timedelta(minutes=5):
            return True

    return False


class TestThreatDetector(unittest.TestCase):

    def test_three_failed_logins_within_five_minutes(self):
        timestamps = [
            datetime(2026, 11, 13, 10, 10, tzinfo=timezone.utc),
            datetime(2026, 11, 13, 10, 11, tzinfo=timezone.utc),
            datetime(2026, 11, 13, 10, 12, tzinfo=timezone.utc),
        ]

        self.assertTrue(
            detect_repeated_failed_logins(timestamps)
        )

    def test_failed_logins_outside_five_minutes(self):
        timestamps = [
            datetime(2026, 11, 13, 10, 10, tzinfo=timezone.utc),
            datetime(2026, 11, 13, 10, 15, tzinfo=timezone.utc),
            datetime(2026, 11, 13, 10, 20, tzinfo=timezone.utc),
        ]

        self.assertFalse(
            detect_repeated_failed_logins(timestamps)
        )

    def test_less_than_three_failed_logins(self):
        timestamps = [
            datetime(2026, 11, 13, 10, 10, tzinfo=timezone.utc),
            datetime(2026, 11, 13, 10, 11, tzinfo=timezone.utc),
        ]

        self.assertFalse(
            detect_repeated_failed_logins(timestamps)
        )


if __name__ == "__main__":
    unittest.main()
