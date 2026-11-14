# AWS Cloud Threat Detection System

A Python-based cybersecurity project that analyzes simulated AWS CloudTrail events and detects suspicious cloud activity.

## Features

- Reads AWS-style CloudTrail logs from JSON
- Detects CloudTrail deletion activity
- Identifies failed AWS console login attempts
- Detects three failed logins from the same IP within five minutes
- Generates structured JSON security findings
- Includes automated unit tests

## Technologies

- Python
- JSON
- AWS CloudTrail concepts
- Security log analysis
- Git

## Detection Rules

### AWS-001: CloudTrail Deletion Activity

Flags CloudTrail DeleteTrail API activity for investigation.

### AWS-002: Repeated Failed Logins

Flags three failed AWS console logins
