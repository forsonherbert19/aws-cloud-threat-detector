# AWS Cloud Threat Detection System

A Python-based cloud security monitoring project that analyzes simulated AWS CloudTrail events, detects suspicious activity, and generates structured security alerts.

## Project Overview

This project simulates how a cloud security monitoring system can analyze AWS activity logs and identify potentially malicious behavior.

The detection engine currently identifies:

- CloudTrail deletion activity
- Failed AWS console login attempts
- Repeated failed logins from the same IP address
- Three failed login attempts occurring within a five-minute window

The project also generates a structured JSON security report for further investigation.

## Security Detection Rules

### AWS-001 — CloudTrail Deletion Activity

Detects the `DeleteTrail` API action.

CloudTrail provides important audit logging in AWS environments, so deletion activity should be investigated to determine whether it was authorized.

### AWS-002 — Repeated Failed Logins

Detects three failed AWS console login attempts from the same IP address within five minutes.

This may indicate password-guessing or brute-force activity and should be investigated.

## Technologies Used

- Python
- JSON
- Git
- AWS CloudTrail concepts
- Security log analysis
- Unit testing
- Detection engineering

## Project Architecture

Simulated AWS CloudTrail Logs  
↓  
Python Threat Detection Engine  
↓  
Detection Rules  
↓  
Structured Security Alerts  
↓  
security_alerts.json

## Features

- Parses AWS-style JSON security events
- Uses reusable Python detection functions
- Groups failed logins by source IP
- Performs time-window-based threat detection
- Assigns rule IDs and severity levels
- Generates structured JSON reports
- Includes automated unit tests
- Uses synthetic security data only

## Run the Detector

```bash
python threat_detector.py
