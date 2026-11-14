# AWS Cloud Threat Detection System

![Python Security Tests](https://github.com/forsonherbert19/aws-cloud-threat-detector/actions/workflows/tests.yml/badge.svg)

A cloud security monitoring and detection project built with Python and AWS. The system analyzes AWS CloudTrail activity, detects suspicious events, runs detection logic in AWS Lambda, records findings in CloudWatch Logs, and sends high-severity security alerts through Amazon SNS.

## Project Overview

This project demonstrates a practical cloud threat-detection pipeline using AWS security services and Python.

It began as a local Python detection engine using simulated CloudTrail logs and was later extended into a live AWS event-driven architecture.

The project demonstrates:

- Cloud security monitoring
- AWS CloudTrail analysis
- Detection engineering
- Event-driven security automation
- Serverless security tooling
- Automated alerting
- Python unit testing
- CI/CD with GitHub Actions

## Architecture

```mermaid
flowchart TD
    A[AWS API Activity] --> B[AWS CloudTrail]
    B --> C[Amazon EventBridge]
    C --> D[AWS Lambda Threat Detector]
    D --> E[Detection Rules]
    E --> F[Amazon CloudWatch Logs]
    E --> G[Amazon SNS]
    G --> H[Email Security Alert]
