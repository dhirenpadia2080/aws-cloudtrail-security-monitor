# AWS CloudTrail Security Monitor V2

A Python-based defensive cloud security project that analyzes AWS CloudTrail JSON logs and detects selected suspicious or security-sensitive activities.

## Project Overview

AWS CloudTrail records API activity within an AWS account. This project uses Python to analyze CloudTrail-style JSON event logs and identify selected security events.

## Features

- Parses CloudTrail JSON event logs.
- Counts analyzed events.
- Detects selected security-sensitive AWS API actions.
- Identifies failed AWS Console login attempts.
- Displays security alerts in the terminal.
- Handles invalid JSON and file-access errors.

## Security Events Monitored

- CreateAccessKey
- DeleteAccessKey
- DeleteBucket
- PutBucketPolicy
- AttachUserPolicy
- AttachRolePolicy
- CreateLoginProfile
- AuthorizeSecurityGroupIngress
- StopLogging
- DeleteTrail
- UpdateTrail
- Failed ConsoleLogin attempts

## Technologies Used

- Python 3
- AWS CloudTrail
- JSON
- Kali Linux
- Git and GitHub

## Project Structure

```text
aws-cloudtrail-security-monitor/
├── analyzer.py
├── test_events.json
├── .gitignore
└── README.md
```

## How to Run

Clone the repository:

```bash
git clone https://github.com/dhirenpadia2080/aws-cloudtrail-security-monitor.git
```

Navigate to the project directory:

```bash
cd aws-cloudtrail-security-monitor
```

Run the analyzer:

```bash
python3 analyzer.py
```

## Testing

The project includes synthetic CloudTrail-style events in `test_events.json` for testing detection logic without using real production logs.

## Security Considerations

- Test data is synthetic.
- Never upload AWS access keys, credentials, or sensitive production logs.
- This educational tool does not replace AWS-native security monitoring services.

## Skills Demonstrated

- AWS CloudTrail monitoring
- Python scripting
- JSON parsing
- Defensive cloud security
- Security event detection
- Linux command-line operations
- Git version control

## Author

Dhiren Padia

GitHub: https://github.com/dhirenpadia2080
