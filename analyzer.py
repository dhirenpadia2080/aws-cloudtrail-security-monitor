import json
from pathlib import Path

print("=" * 55)
print("       AWS CLOUDTRAIL SECURITY MONITOR V2")
print("=" * 55)

log_files = sorted(
    f for f in Path(".").glob("*.json")
    if "CloudTrail-Digest" not in f.name
)

if not log_files:
    print("No CloudTrail JSON log files found.")
    raise SystemExit

total_events = 0
total_alerts = 0

# Events that deserve security investigation
security_rules = {
    "CreateAccessKey": "IAM access key created",
    "DeleteAccessKey": "IAM access key deleted",
    "DeleteBucket": "S3 bucket deleted",
    "PutBucketPolicy": "S3 bucket policy changed",
    "DeleteBucketPolicy": "S3 bucket policy deleted",
    "AttachUserPolicy": "IAM policy attached to user",
    "AttachRolePolicy": "IAM policy attached to role",
    "PutUserPolicy": "IAM user permissions changed",
    "PutRolePolicy": "IAM role permissions changed",
    "CreateLoginProfile": "IAM console password created",
    "AuthorizeSecurityGroupIngress": "Security group inbound access changed",
    "RevokeSecurityGroupIngress": "Security group inbound rule removed",
    "StopLogging": "CloudTrail logging stopped",
    "DeleteTrail": "CloudTrail trail deleted",
    "UpdateTrail": "CloudTrail trail configuration changed",
}

for filename in log_files:
    print(f"\nAnalyzing: {filename.name}")

    try:
        with filename.open("r", encoding="utf-8") as file:
            data = json.load(file)

        events = data.get("Records", [])

        if not isinstance(events, list):
            print("Unexpected log format. Skipping.")
            continue

        print("Events found:", len(events))

        for event in events:
            total_events += 1

            event_name = event.get("eventName", "Unknown")
            event_source = event.get("eventSource", "Unknown")

            identity = event.get("userIdentity") or {}
            username = identity.get(
                "userName",
                identity.get("arn", "Unknown")
            )

            if event_name in security_rules:
                total_alerts += 1

                print("\n[SECURITY ALERT]")
                print("Threat:", security_rules[event_name])
                print("Event:", event_name)
                print("Service:", event_source)
                print("User:", username)
                print("Time:", event.get("eventTime", "Unknown"))
                print("Source IP:", event.get("sourceIPAddress", "Unknown"))

            elif event_name == "ConsoleLogin":
                response = event.get("responseElements") or {}

                if response.get("ConsoleLogin") == "Failure":
                    total_alerts += 1
                    print("\n[SECURITY ALERT]")
                    print("Threat: Failed console login")
                    print("User:", username)
                    print("Source IP:", event.get("sourceIPAddress", "Unknown"))

    except json.JSONDecodeError:
        print("ERROR: Invalid JSON file.")

    except OSError as error:
        print("ERROR reading file:", error)

print("\n" + "=" * 55)
print("                 SCAN SUMMARY")
print("=" * 55)
print("Total events analyzed:", total_events)
print("Security alerts found:", total_alerts)
print("Analysis complete.")
