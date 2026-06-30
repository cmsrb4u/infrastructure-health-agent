"""Tools for the Infrastructure Health Check Agent.

Each tool performs read-only queries against AWS APIs and returns structured
summaries suitable for agent consumption.
"""

import os
from datetime import datetime, timedelta, timezone
from typing import Optional

import boto3
from strands import tool

REGION = os.environ.get("AWS_DEFAULT_REGION", "us-east-1")


@tool
def get_alarm_status(namespace: Optional[str] = None, state: Optional[str] = None) -> dict:
    """Get the current state of CloudWatch alarms.

    Args:
        namespace: Optional CloudWatch namespace to filter alarms (e.g., "AWS/EC2", "AWS/RDS").
                   If not provided, returns alarms across all namespaces.
        state: Optional alarm state filter. One of "OK", "ALARM", "INSUFFICIENT_DATA".

    Returns:
        A summary of CloudWatch alarms including counts by state and alarm details.
    """
    client = boto3.client("cloudwatch", region_name=REGION)

    kwargs = {}
    if state:
        kwargs["StateValue"] = state

    paginator = client.get_paginator("describe_alarms")
    alarms = []
    for page in paginator.paginate(**kwargs):
        for alarm in page["MetricAlarms"]:
            if namespace and alarm.get("Namespace") != namespace:
                continue
            alarms.append({
                "name": alarm["AlarmName"],
                "state": alarm["StateValue"],
                "namespace": alarm.get("Namespace", "N/A"),
                "metric": alarm.get("MetricName", "N/A"),
                "reason": alarm.get("StateReason", ""),
            })

    counts = {"OK": 0, "ALARM": 0, "INSUFFICIENT_DATA": 0}
    for a in alarms:
        counts[a["state"]] = counts.get(a["state"], 0) + 1

    return {
        "total_alarms": len(alarms),
        "counts_by_state": counts,
        "alarms": alarms[:50],
    }


@tool
def check_ec2_health(instance_ids: Optional[list[str]] = None) -> dict:
    """Check EC2 instance health including system and instance status checks.

    Args:
        instance_ids: Optional list of EC2 instance IDs to check.
                      If not provided, checks all running instances.

    Returns:
        A summary of instance health including status checks and instance details.
    """
    client = boto3.client("ec2", region_name=REGION)

    kwargs = {"Filters": [{"Name": "instance-state-name", "Values": ["running"]}]}
    if instance_ids:
        kwargs["InstanceIds"] = instance_ids

    instances = []
    paginator = client.get_paginator("describe_instance_status")
    for page in paginator.paginate(**kwargs):
        for status in page["InstanceStatuses"]:
            instances.append({
                "instance_id": status["InstanceId"],
                "availability_zone": status["AvailabilityZone"],
                "instance_state": status["InstanceState"]["Name"],
                "system_status": status["SystemStatus"]["Status"],
                "instance_status": status["InstanceStatus"]["Status"],
                "system_checks": [
                    {"name": d["Name"], "status": d["Status"]}
                    for d in status["SystemStatus"].get("Details", [])
                ],
                "instance_checks": [
                    {"name": d["Name"], "status": d["Status"]}
                    for d in status["InstanceStatus"].get("Details", [])
                ],
            })

    healthy = sum(1 for i in instances if i["system_status"] == "ok" and i["instance_status"] == "ok")

    return {
        "total_instances": len(instances),
        "healthy": healthy,
        "unhealthy": len(instances) - healthy,
        "instances": instances[:50],
    }


@tool
def get_recent_events(
    event_source: Optional[str] = None,
    lookback_hours: Optional[int] = None,
) -> dict:
    """Get recent CloudTrail management events.

    Args:
        event_source: Optional AWS service event source to filter by
                      (e.g., "ec2.amazonaws.com", "rds.amazonaws.com").
        lookback_hours: Number of hours to look back. Defaults to no limit.

    Returns:
        A summary of recent management events grouped by event source and name.
    """
    client = boto3.client("cloudtrail", region_name=REGION)

    kwargs = {"MaxResults": 50}

    lookup_attributes = []
    if event_source:
        lookup_attributes.append({"AttributeKey": "EventSource", "AttributeValue": event_source})
    if lookup_attributes:
        kwargs["LookupAttributes"] = lookup_attributes

    if lookback_hours:
        kwargs["StartTime"] = datetime.now(timezone.utc) - timedelta(hours=lookback_hours)

    response = client.lookup_events(**kwargs)

    events = []
    error_events = []
    for event in response.get("Events", []):
        entry = {
            "event_time": event["EventTime"].isoformat(),
            "event_source": event.get("EventSource", "unknown"),
            "event_name": event.get("EventName", "unknown"),
            "username": event.get("Username", "unknown"),
        }
        if "ErrorCode" in event.get("CloudTrailEvent", ""):
            entry["has_error"] = True
            error_events.append(entry)
        events.append(entry)

    return {
        "total_events": len(events),
        "error_events_count": len(error_events),
        "events": events,
        "error_events": error_events,
    }


@tool
def check_iam_health() -> dict:
    """Check IAM security health: expiring access keys, users without MFA, and unused roles.

    Returns:
        A summary of IAM health findings including security recommendations.
    """
    client = boto3.client("iam", region_name=REGION)

    findings = []

    users_response = client.list_users()
    users = users_response.get("Users", [])

    for user in users:
        username = user["UserName"]

        mfa_response = client.list_mfa_devices(UserName=username)
        if not mfa_response.get("MFADevices"):
            findings.append({
                "type": "NO_MFA",
                "severity": "HIGH",
                "resource": username,
                "detail": f"User '{username}' does not have MFA enabled",
            })

        keys_response = client.list_access_keys(UserName=username)
        for key in keys_response.get("AccessKeyMetadata", []):
            if key["Status"] == "Active":
                age_days = (datetime.now(timezone.utc) - key["CreateDate"]).days
                if age_days > 90:
                    findings.append({
                        "type": "OLD_ACCESS_KEY",
                        "severity": "MEDIUM",
                        "resource": f"{username}/{key['AccessKeyId']}",
                        "detail": f"Access key is {age_days} days old (threshold: 90 days)",
                    })

    return {
        "total_users": len(users),
        "total_findings": len(findings),
        "findings_by_severity": {
            "HIGH": sum(1 for f in findings if f["severity"] == "HIGH"),
            "MEDIUM": sum(1 for f in findings if f["severity"] == "MEDIUM"),
        },
        "findings": findings,
    }
