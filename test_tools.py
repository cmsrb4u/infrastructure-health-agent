"""Unit tests for the Infrastructure Health Check Agent tools."""

import os
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

os.environ["AWS_DEFAULT_REGION"] = "us-east-1"

from health_agent.tools import check_ec2_health, check_iam_health, get_alarm_status, get_recent_events


class TestGetAlarmStatus:
    @patch("health_agent.tools.boto3.client")
    def test_returns_alarm_summary(self, mock_boto_client):
        mock_cw = MagicMock()
        mock_boto_client.return_value = mock_cw

        mock_paginator = MagicMock()
        mock_cw.get_paginator.return_value = mock_paginator
        mock_paginator.paginate.return_value = [
            {
                "MetricAlarms": [
                    {
                        "AlarmName": "HighCPU",
                        "StateValue": "ALARM",
                        "Namespace": "AWS/EC2",
                        "MetricName": "CPUUtilization",
                        "StateReason": "Threshold crossed",
                    },
                    {
                        "AlarmName": "LowMem",
                        "StateValue": "OK",
                        "Namespace": "AWS/EC2",
                        "MetricName": "MemoryUtilization",
                        "StateReason": "",
                    },
                ]
            }
        ]

        result = get_alarm_status._tool_func()

        assert result["total_alarms"] == 2
        assert result["counts_by_state"]["ALARM"] == 1
        assert result["counts_by_state"]["OK"] == 1

    @patch("health_agent.tools.boto3.client")
    def test_filters_by_namespace(self, mock_boto_client):
        mock_cw = MagicMock()
        mock_boto_client.return_value = mock_cw

        mock_paginator = MagicMock()
        mock_cw.get_paginator.return_value = mock_paginator
        mock_paginator.paginate.return_value = [
            {
                "MetricAlarms": [
                    {
                        "AlarmName": "HighCPU",
                        "StateValue": "ALARM",
                        "Namespace": "AWS/EC2",
                        "MetricName": "CPUUtilization",
                        "StateReason": "",
                    },
                    {
                        "AlarmName": "RDSConnections",
                        "StateValue": "OK",
                        "Namespace": "AWS/RDS",
                        "MetricName": "DatabaseConnections",
                        "StateReason": "",
                    },
                ]
            }
        ]

        result = get_alarm_status._tool_func(namespace="AWS/EC2")

        assert result["total_alarms"] == 1
        assert result["alarms"][0]["name"] == "HighCPU"


class TestCheckEc2Health:
    @patch("health_agent.tools.boto3.client")
    def test_returns_instance_health(self, mock_boto_client):
        mock_ec2 = MagicMock()
        mock_boto_client.return_value = mock_ec2

        mock_paginator = MagicMock()
        mock_ec2.get_paginator.return_value = mock_paginator
        mock_paginator.paginate.return_value = [
            {
                "InstanceStatuses": [
                    {
                        "InstanceId": "i-1234567890abcdef0",
                        "AvailabilityZone": "us-east-1a",
                        "InstanceState": {"Name": "running"},
                        "SystemStatus": {"Status": "ok", "Details": []},
                        "InstanceStatus": {"Status": "ok", "Details": []},
                    }
                ]
            }
        ]

        result = check_ec2_health._tool_func()

        assert result["total_instances"] == 1
        assert result["healthy"] == 1
        assert result["unhealthy"] == 0


class TestGetRecentEvents:
    @patch("health_agent.tools.boto3.client")
    def test_returns_events(self, mock_boto_client):
        mock_ct = MagicMock()
        mock_boto_client.return_value = mock_ct
        mock_ct.lookup_events.return_value = {
            "Events": [
                {
                    "EventTime": datetime(2026, 1, 1, tzinfo=timezone.utc),
                    "EventSource": "ec2.amazonaws.com",
                    "EventName": "RunInstances",
                    "Username": "admin",
                    "CloudTrailEvent": "{}",
                }
            ]
        }

        result = get_recent_events._tool_func(lookback_hours=2)

        assert result["total_events"] == 1
        assert result["events"][0]["event_source"] == "ec2.amazonaws.com"

    @patch("health_agent.tools.boto3.client")
    def test_no_lookback_sends_unbounded_query(self, mock_boto_client):
        """DEFECT #3: When lookback_hours is not provided, no StartTime is set."""
        mock_ct = MagicMock()
        mock_boto_client.return_value = mock_ct
        mock_ct.lookup_events.return_value = {"Events": []}

        get_recent_events._tool_func()

        call_kwargs = mock_ct.lookup_events.call_args[1]
        assert "StartTime" not in call_kwargs


class TestCheckIamHealth:
    @patch("health_agent.tools.boto3.client")
    def test_detects_missing_mfa(self, mock_boto_client):
        mock_iam = MagicMock()
        mock_boto_client.return_value = mock_iam

        mock_iam.list_users.return_value = {
            "Users": [{"UserName": "alice"}]
        }
        mock_iam.list_mfa_devices.return_value = {"MFADevices": []}
        mock_iam.list_access_keys.return_value = {"AccessKeyMetadata": []}

        result = check_iam_health._tool_func()

        assert result["total_findings"] == 1
        assert result["findings"][0]["type"] == "NO_MFA"
        assert result["findings"][0]["severity"] == "HIGH"

    @patch("health_agent.tools.boto3.client")
    def test_detects_old_access_keys(self, mock_boto_client):
        mock_iam = MagicMock()
        mock_boto_client.return_value = mock_iam

        mock_iam.list_users.return_value = {
            "Users": [{"UserName": "bob"}]
        }
        mock_iam.list_mfa_devices.return_value = {
            "MFADevices": [{"SerialNumber": "arn:aws:iam::123:mfa/bob"}]
        }
        mock_iam.list_access_keys.return_value = {
            "AccessKeyMetadata": [
                {
                    "AccessKeyId": "FAKEKEYID0123456789AB",
                    "Status": "Active",
                    "CreateDate": datetime(2025, 1, 1, tzinfo=timezone.utc),
                }
            ]
        }

        result = check_iam_health._tool_func()

        assert result["total_findings"] == 1
        assert result["findings"][0]["type"] == "OLD_ACCESS_KEY"
