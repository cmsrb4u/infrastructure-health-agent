# AGENTS.md — Infrastructure Health Check Agent

## Purpose

Read-only agent that reports on AWS infrastructure health. Deployed as an
A2A remote agent for AWS DevOps Agent on Amazon Bedrock AgentCore Runtime.

## Operational Boundaries

- This agent performs READ-ONLY operations only. It must never create, modify,
  terminate, or delete any AWS resource.
- All time-bounded queries (CloudTrail, CloudWatch) must default to a 2-hour
  lookback unless the caller specifies a different window.
- Never return raw CloudTrail event payloads — summarize by event source,
  event name, and error code.

## Security Requirements

- IAM permissions must follow least-privilege. Use wildcard Resource only for
  APIs that do not support resource-level permissions (e.g., ec2:DescribeInstances).
  All other actions must be scoped to specific ARN patterns.
- Trust policies must include `aws:SourceArn` or `aws:SourceAccount` conditions
  to prevent confused-deputy attacks.
- No credentials or secrets may be hardcoded in code, environment variables,
  or configuration files.
- Region must not be hardcoded — use the runtime-provided environment.

## Build and Test

- Install: `uv sync`
- Run locally: `python main.py`
- Unit tests: `uv run pytest test_tools.py -xvs`
- Lint: `uv run ruff check .`
- Deploy: `agentcore deploy`

## Accepted Exceptions

- `ec2:DescribeInstances` and `ec2:DescribeInstanceStatus` use `Resource: "*"`
  because the EC2 Describe APIs do not support resource-level permissions.
- `iam:ListUsers`, `iam:ListMFADevices`, and `iam:ListAccessKeys` use
  `Resource: "*"` because these List APIs do not support resource-level permissions.
