"""Entry point for the Infrastructure Health Check Agent.

Starts an A2A-compatible server on port 9000 for deployment to
Amazon Bedrock AgentCore Runtime.
"""

from strands import Agent, tool
from strands.multiagent.a2a.executor import StrandsA2AExecutor

from bedrock_agentcore.runtime import serve_a2a
from model.load import load_model
from tools import check_ec2_health, check_iam_health, get_alarm_status, get_recent_events

SYSTEM_PROMPT = """\
You are an Infrastructure Health Check Agent. Your role is to analyze AWS \
infrastructure health and provide clear, actionable summaries.

You have access to tools that query AWS CloudWatch alarms, EC2 instance health, \
CloudTrail events, and IAM security posture. Use them to answer questions about \
the current state of the AWS account.

Guidelines:
- Always report the time window you queried.
- Summarize findings by severity (critical issues first).
- When reporting alarms, group by namespace.
- For IAM findings, clearly distinguish HIGH from MEDIUM severity.
- If a query returns no results, state that explicitly rather than speculating.
- Never recommend modifying, deleting, or stopping resources — your role is observation only.
"""

agent = Agent(
    model=load_model(),
    system_prompt=SYSTEM_PROMPT,
    tools=[get_alarm_status, check_ec2_health, get_recent_events, check_iam_health],
)

if __name__ == "__main__":
    serve_a2a(StrandsA2AExecutor(agent))
