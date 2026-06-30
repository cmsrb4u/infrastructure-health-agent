# Infrastructure Health Check Agent

A read-only AWS infrastructure health analyzer, built as an A2A (Agent-to-Agent) agent for Amazon Bedrock AgentCore Runtime.

## Workshop

This repository is used in **"The Dev Side of the AWS DevOps Agent"** — a release-management workshop. See your workshop instructions for next steps.

## Local Development

```bash
uv sync
python main.py
```

## Deploy

```bash
npm install -g @aws/agentcore
agentcore deploy --yes
```
