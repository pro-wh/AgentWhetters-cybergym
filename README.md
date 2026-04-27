---
title: AgentWhetters CyberGym
description: Setup and run guide for the CyberGym purple agent and evaluation scenarios
ms.date: 2026-04-27
---

## Prerequisites

* [uv](https://docs.astral.sh/uv/) — Python package manager and runner
* An OpenAI API key (or Azure OpenAI credentials)
* A HuggingFace token (for downloading vulnerability datasets)

## Quick Start

### 1. Install uv

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```

Verify the installation:

```bash
uv --version
```

### 2. Configure the Environment

Copy the example environment file and fill in your credentials:

```bash
cd cybergym-purple
cp .env.example .env
```

Open `.env` in your editor and set at minimum:

```dotenv
OPENAI_API_KEY=sk-your-actual-api-key
```

The full set of available variables:

| Variable | Required | Description |
|---|---|---|
| `OPENAI_API_KEY` | Yes | Your OpenAI API key |
| `HF_TOKEN` | Recommended | HuggingFace token for dataset downloads |
| `OPENAI_MODEL` | No | Model to use (default: `gpt-4o-mini`) |
| `OPENAI_BASE_URL` | No | Custom base URL for OpenAI-compatible APIs |
| `AZURE_OPENAI_ENDPOINT` | No | Azure OpenAI endpoint URL |
| `AZURE_OPENAI_API_VERSION` | No | Azure API version (default: `2024-10-21`) |
| `AZURE_OPENAI_DEPLOYMENT` | No | Azure deployment name |
| `LOG_LEVEL` | No | Logging level (default: `INFO`) |

### 3. Install Dependencies

```bash
cd cybergym-purple
uv sync
```

### 4. Run a Scenario

Source the environment and launch the auto-start scenario:

```bash
cd cybergym-purple
source .env
mkdir -p tempo
AGENT_DEBUG=1 uv run python -m agentbeats.run_scenario scenario-auto.toml --show-logs 2>&1 | tee tempo/$(date +%Y%m%d_%H%M%S).log
```

This auto-starts both the green agent (port 9109) and the purple agent (port 9122),
runs the evaluation, and saves the log to the `tempo/` folder.

## Available Scenarios

| File | Description |
|---|---|
| `scenario-auto.toml` | Auto-starts both agents, single arvo task at level 1 |
| `scenario.toml` | Manual-start — you launch agents yourself |
| `scenario-multi.toml` | Multiple tasks (arvo + oss-fuzz), 2 workers |
| `scenario-level3.toml` | Level 3 with full file context |

## Project Layout

```text
cybergym/
├── cybergym-green/    # Green agent — orchestrates evaluation and scoring
├── cybergym-purple/   # Purple agent — analyzes vulnerabilities, generates PoCs
│   ├── src/           # Agent source code
│   ├── agentbeats/    # Scenario orchestration package
│   ├── tests/         # A2A conformance tests
│   ├── .env.example   # Environment template
│   └── scenario-*.toml
└── README.md          # This file
```
```