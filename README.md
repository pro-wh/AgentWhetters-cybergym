# CyberGym Purple Agent

A2A purple agent for the [CyberGym](https://github.com/sunblaze-ucb/cybergym) benchmark on [AgentBeats](https://agentbeats.dev). This agent receives vulnerability information from the green agent, analyzes it using an LLM, and generates proof-of-concept (PoC) exploits.

## How It Works

1. The green agent sends vulnerability files (source code, descriptions, error output, patches) as attachments
2. This purple agent analyzes the vulnerability using an LLM (OpenAI)
3. The agent iteratively generates and tests PoC exploits by sending `test_vulnerable` requests back to the green agent
4. Once a working PoC is found, it submits the final exploit as a file artifact

## Project Structure

```
src/
├─ server.py      # Server setup and agent card configuration
├─ executor.py    # A2A request handling
├─ agent.py       # Vulnerability analysis and PoC generation
└─ messenger.py   # A2A messaging utilities
tests/
├─ conftest.py    # Test fixtures
└─ test_agent.py  # Agent tests
Dockerfile
pyproject.toml
amber-manifest.json5
```

## Running Locally

```bash
# Install dependencies
uv sync

# Set your OpenAI API key
export OPENAI_API_KEY="your-key-here"

# Run the server
uv run src/server.py
```

## Running with Docker

```bash
docker build -t cybergym-purple .
docker run -p 9122:9122 -e OPENAI_API_KEY="your-key" cybergym-purple
```

## Testing

```bash
uv sync --extra test
uv run src/server.py &
uv run pytest --agent-url http://localhost:9122
```

## Configuration

| Variable | Description | Default |
|---|---|---|
| `OPENAI_API_KEY` | OpenAI API key | (required) |
| `OPENAI_MODEL` | Model to use | `gpt-4o-mini` |
| `OPENAI_BASE_URL` | Custom API base URL | (none) |
| `AZURE_OPENAI_ENDPOINT` | Azure OpenAI endpoint | (none) |
| `AZURE_OPENAI_API_VERSION` | Azure API version | `2024-10-21` |
| `AZURE_OPENAI_DEPLOYMENT` | Azure deployment name | (none) |
| `LOG_LEVEL` | Logging level | `INFO` |



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