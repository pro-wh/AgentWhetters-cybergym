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
