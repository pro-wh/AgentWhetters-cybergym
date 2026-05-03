import argparse
import logging
import os

import uvicorn
from dotenv import load_dotenv

from log_config import configure as configure_logging

from a2a.server.apps import A2AStarletteApplication
from a2a.server.request_handlers import DefaultRequestHandler
from a2a.server.tasks import InMemoryTaskStore
from a2a.types import (
    AgentCapabilities,
    AgentCard,
    AgentSkill,
)

from executor import Executor

logger = logging.getLogger(__name__)


def main():
    load_dotenv()  # Load .env file before anything reads env vars

    parser = argparse.ArgumentParser(description="Run the CyberGym purple agent.")
    parser.add_argument("--host", type=str, default="127.0.0.1", help="Host to bind the server")
    parser.add_argument("--port", type=int, default=9122, help="Port to bind the server")
    parser.add_argument("--card-url", type=str, help="URL to advertise in the agent card")
    args = parser.parse_args()

    configure_logging(os.getenv("LOG_LEVEL", "INFO"))

    skill = AgentSkill(
        id="cybergym_exploit",
        name="CyberGym Exploit Generator",
        description="Analyzes software vulnerabilities and generates proof-of-concept exploits.",
        tags=["cybersecurity", "vulnerability", "exploit", "poc", "ctf"],
        examples=[],
    )

    agent_card = AgentCard(
        name="CyberGym Purple",
        description="Purple agent for the CyberGym benchmark — analyzes vulnerabilities and generates PoC exploits.",
        url=args.card_url or f"http://{args.host}:{args.port}/",
        version="1.0.0",
        default_input_modes=["text"],
        default_output_modes=["text"],
        capabilities=AgentCapabilities(streaming=True),
        skills=[skill],
    )

    request_handler = DefaultRequestHandler(
        agent_executor=Executor(),
        task_store=InMemoryTaskStore(),
    )
    server = A2AStarletteApplication(
        agent_card=agent_card,
        http_handler=request_handler,
        max_content_length=None,
    )

    logger.info("Starting CyberGym Purple Agent on %s:%s", args.host, args.port)
    uvicorn.run(server.build(), host=args.host, port=args.port, timeout_keep_alive=600)


if __name__ == "__main__":
    main()
