import base64
from typing import Any
import pytest
import httpx
from uuid import uuid4

from a2a.client import A2ACardResolver, ClientConfig, ClientFactory
from a2a.types import FilePart, FileWithBytes, Message, Part, Role, TextPart

from src.agent import _build_hypothesis_input, _build_poc_format_guidance
from src.hypothesis_parser import parse_hypothesis


def validate_agent_card(card_data: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    required_fields = frozenset([
        "name", "description", "url", "version",
        "capabilities", "defaultInputModes", "defaultOutputModes", "skills",
    ])
    for field in required_fields:
        if field not in card_data:
            errors.append(f"Required field is missing: '{field}'.")

    if "url" in card_data and not (
        card_data["url"].startswith("http://") or card_data["url"].startswith("https://")
    ):
        errors.append("Field 'url' must be an absolute URL starting with http:// or https://.")

    if "capabilities" in card_data and not isinstance(card_data["capabilities"], dict):
        errors.append("Field 'capabilities' must be an object.")

    for field in ["defaultInputModes", "defaultOutputModes"]:
        if field in card_data:
            if not isinstance(card_data[field], list):
                errors.append(f"Field '{field}' must be an array of strings.")
            elif not all(isinstance(item, str) for item in card_data[field]):
                errors.append(f"All items in '{field}' must be strings.")

    if "skills" in card_data:
        if not isinstance(card_data["skills"], list):
            errors.append("Field 'skills' must be an array of AgentSkill objects.")
        elif not card_data["skills"]:
            errors.append("Field 'skills' array is empty.")

    return errors


def validate_event(data: dict[str, Any]) -> list[str]:
    if "kind" not in data:
        return ["Response from agent is missing required 'kind' field."]
    kind = data.get("kind")
    if kind == "task":
        errors = []
        if "id" not in data:
            errors.append("Task object missing required field: 'id'.")
        if "status" not in data or "state" not in data.get("status", {}):
            errors.append("Task object missing required field: 'status.state'.")
        return errors
    elif kind == "status-update":
        if "status" not in data or "state" not in data.get("status", {}):
            return ["StatusUpdate object missing required field: 'status.state'."]
        return []
    elif kind == "artifact-update":
        if "artifact" not in data:
            return ["ArtifactUpdate object missing required field: 'artifact'."]
        artifact = data.get("artifact", {})
        if "parts" not in artifact or not isinstance(artifact.get("parts"), list) or not artifact.get("parts"):
            return ["Artifact object must have a non-empty 'parts' array."]
        return []
    elif kind == "message":
        errors = []
        if "parts" not in data or not isinstance(data.get("parts"), list) or not data.get("parts"):
            errors.append("Message object must have a non-empty 'parts' array.")
        if "role" not in data or data.get("role") != "agent":
            errors.append("Message from agent must have 'role' set to 'agent'.")
        return errors
    return [f"Unknown message kind received: '{kind}'."]


async def send_text_message(text: str, url: str, context_id: str | None = None, streaming: bool = False):
    async with httpx.AsyncClient(timeout=10) as httpx_client:
        resolver = A2ACardResolver(httpx_client=httpx_client, base_url=url)
        agent_card = await resolver.get_agent_card()
        config = ClientConfig(httpx_client=httpx_client, streaming=streaming)
        factory = ClientFactory(config)
        client = factory.create(agent_card)

        msg = Message(
            kind="message",
            role=Role.user,
            parts=[Part(TextPart(text=text))],
            message_id=uuid4().hex,
            context_id=context_id,
        )

        events = [event async for event in client.send_message(msg)]
    return events


def test_agent_card(agent):
    """Validate agent card structure and required fields."""
    response = httpx.get(f"{agent}/.well-known/agent-card.json")
    assert response.status_code == 200, "Agent card endpoint must return 200"

    card_data = response.json()
    assert card_data["name"] == "CyberGym Purple"
    errors = validate_agent_card(card_data)
    assert not errors, f"Agent card validation failed:\n" + "\n".join(errors)


@pytest.mark.asyncio
@pytest.mark.parametrize("streaming", [True, False])
async def test_message(agent, streaming):
    """Test that agent returns valid A2A message format."""
    events = await send_text_message("Hello", agent, streaming=streaming)

    all_errors = []
    for event in events:
        match event:
            case Message() as msg:
                errors = validate_event(msg.model_dump())
                all_errors.extend(errors)
            case (task, update):
                errors = validate_event(task.model_dump())
                all_errors.extend(errors)
                if update:
                    errors = validate_event(update.model_dump())
                    all_errors.extend(errors)
            case _:
                pytest.fail(f"Unexpected event type: {type(event)}")

    assert events, "Agent should respond with at least one event"
    assert not all_errors, f"Message validation failed:\n" + "\n".join(all_errors)


def test_hypothesis_input_includes_error_txt_attachment():
    message = Message(
        kind="message",
        role=Role.user,
        parts=[
            Part(TextPart(text="generic task header")),
            Part(
                root=FilePart(
                    file=FileWithBytes(
                        bytes=base64.b64encode(
                            b"High-level description without the crash function"
                        ).decode("ascii"),
                        name="description.txt",
                        mime_type="text/plain",
                    )
                )
            ),
            Part(
                root=FilePart(
                    file=FileWithBytes(
                        bytes=base64.b64encode(
                            b"ERROR: AddressSanitizer: heap-buffer-overflow\n"
                            b"#0 0x555a in ReadMNGImage coders/mng.c:387\n"
                        ).decode("ascii"),
                        name="error.txt",
                        mime_type="text/plain",
                    )
                )
            ),
        ],
        message_id=uuid4().hex,
    )

    parser_input = _build_hypothesis_input(
        message,
        {
            "description.txt": b"High-level description without the crash function",
            "error.txt": (
                b"ERROR: AddressSanitizer: heap-buffer-overflow\n"
                b"#0 0x555a in ReadMNGImage coders/mng.c:387\n"
            ),
        },
    )

    signal = parse_hypothesis(parser_input)

    assert "error.txt" not in parser_input
    assert signal.vuln_class == "heap-buffer-overflow"
    assert signal.vulnerable_function == "ReadMNGImage"


def test_poc_format_guidance_includes_binary_and_magic_hints():
    signal = parse_hypothesis(
        "heap-buffer-overflow in ReadMNGImage at coders/mng.c:387"
    )

    guidance = _build_poc_format_guidance(
        signal,
        {
            "magic_bytes": "PNG: png.c: check for 0x89 0x50 0x4e 0x47",
            "trigger_field": "chunk length",
            "source": {"function": "LLVMFuzzerTestOneInput", "file": "fuzz/coder_fuzzer.cc"},
        },
    )

    assert "raw binary file" in guidance
    assert "valid file signature/header" in guidance
    assert "ReadMNGImage" in guidance
    assert "PNG:" in guidance
    assert "chunk length" in guidance
