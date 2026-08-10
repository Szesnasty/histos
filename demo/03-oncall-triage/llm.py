"""Ollama over HTTP, in forty lines of standard library.

No framework, no SDK, no dependency. This exists to make one point structurally
rather than in prose: **the gate does not need an adapter.** Histos wraps callables,
and this file proves the surrounding machinery can be anything — including a loop
somebody wrote themselves in an afternoon, which is how a large share of production
agents are actually built.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from typing import Any

MODEL = os.environ.get("OPS_MODEL", "qwen2.5:7b")

# Sampling temperature. 0 by default, so a demo run is reproducible and two wirings
# are compared under identical conditions. The override exists because "the model
# refused this attack" at temperature 0 is one sample, not a property — the
# interesting question is how often it refuses across the distribution it will
# actually be served at.
TEMPERATURE = float(os.environ.get("OPS_TEMP", "0"))
ENDPOINT = os.environ.get("OLLAMA_URL", "http://localhost:11434/api/chat")


def tool_schema(name: str, description: str, properties: dict[str, Any], required: list[str]) -> dict[str, Any]:
    """One tool, in the shape Ollama (and OpenAI) expect."""
    return {
        "type": "function",
        "function": {
            "name": name,
            "description": description,
            "parameters": {"type": "object", "properties": properties, "required": required},
        },
    }


def chat(messages: list[dict[str, Any]], tools: list[dict[str, Any]]) -> dict[str, Any]:
    """One round trip. Returns the assistant message, tool calls included."""
    payload = json.dumps(
        {"model": MODEL, "messages": messages, "tools": tools, "stream": False, "options": {"temperature": TEMPERATURE}}
    ).encode()
    request = urllib.request.Request(ENDPOINT, data=payload, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=300) as response:
            return json.loads(response.read())["message"]
    except urllib.error.URLError as exc:
        raise RuntimeError(f"cannot reach Ollama at {ENDPOINT} — is `ollama serve` running? ({exc})") from exc
