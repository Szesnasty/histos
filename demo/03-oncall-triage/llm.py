"""Ollama over HTTP, in forty lines of standard library.

No framework, no SDK, no dependency. This exists to make one point structurally
rather than in prose: **the gate does not need an adapter.** Histos wraps callables,
and this file proves the surrounding machinery can be anything — including a loop
somebody wrote themselves in an afternoon, which is how a large share of production
agents are actually built.
"""

from __future__ import annotations

import ipaddress
import json
import os
import pathlib
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any


def _endpoint(value: str, setting: str) -> str:
    """Validate an operator-provided HTTP endpoint before a request sees it.

    A custom OpenAI-compatible base is useful for a local Ollama server, but allowing
    a remote clear-text HTTP URL would put the prompt — and on the hosted path,
    ``OPENAI_API_KEY`` — on the wire unchanged. Environment configuration is trusted;
    a typo should still fail loud rather than turn into disclosure.
    """
    try:
        parsed = urllib.parse.urlsplit(value)
        hostname = parsed.hostname
    except ValueError as exc:
        raise RuntimeError(f"{setting} is not a valid URL: {value!r}") from exc
    if parsed.scheme not in {"http", "https"} or not hostname:
        raise RuntimeError(f"{setting} must be an absolute http(s) URL, got {value!r}")
    if parsed.username is not None or parsed.password is not None or parsed.fragment:
        raise RuntimeError(f"{setting} must not contain credentials or a URL fragment")
    try:
        loopback = ipaddress.ip_address(hostname).is_loopback
    except ValueError:
        loopback = hostname.lower() == "localhost"
    if parsed.scheme != "https" and not loopback:
        raise RuntimeError(f"{setting} must use HTTPS unless it points at localhost")
    return value.rstrip("/")


MODEL = os.environ.get("OPS_MODEL", "qwen2.5:7b")

# Sampling temperature. 0 by default, so a demo run is reproducible and two wirings
# are compared under identical conditions. The override exists because "the model
# refused this attack" at temperature 0 is one sample, not a property — the
# interesting question is how often it refuses across the distribution it will
# actually be served at.
TEMPERATURE = float(os.environ.get("OPS_TEMP", "0"))
ENDPOINT = _endpoint(os.environ.get("OLLAMA_URL", "http://localhost:11434/api/chat"), "OLLAMA_URL")

# Where the OpenAI-shaped path points. Overridable for two reasons, one of them the
# reason it exists: Ollama serves an OpenAI-compatible endpoint at `/v1`, so the
# normaliser below can be exercised against a real server without spending anything.
# Code that only ever runs when money is on the line is code nobody has tested.
OPENAI_BASE_URL = _endpoint(
    os.environ.get("OPENAI_BASE_URL", "https://api.openai.com/v1"),
    "OPENAI_BASE_URL",
)

#: Tokens billed on this process, accumulated as the loop runs. Read into the run
#: record so a sweep can be costed from its own output instead of from a receipt.
USAGE: dict[str, int] = {"calls": 0, "input_tokens": 0, "output_tokens": 0}


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
    """One round trip. Returns the assistant message, tool calls included.

    Ollama by default. A model id starting with `gpt-` or `o<digit>` goes to OpenAI
    instead, and the reply is normalised back into Ollama's shape so the agent loop
    above does not learn which provider answered — the whole point of sweeping a
    scenario across providers is that only the model changes.
    """
    if re.match(r"^(gpt-|o\d)", MODEL):
        return _openai_chat(messages, tools)
    payload = json.dumps(
        {"model": MODEL, "messages": messages, "tools": tools, "stream": False, "options": {"temperature": TEMPERATURE}}
    ).encode()
    request = urllib.request.Request(ENDPOINT, data=payload, headers={"Content-Type": "application/json"})
    try:
        # ENDPOINT passed `_endpoint` at module load; urllib has no scheme left to choose.
        with urllib.request.urlopen(request, timeout=300) as response:  # nosec B310
            body = json.loads(response.read())
    except urllib.error.URLError as exc:
        raise RuntimeError(f"cannot reach Ollama at {ENDPOINT} — is `ollama serve` running? ({exc})") from exc
    _count(body.get("prompt_eval_count"), body.get("eval_count"))
    return body["message"]


def _count(input_tokens: object, output_tokens: object) -> None:
    """Add one round trip to `USAGE`. Missing counts are counted as zero, not skipped.

    A provider that reports no usage still made a call, and `calls` is what tells a
    sweep the difference between "this run was cheap" and "this run never happened".
    """
    USAGE["calls"] += 1
    USAGE["input_tokens"] += int(input_tokens or 0)
    USAGE["output_tokens"] += int(output_tokens or 0)


def _api_key() -> str:
    key = os.environ.get("OPENAI_API_KEY")
    if not key and os.environ.get("OPENAI_API_KEY_FILE"):
        key = pathlib.Path(os.environ["OPENAI_API_KEY_FILE"]).read_text().strip()
    if not key:
        raise RuntimeError("set OPENAI_API_KEY or OPENAI_API_KEY_FILE to use a hosted model")
    return key


def _outbound(messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """The conversation in the shape OpenAI's schema requires, on the way *in*.

    The loop keeps history in Ollama's shape, where a tool call's `arguments` is an
    object. OpenAI requires a JSON *string* there, and requires `id` and `type` on
    every tool call and `tool_call_id` on every tool result. Ollama ignores the extra
    keys, so the loop can carry them for free and only this function has to translate.

    Getting this wrong is not a crash, which is what makes it dangerous: the first
    round trip has no tool calls in the history and succeeds, and the rejection lands
    on the second one — by which time one tool has already run. An audit reproduced
    exactly that, and the agent loop laundered the 400 into an ordinary short run that
    the sweep recorded as `no damage` in both columns.
    """
    out = []
    for message in messages:
        calls = message.get("tool_calls")
        if not calls:
            out.append(message)
            continue
        rewritten = [
            {
                "id": call.get("id", ""),
                "type": "function",
                "function": {
                    "name": call["function"]["name"],
                    "arguments": json.dumps(call["function"].get("arguments") or {}),
                },
            }
            for call in calls
        ]
        out.append({**message, "tool_calls": rewritten})
    return out


def _openai_chat(messages: list[dict[str, Any]], tools: list[dict[str, Any]]) -> dict[str, Any]:
    """The same round trip against OpenAI, normalised to Ollama's reply shape.

    Two differences the agent loop must never see: the message is wrapped in
    `choices[0]`, and tool-call arguments arrive as a JSON *string* rather than an
    object. A malformed argument string is left as an empty dict rather than raising,
    because a model emitting unparseable arguments is a result to measure, not a crash.

    The call `id` is carried through even though nothing downstream reads it — it is
    what `_outbound` needs to send the history back, and dropping it here is what
    broke this path.
    """
    body = {"model": MODEL, "messages": _outbound(messages), "tools": tools, "temperature": TEMPERATURE}
    reply = _post(f"{OPENAI_BASE_URL}/chat/completions", body)
    usage = reply.get("usage") or {}
    _count(usage.get("prompt_tokens"), usage.get("completion_tokens"))
    message = reply["choices"][0]["message"]

    normalised: dict[str, Any] = {"role": "assistant", "content": message.get("content") or ""}
    calls = []
    for call in message.get("tool_calls") or []:
        raw = call["function"].get("arguments") or "{}"
        try:
            args = json.loads(raw) if isinstance(raw, str) else raw
        except json.JSONDecodeError:
            args = {}
        calls.append({"id": call.get("id", ""), "function": {"name": call["function"]["name"], "arguments": args}})
    if calls:
        normalised["tool_calls"] = calls
    return normalised


def _post(url: str, body: dict[str, Any], *, attempts: int = 3) -> dict[str, Any]:
    """One POST, retried on anything transient, raising `RuntimeError` on anything else.

    The Ollama branch has always turned a dead connection into a `RuntimeError` the
    loop can report. The hosted branch caught only `HTTPError`, so a refused
    connection escaped as a bare `URLError` and killed the process mid-sweep — a
    provider-asymmetric hole in the denominator, since only the hosted cells could
    vanish that way. Three attempts matches the `max_retries=3` the LangChain demos
    get from their client for free.
    """
    url = _endpoint(url, "OpenAI request URL")
    request = urllib.request.Request(
        url,
        data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {_api_key()}"},
    )
    last = ""
    for attempt in range(attempts):
        try:
            # `_endpoint` above restricts urllib to HTTPS or local loopback HTTP.
            with urllib.request.urlopen(request, timeout=300) as response:  # nosec B310
                return json.loads(response.read())
        except urllib.error.HTTPError as exc:
            detail = exc.read()[:300].decode(errors="replace")
            # 4xx other than rate limiting is a bad request; retrying sends the same
            # bad request again. Fail immediately so the reason reaches the record.
            if exc.code != 429 and exc.code < 500:
                raise RuntimeError(f"OpenAI returned {exc.code}: {detail}") from exc
            last = f"{exc.code}: {detail}"
        except urllib.error.URLError as exc:
            last = str(exc.reason)
        if attempt + 1 < attempts:
            time.sleep(2**attempt)
    raise RuntimeError(f"OpenAI unreachable after {attempts} attempts: {last}")
