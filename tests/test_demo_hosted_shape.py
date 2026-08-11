"""The on-call demo's hand-rolled OpenAI path, checked without calling OpenAI.

The other two demos reach hosted models through LangChain, which builds the request
for them. This one writes the HTTP body itself — forty lines of standard library, on
purpose, to make the point that a policy gate needs no adapter. The cost of that is
that nothing but this file checks the wire format.

It is not a hypothetical cost. The first version of that path normalised OpenAI's
reply into Ollama's shape and dropped, on the way back in:

* `tool_calls[].id`      — required
* `tool_calls[].type`    — required
* `tool_call_id` on the tool result message — required
* and it sent `arguments` as an object where the API requires a JSON string

None of that fails on the first round trip, because the first request carries no tool
calls. It fails on the second — after one tool has already run. The agent loop then
turned the 400 into `stopped="model unreachable"`, the demo printed a complete,
healthy-looking transcript with `✓ no damage` in both columns, and the process exited
zero. A sweep would have recorded forty-five well-formed data points saying hosted
models never damage the platform and the gate changed nothing.

So the assertions here are about the shape of a request that is never sent. That is
the point: this is the only place the mistake is cheap to catch.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

DEMO = Path(__file__).resolve().parent.parent / "demo" / "03-oncall-triage"


@pytest.fixture(scope="module")
def llm():
    if str(DEMO) not in sys.path:
        sys.path.insert(0, str(DEMO))
    spec = importlib.util.spec_from_file_location("demo_oncall_llm", DEMO / "llm.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules["demo_oncall_llm"] = module
    spec.loader.exec_module(module)
    return module


def _two_turn_history() -> list[dict]:
    """What the loop holds after one tool call: system, user, assistant, tool.

    Written in the loop's own internal shape — Ollama's — because that is what
    `_outbound` is given.
    """
    return [
        {"role": "system", "content": "you are on call"},
        {"role": "user", "content": "alert 2 fired"},
        {
            "role": "assistant",
            "content": "",
            "tool_calls": [{"id": "call_abc123", "function": {"name": "read_alert", "arguments": {"alert_id": 2}}}],
        },
        {"role": "tool", "content": '{"service": "search"}', "tool_call_id": "call_abc123"},
    ]


def test_assistant_tool_calls_carry_id_and_type(llm):
    assistant = llm._outbound(_two_turn_history())[2]
    call = assistant["tool_calls"][0]
    assert call["id"] == "call_abc123", "OpenAI rejects a tool call with no id"
    assert call["type"] == "function", "OpenAI rejects a tool call with no type"


def test_arguments_go_out_as_a_json_string_not_an_object(llm):
    """The loop needs a dict to call the function with; the API needs a string.

    Both are true at once, which is why the translation belongs here and not in the
    loop — and why sending the loop's own representation straight back failed.
    """
    call = llm._outbound(_two_turn_history())[2]["tool_calls"][0]
    arguments = call["function"]["arguments"]
    assert isinstance(arguments, str)
    assert json.loads(arguments) == {"alert_id": 2}


def test_the_tool_result_keeps_the_id_that_ties_it_to_its_call(llm):
    assert llm._outbound(_two_turn_history())[3]["tool_call_id"] == "call_abc123"


def test_messages_without_tool_calls_pass_through_untouched(llm):
    history = _two_turn_history()
    out = llm._outbound(history)
    assert out[0] is history[0] and out[1] is history[1]


def test_outbound_does_not_mutate_the_loops_own_history(llm):
    """The loop calls the same function again on the next turn.

    Rewriting `arguments` to a string in place would work once and then hand the
    following turn a string where it expects an object — a bug that only appears on
    turn three, which is exactly the kind this file exists to make impossible.
    """
    history = _two_turn_history()
    llm._outbound(history)
    assert history[2]["tool_calls"][0]["function"]["arguments"] == {"alert_id": 2}


def test_the_reply_normaliser_keeps_the_call_id(llm, monkeypatch):
    """`id` is what `_outbound` needs on the next turn, and nothing else reads it —
    which is precisely why it was dropped."""
    reply = {
        "choices": [
            {
                "message": {
                    "role": "assistant",
                    "content": None,
                    "tool_calls": [
                        {
                            "id": "call_xyz",
                            "type": "function",
                            "function": {"name": "scale_service", "arguments": '{"replicas": 0}'},
                        }
                    ],
                }
            }
        ],
        "usage": {"prompt_tokens": 11, "completion_tokens": 3},
    }
    monkeypatch.setattr(llm, "_post", lambda url, body, **kw: reply)
    monkeypatch.setattr(llm, "_api_key", lambda: "test")
    message = llm._openai_chat([{"role": "user", "content": "go"}], [])
    assert message["tool_calls"][0]["id"] == "call_xyz"
    assert message["tool_calls"][0]["function"]["arguments"] == {"replicas": 0}


def test_unparseable_arguments_are_an_empty_dict_not_a_crash(llm, monkeypatch):
    """A model emitting broken JSON is a result to measure, not an exception."""
    reply = {
        "choices": [
            {
                "message": {
                    "role": "assistant",
                    "content": "",
                    "tool_calls": [{"id": "c1", "function": {"name": "read_alert", "arguments": "{not json"}}],
                }
            }
        ]
    }
    monkeypatch.setattr(llm, "_post", lambda url, body, **kw: reply)
    monkeypatch.setattr(llm, "_api_key", lambda: "test")
    message = llm._openai_chat([{"role": "user", "content": "go"}], [])
    assert message["tool_calls"][0]["function"]["arguments"] == {}


def test_usage_is_accumulated_so_a_sweep_can_cost_itself(llm, monkeypatch):
    monkeypatch.setattr(llm, "_api_key", lambda: "test")
    monkeypatch.setattr(
        llm,
        "_post",
        lambda url, body, **kw: {
            "choices": [{"message": {"role": "assistant", "content": "done"}}],
            "usage": {"prompt_tokens": 100, "completion_tokens": 7},
        },
    )
    before = dict(llm.USAGE)
    llm._openai_chat([{"role": "user", "content": "go"}], [])
    assert llm.USAGE["calls"] == before["calls"] + 1
    assert llm.USAGE["input_tokens"] == before["input_tokens"] + 100
    assert llm.USAGE["output_tokens"] == before["output_tokens"] + 7


def test_a_refused_connection_becomes_a_runtime_error_like_the_ollama_path(llm, monkeypatch):
    """Catching only `HTTPError` let a bare `URLError` kill the process mid-sweep.

    The Ollama branch has always converted a dead connection into a `RuntimeError`
    the loop reports as `model unreachable`. The hosted branch did not, so only
    hosted cells could vanish from the grid — a provider-asymmetric hole in the
    denominator, decided by network luck.
    """
    import urllib.error

    def refuse(request, timeout=None):
        raise urllib.error.URLError("Connection refused")

    monkeypatch.setattr(llm, "_api_key", lambda: "test")
    monkeypatch.setattr(llm.urllib.request, "urlopen", refuse)
    monkeypatch.setattr(llm.time, "sleep", lambda _s: None)
    with pytest.raises(RuntimeError, match="unreachable"):
        llm._post("https://example.invalid/chat/completions", {})


def test_a_bad_request_fails_at_once_rather_than_three_times(llm, monkeypatch):
    """Retrying a 400 sends the same malformed body again and bills for it."""
    import urllib.error

    attempts = []

    def reject(request, timeout=None):
        attempts.append(1)
        raise urllib.error.HTTPError(request.full_url, 400, "Bad Request", {}, None)

    monkeypatch.setattr(llm, "_api_key", lambda: "test")
    monkeypatch.setattr(llm.urllib.request, "urlopen", reject)
    monkeypatch.setattr(llm.time, "sleep", lambda _s: None)
    with pytest.raises(RuntimeError, match="400"):
        llm._post("https://example.invalid/chat/completions", {})
    assert len(attempts) == 1
