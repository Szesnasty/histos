"""Argument-schema validation (deny-by-default on the argument surface)."""

from __future__ import annotations

import pytest

from histos import Field, Gate, GateDenied, Policy, Principal, Schema, ToolContract, use_principal


def _policy(schema: Schema) -> Policy:
    return Policy(
        tools={"t": ToolContract(name="t", args=schema)},
        permissions={"r": frozenset({"t"})},
    )


def _wrap(schema: Schema):
    def t(**kwargs):
        return kwargs

    policy = _policy(schema)
    # allow **kwargs through the wrapper by naming the tool explicitly
    return Gate(policy).wrap(t, name="t")


@pytest.mark.parametrize(
    "schema,args,ok",
    [
        (Schema({"n": Field(type="integer")}), {"n": 5}, True),
        (Schema({"n": Field(type="integer")}), {"n": "5"}, False),  # wrong type
        (Schema({"n": Field(type="integer")}), {"n": True}, False),  # bool is not integer
        (Schema({"s": Field(type="string", max_length=3)}), {"s": "abc"}, True),
        (Schema({"s": Field(type="string", max_length=3)}), {"s": "abcd"}, False),
        (Schema({"s": Field(type="string", enum=("a", "b"))}), {"s": "a"}, True),
        (Schema({"s": Field(type="string", enum=("a", "b"))}), {"s": "z"}, False),
        (Schema({"s": Field(type="string", pattern=r"[a-z]+")}), {"s": "abc"}, True),
        (Schema({"s": Field(type="string", pattern=r"[a-z]+")}), {"s": "ABC"}, False),
        (Schema({"n": Field(type="integer", required=False)}), {}, True),  # optional missing
        (Schema({"n": Field(type="integer")}), {}, False),  # required missing
    ],
)
def test_validation(schema, args, ok):
    safe = _wrap(schema)
    with use_principal(Principal(role="r")):
        if ok:
            assert safe(**args) == args
        else:
            with pytest.raises(GateDenied) as exc:
                safe(**args)
            assert exc.value.decision.rule == "arg_schema"


def test_unexpected_argument_is_rejected():
    safe = _wrap(Schema({"n": Field(type="integer")}))
    with use_principal(Principal(role="r")), pytest.raises(GateDenied) as exc:
        safe(n=1, extra="nope")
    assert "unexpected" in exc.value.decision.reason


def test_denied_decision_names_the_field():
    safe = _wrap(Schema({"amount": Field(type="integer")}))
    with use_principal(Principal(role="r")), pytest.raises(GateDenied) as exc:
        safe(amount="oops")
    assert exc.value.decision.field == "amount"


def test_array_string_elements_are_length_checked_per_element():
    # max_length applies to EACH string element, not just scalar strings (review finding 2).
    safe = _wrap(Schema({"tags": Field(type="array", item_type="string", max_length=3)}))
    with use_principal(Principal(role="r")):
        assert safe(tags=["ab", "cde"]) == {"tags": ["ab", "cde"]}
        with pytest.raises(GateDenied) as exc:
            safe(tags=["ab", "toolong"])
    assert exc.value.decision.rule == "arg_schema"
    assert "tags[1]" in exc.value.decision.reason


def test_unpatterned_array_string_element_can_exceed_pattern_cap():
    # Unpatterned text is governed by the aggregate gate input budget, not re.fullmatch's
    # narrower 4096-character safety ceiling.
    safe = _wrap(Schema({"tags": Field(type="array", item_type="string")}))
    with use_principal(Principal(role="r")):
        assert safe(tags=["ok", "x" * 5000]) == {"tags": ["ok", "x" * 5000]}


def test_patterned_array_string_element_over_pattern_cap_is_denied():
    safe = _wrap(Schema({"tags": Field(type="array", item_type="string", pattern=r"x+")}))
    with use_principal(Principal(role="r")), pytest.raises(GateDenied) as exc:
        safe(tags=["x" * 5000])
    assert exc.value.decision.rule == "arg_schema"
    assert "pattern input too long" in exc.value.decision.reason


def test_array_string_element_pattern_is_enforced():
    safe = _wrap(Schema({"tags": Field(type="array", item_type="string", pattern=r"[a-z]+")}))
    with use_principal(Principal(role="r")):
        assert safe(tags=["abc", "xyz"]) == {"tags": ["abc", "xyz"]}
        with pytest.raises(GateDenied) as exc:
            safe(tags=["abc", "ABC"])
    assert exc.value.decision.rule == "arg_schema"
