"""Auditable declarative rules; untrusted input is never executed as code."""
import json
from importlib.resources import files


def get_rules():
    return json.loads(files("sentinel_zt").joinpath("data/rules.json").read_text(encoding="utf-8"))


def matches(event, condition):
    if "all" in condition:
        return all(matches(event, x) for x in condition["all"])
    if "any" in condition:
        return any(matches(event, x) for x in condition["any"])
    field = condition["field"]
    if field not in event or event[field] is None:
        return False
    value, expected = event[field], condition["value"]
    op = condition["op"]
    if op == "eq":
        return type(value) is type(expected) and value == expected
    if op == "in":
        return any(type(value) is type(x) and value == x for x in expected)
    if op == "contains_any":
        return isinstance(value, str) and any(x.lower() in value.lower() for x in expected)
    if op == "endswith_any":
        return isinstance(value, str) and value.lower().endswith(tuple(x.lower() for x in expected))
    raise ValueError(f"unsupported condition operator: {op}")


def detect(event, rules):
    return [r for r in rules if matches(event, r["condition"])]
