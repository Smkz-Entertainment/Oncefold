from __future__ import annotations

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, ValidationError
from referencing import Registry, Resource


def test_public_schemas_are_strict_json_objects() -> None:
    schema_dir = Path("schemas")
    names = {
        "action-identity.schema.json",
        "reuse-receipt.schema.json",
        "reuse-decision.schema.json",
    }
    found = {path.name for path in schema_dir.glob("*.schema.json")}
    assert found == names
    for path in sorted(schema_dir.glob("*.schema.json")):
        schema = json.loads(path.read_text(encoding="utf-8"))
        assert schema["type"] == "object"
        assert schema["additionalProperties"] is False
        assert schema["$id"].startswith("https://oncefold.dev/schemas/")


def test_schemas_validate_the_base_protocol_documents() -> None:
    schema_dir = Path("schemas")
    action = json.loads((schema_dir / "action-identity.schema.json").read_text(encoding="utf-8"))
    receipt = json.loads((schema_dir / "reuse-receipt.schema.json").read_text(encoding="utf-8"))
    decision = json.loads((schema_dir / "reuse-decision.schema.json").read_text(encoding="utf-8"))
    vectors = json.loads(Path("conformance/vectors.json").read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(action)
    Draft202012Validator.check_schema(receipt)
    Draft202012Validator.check_schema(decision)
    Draft202012Validator(action).validate(vectors["base"]["action"])
    registry = Registry().with_resource(
        "https://oncefold.dev/schemas/action-identity/1",
        Resource.from_contents(action),
    )
    Draft202012Validator(receipt, registry=registry).validate(vectors["base"]["receipt"])
    Draft202012Validator(decision).validate({"state": "UNKNOWN", "reason": "schema test"})
    incomplete_action = dict(vectors["base"]["action"])
    del incomplete_action["dependency_completeness"]
    with pytest.raises(ValidationError):
        Draft202012Validator(action).validate(incomplete_action)
