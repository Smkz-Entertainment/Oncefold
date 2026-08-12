from __future__ import annotations

import json
from pathlib import Path


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
