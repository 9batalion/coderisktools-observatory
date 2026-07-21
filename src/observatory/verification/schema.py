"""Small dependency-free validator for the closed Observatory schemas."""

import json
from pathlib import Path
import re


class SchemaValidationError(ValueError):
    """Raised when a JSON value does not satisfy a supported schema."""


def _type_matches(value, expected):
    if expected == "object": return isinstance(value, dict)
    if expected == "array": return isinstance(value, list)
    if expected == "string": return isinstance(value, str)
    if expected == "boolean": return isinstance(value, bool)
    if expected == "null": return value is None
    raise SchemaValidationError(f"unsupported schema type: {expected}")


def validate(value, schema, path="$", root=None):
    root = schema if root is None else root
    if "$ref" in schema:
        raise SchemaValidationError(f"{path}: $ref is not supported")
    if "const" in schema and value != schema["const"]:
        raise SchemaValidationError(f"{path}: expected const {schema['const']!r}")
    if "enum" in schema and value not in schema["enum"]:
        raise SchemaValidationError(f"{path}: value is not in enum")
    expected = schema.get("type")
    if expected and not _type_matches(value, expected):
        raise SchemaValidationError(f"{path}: expected {expected}")
    if isinstance(value, dict):
        for name in schema.get("required", []):
            if name not in value:
                raise SchemaValidationError(f"{path}: missing required property {name}")
        if schema.get("additionalProperties") is False:
            unknown = set(value) - set(schema.get("properties", {}))
            if unknown:
                raise SchemaValidationError(f"{path}: unknown properties {sorted(unknown)}")
        for name, child in schema.get("properties", {}).items():
            if name in value:
                validate(value[name], child, f"{path}.{name}", root)
    if isinstance(value, list):
        if len(value) < schema.get("minItems", 0):
            raise SchemaValidationError(f"{path}: fewer than {schema['minItems']} items")
        if "items" in schema:
            for index, item in enumerate(value):
                validate(item, schema["items"], f"{path}[{index}]", root)
    if isinstance(value, str):
        if len(value) < schema.get("minLength", 0):
            raise SchemaValidationError(f"{path}: shorter than {schema['minLength']} characters")
        pattern = schema.get("pattern")
        if pattern and re.search(pattern, value) is None:
            raise SchemaValidationError(f"{path}: pattern mismatch")
    return value


def validate_json_file(input_path, schema_path, max_bytes=5 * 1024 * 1024):
    input_path = Path(input_path); schema_path = Path(schema_path)
    if input_path.stat().st_size > max_bytes or schema_path.stat().st_size > max_bytes:
        raise SchemaValidationError("schema validation input limit exceeded")
    try:
        value = json.loads(input_path.read_text(encoding="utf-8"))
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SchemaValidationError("invalid JSON input or schema") from exc
    return validate(value, schema)
